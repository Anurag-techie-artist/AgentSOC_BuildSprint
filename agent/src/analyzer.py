from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict
from datetime import datetime, datetime as dt

# Default maximum time delta allowed between brute force attempts & successful login (in seconds)
CORRELATION_WINDOW_SECONDS = 3600  # 1 hour window

SEVERITY_SCORES = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

SCORE_TO_SEVERITY = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL"
}

# Standardized MITRE Tactic Labels
MITRE_INITIAL_ACCESS = "TA0001: Initial Access"
MITRE_PRIVILEGE_ESCALATION = "TA0004: Privilege Escalation"
MITRE_CREDENTIAL_ACCESS = "TA0006: Credential Access"
MITRE_DEFENSE_EVASION = "TA0005: Defense Evasion"
MITRE_EXECUTION = "TA0002: Execution"

def _parse_timestamp(ts_str: Any) -> float:
    """Safely parse ISO-8601 or standard datetime strings into UNIX epoch seconds. Returns -1.0 if unparseable."""
    if not isinstance(ts_str, str) or not ts_str.strip():
        return -1.0
    ts_clean = ts_str.strip().replace("Z", "+00:00")
    try:
        return dt.fromisoformat(ts_clean).timestamp()
    except Exception:
        try:
            # Fallback for alternative standard formats
            return dt.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S").timestamp()
        except Exception:
            return -1.0

def analyze_events(agent_input: Dict[str, Any]) -> Dict[str, Any]:
    incident_id = agent_input["incident_id"]
    title = agent_input.get("title", "Security Incident")
    initial_severity = agent_input.get("initial_severity", "LOW")
    entities = agent_input.get("entities", {})
    events = agent_input.get("events", [])

    # Sort events chronologically by parsed timestamp
    sorted_events = sorted(
        events,
        key=lambda e: (_parse_timestamp(e.get("timestamp")) if isinstance(e, dict) else -1.0)
    )

    reasoning_steps: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    mitre_tactics_set: Set[str] = set()
    response_actions: List[Dict[str, Any]] = []

    ip_addresses = set(entities.get("ip_addresses", []))
    users = set(entities.get("users", []))
    hosts = set(entities.get("hosts", []))

    # Pattern tracking
    failures_by_ip_user: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    failures_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    successes_by_ip_user: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    sudo_cmds_by_host_user: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    cred_access_events: List[Dict[str, Any]] = []
    suspicious_logins: List[Dict[str, Any]] = []
    other_suspicious_events: List[Dict[str, Any]] = []
    benign_events: List[Dict[str, Any]] = []

    step_counter = 1

    # Step 1: Ingest & timeline ordering
    if sorted_events:
        t_start = sorted_events[0].get("timestamp", "N/A")
        t_end = sorted_events[-1].get("timestamp", "N/A")
        time_msg = f"Ordered timeline from {t_start} to {t_end}."
    else:
        time_msg = "No events present in telemetry."

    reasoning_steps.append({
        "step": step_counter,
        "action": f"Ingested {len(sorted_events)} security events for incident {incident_id}.",
        "finding": time_msg
    })
    step_counter += 1

    # Specific sensitive paths & terms for BUG-003 fix
    SENSITIVE_INDICATORS = ["/etc/shadow", "/etc/passwd", "mimikatz", "lsass", "sam", "credential_dump", "ntds.dit"]

    for ev in sorted_events:
        if not isinstance(ev, dict):
            continue

        evt_id = str(ev.get("event_id", ""))
        evt_type = str(ev.get("event_type", "")).lower()
        evt_sev = str(ev.get("severity", "LOW")).upper()
        evt_user = str(ev.get("user")) if ev.get("user") else None
        evt_host = str(ev.get("host")) if ev.get("host") else None
        evt_ip = str(ev.get("ip_address")) if ev.get("ip_address") else None
        raw_data = ev.get("raw_data", {}) if isinstance(ev.get("raw_data"), dict) else {}

        if evt_user: users.add(evt_user)
        if evt_host: hosts.add(evt_host)
        if evt_ip: ip_addresses.add(evt_ip)

        ip_key = evt_ip or "unknown_ip"
        user_key = evt_user or "unknown_user"
        host_key = evt_host or "unknown_host"

        cmd_str = str(raw_data.get("command", "")).lower()

        # Categorize events
        if "failure" in evt_type or "failed" in evt_type or evt_type == "ssh_login_failure":
            failures_by_ip_user[(ip_key, user_key)].append(ev)
            failures_by_ip[ip_key].append(ev)
            mitre_tactics_set.add(MITRE_INITIAL_ACCESS)
            evidence.append({
                "description": f"Failed authentication attempt for user '{user_key}' from IP {ip_key}",
                "source_event_id": evt_id,
                "relevance": "Authentication failure pattern indicating credential probing or brute force."
            })

        elif "success" in evt_type or evt_type == "ssh_login_success":
            successes_by_ip_user[(ip_key, user_key)].append(ev)
            mitre_tactics_set.add(MITRE_INITIAL_ACCESS)
            evidence.append({
                "description": f"Successful authentication for user '{user_key}' from IP {ip_key}",
                "source_event_id": evt_id,
                "relevance": "Successful login establishing remote access."
            })
            if evt_sev in ["HIGH", "CRITICAL"] or raw_data.get("suspicious", False) or "unknown" in ip_key:
                suspicious_logins.append(ev)

        # BUG-002 Fix: Precise matching for privileged command execution
        elif ("sudo" in evt_type or "privilege_escalation" in evt_type or evt_type in ["sudo_command_execution", "privileged_execution"] or "sudo" in cmd_str) and "cmd_execution" not in evt_type:
            sudo_cmds_by_host_user[(host_key, user_key)].append(ev)
            mitre_tactics_set.add(MITRE_PRIVILEGE_ESCALATION)
            cmd_name = raw_data.get("command", "privileged command")
            evidence.append({
                "description": f"Execution of privileged command '{cmd_name}' by user '{user_key}' on host '{host_key}'",
                "source_event_id": evt_id,
                "relevance": "Privilege escalation or elevated administrative command execution."
            })
            # BUG-003 Fix: Explicit sensitive indicators check
            if any(term in cmd_str for term in SENSITIVE_INDICATORS):
                cred_access_events.append(ev)
                mitre_tactics_set.add(MITRE_CREDENTIAL_ACCESS)

        # BUG-003 Fix: Require explicit sensitive indicator or specific event type
        elif any(term in evt_type for term in ["cred_access", "sensitive_read", "credential_dump"]) or any(term in cmd_str for term in SENSITIVE_INDICATORS):
            cred_access_events.append(ev)
            mitre_tactics_set.add(MITRE_CREDENTIAL_ACCESS)
            evidence.append({
                "description": f"Sensitive file or credential access detected by user '{user_key}' on host '{host_key}'",
                "source_event_id": evt_id,
                "relevance": "Direct credential access or sensitive security file inspection."
            })

        elif evt_sev in ["HIGH", "CRITICAL"]:
            other_suspicious_events.append(ev)
            mitre_tactics_set.add(MITRE_EXECUTION)
            evidence.append({
                "description": f"High severity event '{evt_type}' on host '{host_key}' by user '{user_key}'",
                "source_event_id": evt_id,
                "relevance": "High-risk system or application anomaly."
            })

        else:
            benign_events.append(ev)

    # BUG-005 Fix: Mathematical Timestamp Delta Correlation Window Enforcement
    brute_force_chains = []
    for (ip, usr), fails in failures_by_ip_user.items():
        succs = successes_by_ip_user.get((ip, usr), [])
        if succs and len(fails) >= 2:
            # Verify chronological order and delta <= CORRELATION_WINDOW_SECONDS
            last_fail_ts = _parse_timestamp(fails[-1].get("timestamp"))
            first_succ_ts = _parse_timestamp(succs[0].get("timestamp"))
            if last_fail_ts >= 0 and first_succ_ts >= 0:
                delta = first_succ_ts - last_fail_ts
                if 0 <= delta <= CORRELATION_WINDOW_SECONDS:
                    brute_force_chains.append((ip, usr, fails, succs))

    ip_probing_then_login = []
    if not brute_force_chains:
        for ip, succ_list in [(ip, sl) for (ip, u), sl in successes_by_ip_user.items() if ip != "unknown_ip"]:
            all_ip_fails = failures_by_ip.get(ip, [])
            if len(all_ip_fails) >= 2:
                last_fail_ts = _parse_timestamp(all_ip_fails[-1].get("timestamp"))
                first_succ_ts = _parse_timestamp(succ_list[0].get("timestamp"))
                if last_fail_ts >= 0 and first_succ_ts >= 0:
                    delta = first_succ_ts - last_fail_ts
                    if 0 <= delta <= CORRELATION_WINDOW_SECONDS:
                        succ_user = succ_list[0].get("user", "unknown_user")
                        failed_users = list(set(f.get("user", "unknown") for f in all_ip_fails if f.get("user") != succ_user))
                        ip_probing_then_login.append((ip, succ_user, failed_users, all_ip_fails, succ_list))

    # Step 2: Correlation Reasoning
    if brute_force_chains:
        for ip, usr, fails, succs in brute_force_chains:
            reasoning_steps.append({
                "step": step_counter,
                "action": f"Correlated authentication failure sequence with successful login for user '{usr}' from IP {ip}.",
                "finding": f"Detected {len(fails)} failed login attempts followed by successful login for compromised account '{usr}' within correlation window."
            })
            step_counter += 1
    elif ip_probing_then_login:
        for ip, succ_usr, fail_usrs, fails, succs in ip_probing_then_login:
            reasoning_steps.append({
                "step": step_counter,
                "action": f"Analyzed IP-level authentication activity from source IP {ip}.",
                "finding": f"Observed {len(fails)} failed login attempts against account(s) {fail_usrs} followed by successful login for user '{succ_usr}' within correlation window."
            })
            step_counter += 1
    elif failures_by_ip_user:
        total_fails = sum(len(f) for f in failures_by_ip_user.values())
        reasoning_steps.append({
            "step": step_counter,
            "action": "Analyzed authentication failure volume.",
            "finding": f"Observed {total_fails} failed login attempts across {len(failures_by_ip_user)} source IP/user pairs without confirmed compromise."
        })
        step_counter += 1

    # Step 3: Privilege & Credential Analysis
    if sudo_cmds_by_host_user:
        for (h, u), cmds in sudo_cmds_by_host_user.items():
            cmd_list = [c.get("raw_data", {}).get("command", "command") for c in cmds]
            reasoning_steps.append({
                "step": step_counter,
                "action": f"Evaluated privileged command execution logs on host '{h}'.",
                "finding": f"Identified elevated command(s) ({', '.join(cmd_list)}) executed by user '{u}'."
            })
            step_counter += 1

    if cred_access_events:
        reasoning_steps.append({
            "step": step_counter,
            "action": "Investigated credential and sensitive file access telemetry.",
            "finding": f"Confirmed {len(cred_access_events)} event(s) involving sensitive credential inspection or dumping."
        })
        step_counter += 1

    if suspicious_logins and not brute_force_chains and not ip_probing_then_login:
        for sl in suspicious_logins:
            reasoning_steps.append({
                "step": step_counter,
                "action": "Analyzed standalone authentication anomaly.",
                "finding": f"Identified suspicious successful login for user '{sl.get('user', 'unknown')}' from IP {sl.get('ip_address', 'unknown')} without prior brute force."
            })
            step_counter += 1

    if not brute_force_chains and not ip_probing_then_login and not sudo_cmds_by_host_user and not cred_access_events and not suspicious_logins:
        reasoning_steps.append({
            "step": step_counter,
            "action": "Evaluated event severity and threat indicators.",
            "finding": f"No high-confidence attack chains detected across {len(sorted_events)} events. Telemetry consists of standard or benign operational activity."
        })
        step_counter += 1

    # BUG-006 Fix: Severity & Confidence Consistency
    max_event_sev_score = max([SEVERITY_SCORES.get(str(e.get("severity", "LOW")).upper(), 1) for e in sorted_events if isinstance(e, dict)], default=1)
    init_sev_score = SEVERITY_SCORES.get(initial_severity.upper(), 1)
    assessed_score = max(max_event_sev_score, init_sev_score)

    has_brute_or_probe = bool(brute_force_chains or ip_probing_then_login)
    if has_brute_or_probe and sudo_cmds_by_host_user:
        assessed_score = 4 # CRITICAL
    elif has_brute_or_probe or cred_access_events or (sudo_cmds_by_host_user and suspicious_logins):
        assessed_score = max(assessed_score, 3) # HIGH or CRITICAL

    assessed_severity = SCORE_TO_SEVERITY[assessed_score]

    # Calculate Confidence Score Deterministically (BUG-006 Fix: Require valid window correlation for 0.85+)
    if has_brute_or_probe and sudo_cmds_by_host_user:
        confidence_score = 0.95
    elif has_brute_or_probe or cred_access_events:
        confidence_score = 0.85
    elif sudo_cmds_by_host_user or suspicious_logins:
        confidence_score = 0.75
    elif other_suspicious_events or failures_by_ip_user:
        confidence_score = 0.60
    else:
        confidence_score = 0.40

    # Formulate Summary & Root Cause
    if brute_force_chains and sudo_cmds_by_host_user:
        ip, usr, _, succs = brute_force_chains[0]
        host = succs[0].get("host", "target host") if succs else "target host"
        summary = f"Attacker conducted password brute force from {ip}, compromised account '{usr}', and executed privileged commands on host '{host}'."
        root_cause = f"Exposed authentication endpoint allowing password brute force and weak credentials for '{usr}'."
    elif ip_probing_then_login and sudo_cmds_by_host_user:
        ip, succ_usr, fail_usrs, _, succs = ip_probing_then_login[0]
        host = succs[0].get("host", "target host") if succs else "target host"
        fail_str = ", ".join(f"'{u}'" for u in fail_usrs)
        summary = f"Attacker probed credentials from IP {ip} against {fail_str}, successfully authenticated as '{succ_usr}' on host '{host}', and executed privileged commands."
        root_cause = f"Exposed authentication endpoint subject to credential probing and valid credentials for '{succ_usr}'."
    elif brute_force_chains:
        ip, usr, _, succs = brute_force_chains[0]
        summary = f"Successful credential brute force attack detected from IP {ip} targeting account '{usr}'."
        root_cause = f"Weak account password or missing multi-factor authentication for '{usr}'."
    elif ip_probing_then_login:
        ip, succ_usr, fail_usrs, _, _ = ip_probing_then_login[0]
        fail_str = ", ".join(f"'{u}'" for u in fail_usrs)
        summary = f"Credential probing detected from IP {ip} against {fail_str} followed by successful login for '{succ_usr}'."
        root_cause = f"Credential probing activity from IP {ip} and compromised credentials for '{succ_usr}'."
    elif cred_access_events:
        summary = f"Sensitive credential file access detected across host(s) {list(hosts)}."
        root_cause = "Unauthorized attempt to access or dump system security credentials."
    elif sudo_cmds_by_host_user:
        summary = f"Privileged command execution detected on host(s) {list(hosts)} by user(s) {list(users)}."
        root_cause = "Execution of elevated system administrative commands."
    elif suspicious_logins:
        summary = f"Suspicious successful authentication detected from IP(s) {list(ip_addresses)}."
        root_cause = "Anomalous successful login without documented prior brute force."
    elif failures_by_ip_user:
        summary = f"Authentication failure activity observed across IP(s) {list(ip_addresses)}."
        root_cause = "Failed login attempts without confirmed system compromise."
    else:
        summary = f"Security incident '{title}' evaluated; no confirmed exploit patterns detected."
        root_cause = "Routine or low-severity operational events."

    # BUG-004 Fix: Deduplicate Response Actions by (Entity, Purpose) while maintaining sequential action_id
    # Phase 5: Entity-specific, evidence-grounded response intelligence
    suspicious_ips: Set[str] = set()
    targeted_users: Set[str] = set()
    affected_hosts: Set[str] = set()

    for (ip, usr), fails in failures_by_ip_user.items():
        if ip and ip != "unknown_ip":
            suspicious_ips.add(ip)
        if usr and usr not in ["root", "unknown_user"]:
            targeted_users.add(usr)

    for (ip, usr), succs in successes_by_ip_user.items():
        if (ip, usr) in [chain[:2] for chain in brute_force_chains] or any(p[0] == ip and p[1] == usr for p in ip_probing_then_login):
            if ip and ip != "unknown_ip":
                suspicious_ips.add(ip)
            if usr and usr not in ["root", "unknown_user"]:
                targeted_users.add(usr)
            for s in succs:
                if s.get("host") and s.get("host") != "unknown_host":
                    affected_hosts.add(s.get("host"))

    for sl in suspicious_logins:
        ip = sl.get("ip_address")
        usr = sl.get("user")
        hst = sl.get("host")
        if ip and ip != "unknown_ip":
            suspicious_ips.add(ip)
        if usr and usr not in ["root", "unknown_user"]:
            targeted_users.add(usr)
        if hst and hst != "unknown_host":
            affected_hosts.add(hst)

    for (h, u), cmds in sudo_cmds_by_host_user.items():
        if h and h != "unknown_host":
            affected_hosts.add(h)
        if u and u not in ["root", "unknown_user"]:
            targeted_users.add(u)

    for ev in cred_access_events:
        ip = ev.get("ip_address")
        usr = ev.get("user")
        hst = ev.get("host")
        if ip and ip != "unknown_ip":
            suspicious_ips.add(ip)
        if usr and usr not in ["root", "unknown_user"]:
            targeted_users.add(usr)
        if hst and hst != "unknown_host":
            affected_hosts.add(hst)

    for ev in other_suspicious_events:
        ip = ev.get("ip_address")
        usr = ev.get("user")
        hst = ev.get("host")
        if ip and ip != "unknown_ip":
            suspicious_ips.add(ip)
        if usr and usr not in ["root", "unknown_user"]:
            targeted_users.add(usr)
        if hst and hst != "unknown_host":
            affected_hosts.add(hst)

    actions_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for ip in sorted(list(suspicious_ips)):
        key = (f"ip:{ip}", "block_ip")
        if key not in actions_map:
            actions_map[key] = {
                "title": f"Block Source IP {ip}",
                "description": f"Enforce firewall rule to drop inbound traffic from attacking IP {ip}.",
                "risk_level": "LOW",
                "automated_script": f"iptables -A INPUT -s {ip} -j DROP"
            }

    for u in sorted(list(targeted_users)):
        key = (f"user:{u}", "reset_user")
        if key not in actions_map:
            actions_map[key] = {
                "title": f"Reset Credentials for User {u}",
                "description": f"Terminate active sessions and force credential reset for account {u}.",
                "risk_level": "MEDIUM",
                "automated_script": f"passwd -l {u} && pkill -u {u}"
            }

    if assessed_severity in ["HIGH", "CRITICAL"]:
        for h in sorted(list(affected_hosts)):
            key = (f"host:{h}", "isolate_host")
            if key not in actions_map:
                actions_map[key] = {
                    "title": f"Isolate Host {h}",
                    "description": f"Apply network isolation policy to host {h} to contain potential lateral movement.",
                    "risk_level": "HIGH",
                    "automated_script": f"systemctl stop networking"
                }

    action_counter = 1
    for act_data in actions_map.values():
        act_data["action_id"] = f"ACT-{action_counter:03d}"
        response_actions.append(act_data)
        action_counter += 1

    # Ensure clean MITRE tactics (no duplicate prefixes/labels)
    if not mitre_tactics_set:
        mitre_tactics_set.add(MITRE_INITIAL_ACCESS)

    sorted_mitre_tactics = sorted(list(mitre_tactics_set))

    # Fallback evidence if empty
    if not evidence and sorted_events:
        first_ev = sorted_events[0]
        evidence.append({
            "description": f"Event '{first_ev.get('event_type', 'unknown')}' recorded on host '{first_ev.get('host', 'unknown')}'",
            "source_event_id": str(first_ev.get("event_id", "EVT-0000")),
            "relevance": "Baseline event recorded in telemetry."
        })

    return {
        "incident_id": incident_id,
        "summary": summary,
        "root_cause": root_cause,
        "assessed_severity": assessed_severity,
        "confidence_score": confidence_score,
        "mitre_tactics": sorted_mitre_tactics,
        "reasoning_steps": reasoning_steps,
        "evidence": evidence,
        "response_actions": response_actions
    }
