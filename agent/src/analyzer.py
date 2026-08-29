from typing import Dict, Any, List, Set, Tuple

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

def analyze_events(agent_input: Dict[str, Any]) -> Dict[str, Any]:
    incident_id = agent_input["incident_id"]
    title = agent_input.get("title", "Security Incident")
    initial_severity = agent_input.get("initial_severity", "LOW")
    entities = agent_input.get("entities", {})
    events = agent_input.get("events", [])

    # Sort events by timestamp ascending
    sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

    reasoning_steps: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    mitre_tactics_set: Set[str] = set()
    response_actions: List[Dict[str, Any]] = []

    # Category trackers
    ssh_failures = []
    ssh_successes = []
    sudo_commands = []
    critical_events = []
    high_events = []

    ip_addresses = set(entities.get("ip_addresses", []))
    users = set(entities.get("users", []))
    hosts = set(entities.get("hosts", []))

    # Step 1: Ingest & timeline ordering
    reasoning_steps.append({
        "step": 1,
        "action": f"Ingested {len(sorted_events)} security events for incident {incident_id}.",
        "finding": f"Ordered timeline from {sorted_events[0]['timestamp'] if sorted_events else 'N/A'} to {sorted_events[-1]['timestamp'] if sorted_events else 'N/A'}."
    })

    for ev in sorted_events:
        evt_id = ev.get("event_id", "")
        evt_type = ev.get("event_type", "").lower()
        evt_sev = ev.get("severity", "LOW")
        evt_user = ev.get("user")
        evt_host = ev.get("host")
        evt_ip = ev.get("ip_address")
        raw_data = ev.get("raw_data", {})

        if evt_user: users.add(evt_user)
        if evt_host: hosts.add(evt_host)
        if evt_ip: ip_addresses.add(evt_ip)

        if evt_sev == "CRITICAL":
            critical_events.append(ev)
        elif evt_sev == "HIGH":
            high_events.append(ev)

        # Attack pattern identification
        if "failure" in evt_type or "failed" in evt_type or evt_type == "ssh_login_failure":
            ssh_failures.append(ev)
            mitre_tactics_set.add("TA0001: Initial Access (Credential Stuffing / Brute Force)")
            evidence.append({
                "description": f"Failed login attempt for user '{evt_user or 'unknown'}' from IP {evt_ip or 'unknown'}",
                "source_event_id": evt_id,
                "relevance": "Initial access brute force or credential probing activity."
            })

        elif "success" in evt_type or evt_type == "ssh_login_success":
            ssh_successes.append(ev)
            mitre_tactics_set.add("TA0001: Initial Access")
            evidence.append({
                "description": f"Successful login for user '{evt_user or 'unknown'}' from IP {evt_ip or 'unknown'}",
                "source_event_id": evt_id,
                "relevance": "Successful authentication establishing initial entry."
            })

        elif "sudo" in evt_type or "privilege" in evt_type or "cmd" in evt_type or evt_type == "sudo_command_execution":
            sudo_commands.append(ev)
            mitre_tactics_set.add("TA0004: Privilege Escalation")
            cmd = raw_data.get("command", "privileged execution")
            evidence.append({
                "description": f"Execution of privileged command '{cmd}' by user '{evt_user or 'unknown'}'",
                "source_event_id": evt_id,
                "relevance": "Privilege escalation and administrative command execution."
            })
            if "shadow" in str(cmd).lower() or "passwd" in str(cmd).lower() or "cat" in str(cmd).lower():
                mitre_tactics_set.add("TA0006: Credential Access")

    # Step 2: Correlation reasoning
    if ssh_failures and ssh_successes:
        reasoning_steps.append({
            "step": 2,
            "action": "Correlated authentication failure stream with subsequent successful login.",
            "finding": f"Detected {len(ssh_failures)} failed login attempts prior to successful login for user '{ssh_successes[0].get('user')}'."
        })
    elif ssh_failures:
        reasoning_steps.append({
            "step": 2,
            "action": "Analyzed authentication failure volume.",
            "finding": f"Observed {len(ssh_failures)} failed login attempts without confirmed compromise."
        })
    else:
        reasoning_steps.append({
            "step": 2,
            "action": "Analyzed event distribution across system components.",
            "finding": f"Processed {len(sorted_events)} events across hosts {list(hosts)}."
        })

    # Step 3: Privilege / Command analysis
    if sudo_commands:
        cmds = [e.get("raw_data", {}).get("command", "command") for e in sudo_commands]
        reasoning_steps.append({
            "step": 3,
            "action": "Evaluated privileged command execution logs.",
            "finding": f"Identified elevated command execution ({', '.join(cmds)}) following authentication."
        })
    else:
        reasoning_steps.append({
            "step": 3,
            "action": "Assessed system impact and command execution history.",
            "finding": "No elevated sudo or privilege escalation commands were detected in event telemetry."
        })

    # Severity & Confidence Calculation
    max_event_sev_score = max([SEVERITY_SCORES.get(e.get("severity", "LOW"), 1) for e in events], default=1)
    init_sev_score = SEVERITY_SCORES.get(initial_severity, 1)

    assessed_score = max(max_event_sev_score, init_sev_score)
    if ssh_failures and ssh_successes and sudo_commands:
        assessed_score = 4 # CRITICAL
    assessed_severity = SCORE_TO_SEVERITY[assessed_score]

    # Calculate confidence score deterministically
    base_confidence = 0.5
    if len(events) >= 3:
        base_confidence += 0.2
    if len(evidence) >= 2:
        base_confidence += 0.15
    if ssh_failures and ssh_successes:
        base_confidence += 0.1
    confidence_score = round(min(1.0, max(0.1, base_confidence)), 2)

    # Root cause & Summary formulation
    if ssh_failures and ssh_successes and sudo_commands:
        user_target = ssh_successes[0].get("user", "user")
        ip_target = ssh_successes[0].get("ip_address", "remote IP")
        host_target = ssh_successes[0].get("host", "target host")
        summary = (
            f"Attacker conducted password brute force attempts from {ip_target}, "
            f"successfully compromised account '{user_target}' on host '{host_target}', "
            f"and subsequently executed privileged commands."
        )
        root_cause = f"Exposed authentication endpoint allowing password brute force and weak account credentials for '{user_target}'."
    elif ssh_failures:
        summary = f"Multiple failed login attempts detected against host(s) {list(hosts)} from IP(s) {list(ip_addresses)}."
        root_cause = "External authentication brute force or credential stuffing attempt."
    else:
        summary = f"Security incident '{title}' analyzed across {len(events)} events involving entities {list(users)} and {list(hosts)}."
        root_cause = f"Suspicious activity observed on event source(s) {list(set(e.get('source', '') for e in events))}."

    # Generate Response Actions
    action_counter = 1
    for ip in sorted(list(ip_addresses)):
        if ip:
            response_actions.append({
                "action_id": f"ACT-00{action_counter}",
                "title": f"Block Source IP {ip}",
                "description": f"Enforce firewall rule to drop inbound traffic from attacking IP {ip}.",
                "risk_level": "LOW",
                "automated_script": f"iptables -A INPUT -s {ip} -j DROP"
            })
            action_counter += 1

    for u in sorted(list(users)):
        if u and u != "root":
            response_actions.append({
                "action_id": f"ACT-00{action_counter}",
                "title": f"Reset Credentials for User {u}",
                "description": f"Terminate active sessions and force credential reset for account {u}.",
                "risk_level": "MEDIUM",
                "automated_script": f"passwd -l {u} && pkill -u {u}"
            })
            action_counter += 1

    if assessed_severity in ["HIGH", "CRITICAL"]:
        for h in sorted(list(hosts)):
            if h:
                response_actions.append({
                    "action_id": f"ACT-00{action_counter}",
                    "title": f"Isolate Host {h}",
                    "description": f"Apply network isolation policy to host {h} to contain potential lateral movement.",
                    "risk_level": "HIGH",
                    "automated_script": f"systemctl stop networking"
                })
                action_counter += 1

    # Ensure mitre tactics list is populated
    if not mitre_tactics_set:
        mitre_tactics_set.add("TA0001: Initial Access")

    return {
        "incident_id": incident_id,
        "summary": summary,
        "root_cause": root_cause,
        "assessed_severity": assessed_severity,
        "confidence_score": confidence_score,
        "mitre_tactics": sorted(list(mitre_tactics_set)),
        "reasoning_steps": reasoning_steps,
        "evidence": evidence,
        "response_actions": response_actions
    }
