/**
 * Mock Data Layer matching shared contracts
 * - security_event.json
 * - incident.json
 * - agent_output.json
 */

export const mockIncidents = [
  {
    incident_id: "INC-2026-0001",
    title: "SSH Brute Force followed by Privileged System Access",
    status: "INVESTIGATING",
    created_at: "2026-08-29T10:01:05Z",
    updated_at: "2026-08-29T10:01:10Z",
    initial_severity: "CRITICAL",
    entities: {
      hosts: ["srv-prod-db01"],
      users: ["root", "admin_user"],
      ip_addresses: ["192.168.1.105"]
    },
    event_ids: ["EVT-1001", "EVT-1002", "EVT-1003", "EVT-1004"]
  },
  {
    incident_id: "INC-2026-0002",
    title: "Routine Administrative Scheduled Backup Task",
    status: "CLOSED",
    created_at: "2026-08-29T08:15:00Z",
    updated_at: "2026-08-29T08:15:30Z",
    initial_severity: "LOW",
    entities: {
      hosts: ["srv-workstation-01"],
      users: ["alice_backup"],
      ip_addresses: ["10.0.0.12"]
    },
    event_ids: ["EVT-2001"]
  }
];

export const mockEventsMap = {
  "INC-2026-0001": [
    {
      event_id: "EVT-1001",
      timestamp: "2026-08-29T10:00:00Z",
      source: "auth.log",
      event_type: "ssh_login_failure",
      severity: "LOW",
      host: "srv-prod-db01",
      user: "root",
      ip_address: "192.168.1.105",
      raw_data: { port: 22, failure_reason: "Invalid password", attempts: 1 }
    },
    {
      event_id: "EVT-1002",
      timestamp: "2026-08-29T10:00:05Z",
      source: "auth.log",
      event_type: "ssh_login_failure",
      severity: "LOW",
      host: "srv-prod-db01",
      user: "root",
      ip_address: "192.168.1.105",
      raw_data: { port: 22, failure_reason: "Invalid password", attempts: 5 }
    },
    {
      event_id: "EVT-1003",
      timestamp: "2026-08-29T10:00:12Z",
      source: "auth.log",
      event_type: "ssh_login_success",
      severity: "HIGH",
      host: "srv-prod-db01",
      user: "admin_user",
      ip_address: "192.168.1.105",
      raw_data: { port: 22, auth_method: "publickey_and_password" }
    },
    {
      event_id: "EVT-1004",
      timestamp: "2026-08-29T10:01:00Z",
      source: "syslog",
      event_type: "sudo_command_execution",
      severity: "CRITICAL",
      host: "srv-prod-db01",
      user: "admin_user",
      ip_address: "192.168.1.105",
      raw_data: { command: "/usr/bin/cat /etc/shadow", elevated_user: "root" }
    }
  ],
  "INC-2026-0002": [
    {
      event_id: "EVT-2001",
      timestamp: "2026-08-29T08:15:00Z",
      source: "cron.log",
      event_type: "system_backup_start",
      severity: "LOW",
      host: "srv-workstation-01",
      user: "alice_backup",
      ip_address: "10.0.0.12",
      raw_data: { cron_job: "daily_backup.sh" }
    }
  ]
};

export const mockAgentOutputs = {
  "INC-2026-0001": {
    incident_id: "INC-2026-0001",
    summary: "Attacker conducted an SSH password brute force attack from 192.168.1.105, successfully compromised the 'admin_user' account on 'srv-prod-db01', and immediately executed sudo to inspect sensitive credential files (/etc/shadow).",
    root_cause: "Weak SSH password policy and exposed SSH port allowing password authentication for administrative user 'admin_user'.",
    assessed_severity: "CRITICAL",
    confidence_score: 0.95,
    mitre_tactics: [
      "TA0001: Initial Access (Credential Stuffing / Brute Force)",
      "TA0004: Privilege Escalation (Sudo Abusal)",
      "TA0006: Credential Access"
    ],
    reasoning_steps: [
      {
        step: 1,
        action: "Analyzed authentication log entries for source IP 192.168.1.105.",
        finding: "Identified multiple failed login attempts against root within a 12-second window."
      },
      {
        step: 2,
        action: "Correlated successful SSH login immediately following brute force attempts.",
        finding: "User 'admin_user' logged in successfully from the same attacking IP address (192.168.1.105)."
      },
      {
        step: 3,
        action: "Evaluated process execution logs for 'admin_user' post-login.",
        finding: "Command '/usr/bin/cat /etc/shadow' was run via sudo within 48 seconds of login, indicating active post-exploitation credential harvesting."
      }
    ],
    evidence: [
      {
        description: "Failed SSH attempts against 'root' from 192.168.1.105",
        source_event_id: "EVT-1001",
        relevance: "Establishes initial reconnaissance/brute-force activity."
      },
      {
        description: "Successful authentication for 'admin_user' from 192.168.1.105",
        source_event_id: "EVT-1003",
        relevance: "Confirms initial access gained via valid credentials."
      },
      {
        description: "Execution of 'sudo cat /etc/shadow' by 'admin_user'",
        source_event_id: "EVT-1004",
        relevance: "Direct proof of privilege escalation and credential dumping."
      }
    ],
    response_actions: [
      {
        action_id: "ACT-001",
        title: "Block Source IP 192.168.1.105",
        description: "Add IP address 192.168.1.105 to edge firewall blocklist to halt active session.",
        risk_level: "LOW",
        automated_script: "iptables -A INPUT -s 192.168.1.105 -j DROP"
      },
      {
        action_id: "ACT-002",
        title: "Force Password Reset & Revoke SSH Keys for admin_user",
        description: "Invalidate current session tokens and enforce credential reset for compromised user account.",
        risk_level: "MEDIUM",
        automated_script: "passwd -l admin_user && pkill -u admin_user"
      },
      {
        action_id: "ACT-003",
        title: "Isolate Host srv-prod-db01 for Forensic Sampling",
        description: "Apply network isolation to host srv-prod-db01 to prevent potential lateral movement while retaining memory state.",
        risk_level: "HIGH",
        automated_script: "systemctl stop networking"
      }
    ]
  },
  "INC-2026-0002": {
    incident_id: "INC-2026-0002",
    summary: "Routine daily backup execution observed on workstation srv-workstation-01 initiated by authorized user alice_backup.",
    root_cause: "Authorized cron schedule execution.",
    assessed_severity: "LOW",
    confidence_score: 0.99,
    mitre_tactics: [],
    reasoning_steps: [
      {
        step: 1,
        action: "Verified process execution against scheduled maintenance windows.",
        finding: "Cron job daily_backup.sh matches registered system backup schedule."
      }
    ],
    evidence: [
      {
        description: "System cron backup job start",
        source_event_id: "EVT-2001",
        relevance: "Identifies standard operational automated maintenance."
      }
    ],
    response_actions: []
  }
};
