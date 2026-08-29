import os
import sys
import json
import pytest

# Add agent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent import investigate
from src.validator import validate_agent_input, validate_agent_output, ValidationError
from src.providers import MockLLMProvider

@pytest.fixture
def mock_agent_input():
    mock_input_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks", "mock_agent_input.json")
    )
    with open(mock_input_path, "r", encoding="utf-8") as f:
        return json.load(f)

@pytest.fixture
def mock_agent_output():
    mock_output_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks", "mock_agent_output.json")
    )
    with open(mock_output_path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_validate_valid_input(mock_agent_input):
    """Test that valid input passes validation without error."""
    validate_agent_input(mock_agent_input)

def test_validate_invalid_input_missing_required(mock_agent_input):
    """Test that input missing a required field raises ValidationError."""
    invalid_input = dict(mock_agent_input)
    del invalid_input["incident_id"]
    with pytest.raises(ValidationError, match="missing required field 'incident_id'"):
        validate_agent_input(invalid_input)

def test_validate_invalid_input_wrong_type(mock_agent_input):
    """Test that input with wrong type raises ValidationError."""
    invalid_input = dict(mock_agent_input)
    invalid_input["initial_severity"] = 12345
    with pytest.raises(ValidationError, match="initial_severity"):
        validate_agent_input(invalid_input)

def test_validate_valid_output(mock_agent_output):
    """Test that valid output passes validation without error."""
    validate_agent_output(mock_agent_output)

def test_validate_invalid_output_out_of_bounds(mock_agent_output):
    """Test that output with confidence_score > 1.0 raises ValidationError."""
    invalid_output = dict(mock_agent_output)
    invalid_output["confidence_score"] = 1.5
    with pytest.raises(ValidationError, match="greater than maximum 1.0"):
        validate_agent_output(invalid_output)

def test_validate_invalid_output_additional_properties(mock_agent_output):
    """Test that output with additional properties raises ValidationError."""
    invalid_output = dict(mock_agent_output)
    invalid_output["unknown_extra_field"] = "bad"
    with pytest.raises(ValidationError, match="unexpected additional property"):
        validate_agent_output(invalid_output)

# --- PHASE 4 TESTS: AI Reasoning, Grounding, and Fallback ---

def test_phase4_ai_reasoning_primary_scenario(mock_agent_input):
    """Test Phase 4 AI Reasoning with MockLLMProvider on primary SSH scenario."""
    provider = MockLLMProvider()
    output = investigate(mock_agent_input, provider=provider)
    validate_agent_output(output)

    assert output["incident_id"] == "INC-2026-0001"
    assert output["assessed_severity"] == "CRITICAL"
    assert output["confidence_score"] == 0.95
    assert "AI Assessment:" in output["summary"]
    assert any("AI Security Synthesis" in step["action"] for step in output["reasoning_steps"])

def test_phase4_provider_failure_fallback(mock_agent_input):
    """Test Phase 4 safe fallback when AI Provider fails or raises exception."""
    failing_provider = MockLLMProvider(should_fail=True)
    output = investigate(mock_agent_input, provider=failing_provider)
    validate_agent_output(output)

    assert output["incident_id"] == "INC-2026-0001"
    assert output["assessed_severity"] == "CRITICAL"
    assert any("AI Provider was unavailable or unparseable" in step["finding"] for step in output["reasoning_steps"])

def test_phase4_severity_confidence_grounding_bound(mock_agent_input):
    """Test that AI cannot inflate severity or confidence above evidence bounds without grounding."""
    inflated_override = {
        "summary": "AI attempts artificial escalation.",
        "root_cause": "AI hallucinated critical vulnerability.",
        "assessed_severity": "CRITICAL",
        "confidence_score": 1.0,  # Attempts to inflate confidence
        "reasoning_steps": [{"step": 1, "action": "AI test", "finding": "test"}]
    }
    
    # Input with LOW severity events
    low_input = {
        "incident_id": "INC-LOW-1",
        "title": "Low Severity Test",
        "created_at": "2026-08-29T10:00:00Z",
        "initial_severity": "LOW",
        "entities": {"hosts": ["h1"], "users": ["u1"], "ip_addresses": ["1.1.1.1"]},
        "events": [
            {
                "event_id": "EVT-L1",
                "timestamp": "2026-08-29T10:01:00Z",
                "source": "syslog",
                "event_type": "status_check",
                "severity": "LOW",
                "host": "h1",
                "user": "u1",
                "ip_address": "1.1.1.1",
                "raw_data": {}
            }
        ]
    }
    
    provider = MockLLMProvider(response_override=inflated_override)
    output = investigate(low_input, provider=provider)
    validate_agent_output(output)

    # Assessed severity and confidence must be capped by evidence bounds
    assert output["assessed_severity"] == "LOW"
    assert output["confidence_score"] <= 0.40

# --- SCENARIO A: SSH Brute Force Followed by Successful Login ---
def test_scenario_a_ssh_brute_force(mock_agent_input):
    output = investigate(mock_agent_input)
    validate_agent_output(output)
    
    assert output["incident_id"] == "INC-2026-0001"
    assert output["assessed_severity"] == "CRITICAL"
    assert output["confidence_score"] == 0.95
    assert "TA0001: Initial Access" in output["mitre_tactics"]
    assert "TA0004: Privilege Escalation" in output["mitre_tactics"]
    assert "TA0006: Credential Access" in output["mitre_tactics"]
    
    # Check MITRE mapping is clean without duplicate tactic IDs
    tactic_ids = [t.split(":")[0] for t in output["mitre_tactics"]]
    assert len(tactic_ids) == len(set(tactic_ids))

# --- REGRESSION TEST FOR BUG-001: Incorrect Compromised Account Attribution ---
def test_bug_001_account_attribution_regression():
    """Verify that failures against 'root' do not cause 'root' to be reported as compromised when 'admin_user' logs in."""
    inp = {
        "incident_id": "INC-BUG-001",
        "title": "Root Probing Followed by Admin User Login",
        "created_at": "2026-08-29T10:00:00Z",
        "initial_severity": "HIGH",
        "entities": {
            "hosts": ["srv-db01"],
            "users": ["root", "admin_user"],
            "ip_addresses": ["192.168.1.105"]
        },
        "events": [
            {
                "event_id": "EVT-1",
                "timestamp": "2026-08-29T10:00:01Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "srv-db01",
                "user": "root",
                "ip_address": "192.168.1.105",
                "raw_data": {}
            },
            {
                "event_id": "EVT-2",
                "timestamp": "2026-08-29T10:00:05Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "srv-db01",
                "user": "root",
                "ip_address": "192.168.1.105",
                "raw_data": {}
            },
            {
                "event_id": "EVT-3",
                "timestamp": "2026-08-29T10:00:10Z",
                "source": "auth.log",
                "event_type": "ssh_login_success",
                "severity": "HIGH",
                "host": "srv-db01",
                "user": "admin_user",
                "ip_address": "192.168.1.105",
                "raw_data": {}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    # Must NOT report root as compromised
    assert "compromised account 'root'" not in output["summary"]
    assert "weak credentials for 'root'" not in output["root_cause"]
    assert "'admin_user'" in output["summary"]

# --- REGRESSION TEST FOR BUG-002: Overly Broad Privileged Command Classification ---
def test_bug_002_broad_command_classification_regression():
    """Verify that unprivileged cmd_execution events do not trigger privilege escalation classification."""
    inp = {
        "incident_id": "INC-BUG-002",
        "title": "Unprivileged Command Execution",
        "created_at": "2026-08-29T11:00:00Z",
        "initial_severity": "LOW",
        "entities": {
            "hosts": ["web-01"],
            "users": ["app_user"],
            "ip_addresses": ["10.0.0.5"]
        },
        "events": [
            {
                "event_id": "EVT-CMD-1",
                "timestamp": "2026-08-29T11:01:00Z",
                "source": "app.log",
                "event_type": "cmd_execution",
                "severity": "LOW",
                "host": "web-01",
                "user": "app_user",
                "ip_address": "10.0.0.5",
                "raw_data": {"command": "echo hello"}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert "TA0004: Privilege Escalation" not in output["mitre_tactics"]
    assert output["assessed_severity"] == "LOW"
    assert not any("Execution of privileged command" in e["description"] for e in output["evidence"])

# --- REGRESSION TEST FOR BUG-003: Sensitive Credential Access False Positives ---
def test_bug_003_credential_access_false_positives():
    """Verify benign commands containing 'cat' or 'concat' or harmless files do not trigger TA0006 Credential Access."""
    commands = [
        "concat files.txt",
        "cat /tmp/test.txt",
        "category_list.sh",
        "netcat -l 8080"
    ]
    for idx, cmd in enumerate(commands):
        inp = {
            "incident_id": f"INC-BUG-003-{idx}",
            "title": "Harmless Command Execution",
            "created_at": "2026-08-29T11:00:00Z",
            "initial_severity": "LOW",
            "entities": {
                "hosts": ["web-01"],
                "users": ["app_user"],
                "ip_addresses": ["10.0.0.5"]
            },
            "events": [
                {
                    "event_id": f"EVT-C-{idx}",
                    "timestamp": "2026-08-29T11:01:00Z",
                    "source": "syslog",
                    "event_type": "process_creation",
                    "severity": "LOW",
                    "host": "web-01",
                    "user": "app_user",
                    "ip_address": "10.0.0.5",
                    "raw_data": {"command": cmd}
                }
            ]
        }
        output = investigate(inp)
        validate_agent_output(output)
        assert "TA0006: Credential Access" not in output["mitre_tactics"]
        assert output["assessed_severity"] == "LOW"

# --- REGRESSION TEST FOR BUG-004: Deduplication of Response Actions ---
def test_bug_004_response_actions_deduplication():
    """Verify that multiple events for the same IP or User do not generate duplicate response actions."""
    inp = {
        "incident_id": "INC-BUG-004",
        "title": "Multiple Events Same IP",
        "created_at": "2026-08-29T12:00:00Z",
        "initial_severity": "HIGH",
        "entities": {
            "hosts": ["host-1"],
            "users": ["alice"],
            "ip_addresses": ["192.168.1.50"]
        },
        "events": [
            {
                "event_id": "EVT-1",
                "timestamp": "2026-08-29T12:01:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-1",
                "user": "alice",
                "ip_address": "192.168.1.50",
                "raw_data": {}
            },
            {
                "event_id": "EVT-2",
                "timestamp": "2026-08-29T12:02:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-1",
                "user": "alice",
                "ip_address": "192.168.1.50",
                "raw_data": {}
            },
            {
                "event_id": "EVT-3",
                "timestamp": "2026-08-29T12:03:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_success",
                "severity": "HIGH",
                "host": "host-1",
                "user": "alice",
                "ip_address": "192.168.1.50",
                "raw_data": {}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    actions = output["response_actions"]
    ip_blocks = [a for a in actions if "Block Source IP 192.168.1.50" in a["title"]]
    user_resets = [a for a in actions if "Reset Credentials for User alice" in a["title"]]
    
    assert len(ip_blocks) == 1
    assert len(user_resets) == 1
    assert [a["action_id"] for a in actions] == ["ACT-001", "ACT-002", "ACT-003"]

# --- REGRESSION TEST FOR BUG-005 & BUG-006: Timestamp Delta Correlation Window & Confidence Scoring ---
def test_bug_005_006_timestamp_window_correlation_and_confidence():
    """Verify that brute force attempts > 1 hour prior to login do NOT correlate into a brute force chain or inflate confidence."""
    inp_outside_window = {
        "incident_id": "INC-BUG-005-OUT",
        "title": "Old Failures and New Login",
        "created_at": "2026-08-29T15:00:00Z",
        "initial_severity": "LOW",
        "entities": {
            "hosts": ["host-1"],
            "users": ["charlie"],
            "ip_addresses": ["10.0.0.99"]
        },
        "events": [
            {
                "event_id": "EVT-OLD-1",
                "timestamp": "2026-08-29T08:00:00Z",  # 7 hours prior
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-1",
                "user": "charlie",
                "ip_address": "10.0.0.99",
                "raw_data": {}
            },
            {
                "event_id": "EVT-OLD-2",
                "timestamp": "2026-08-29T08:01:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-1",
                "user": "charlie",
                "ip_address": "10.0.0.99",
                "raw_data": {}
            },
            {
                "event_id": "EVT-NEW-3",
                "timestamp": "2026-08-29T15:00:00Z",  # Current login
                "source": "auth.log",
                "event_type": "ssh_login_success",
                "severity": "LOW",
                "host": "host-1",
                "user": "charlie",
                "ip_address": "10.0.0.99",
                "raw_data": {}
            }
        ]
    }
    output = investigate(inp_outside_window)
    validate_agent_output(output)
    
    # Must NOT correlate into brute force compromise chain due to time gap
    assert "brute force" not in output["summary"].lower()
    assert output["confidence_score"] < 0.85

    # Conversely, events WITHIN 1 hour window MUST correlate and receive 0.85+ confidence
    inp_inside_window = dict(inp_outside_window)
    inp_inside_window["events"] = [
        dict(inp_outside_window["events"][0], timestamp="2026-08-29T14:50:00Z"),
        dict(inp_outside_window["events"][1], timestamp="2026-08-29T14:55:00Z"),
        dict(inp_outside_window["events"][2], timestamp="2026-08-29T15:00:00Z")
    ]
    output_inside = investigate(inp_inside_window)
    validate_agent_output(output_inside)
    
    assert "brute force" in output_inside["summary"].lower()
    assert output_inside["confidence_score"] >= 0.85

# --- SCENARIO B: Privileged Command Execution (Standalone) ---
def test_scenario_b_privileged_command_execution():
    inp = {
        "incident_id": "INC-2026-SCEN-B",
        "title": "Standalone Sudo Execution Anomaly",
        "created_at": "2026-08-29T12:00:00Z",
        "initial_severity": "MEDIUM",
        "entities": {
            "hosts": ["app-server-01"],
            "users": ["bob"],
            "ip_addresses": ["10.0.0.15"]
        },
        "events": [
            {
                "event_id": "EVT-B1",
                "timestamp": "2026-08-29T12:01:00Z",
                "source": "syslog",
                "event_type": "sudo_command_execution",
                "severity": "HIGH",
                "host": "app-server-01",
                "user": "bob",
                "ip_address": "10.0.0.15",
                "raw_data": {"command": "sudo systemctl restart nginx"}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert output["assessed_severity"] == "HIGH"
    assert output["confidence_score"] == 0.75
    assert "TA0004: Privilege Escalation" in output["mitre_tactics"]
    assert "Execution of privileged command" in output["evidence"][0]["description"]

# --- SCENARIO C: Sensitive File or Credential Access ---
def test_scenario_c_credential_file_access():
    inp = {
        "incident_id": "INC-2026-SCEN-C",
        "title": "Sensitive Security File Read",
        "created_at": "2026-08-29T13:00:00Z",
        "initial_severity": "HIGH",
        "entities": {
            "hosts": ["db-host-02"],
            "users": ["svc_account"],
            "ip_addresses": ["10.0.2.100"]
        },
        "events": [
            {
                "event_id": "EVT-C1",
                "timestamp": "2026-08-29T13:05:00Z",
                "source": "auditd",
                "event_type": "sensitive_read",
                "severity": "HIGH",
                "host": "db-host-02",
                "user": "svc_account",
                "ip_address": "10.0.2.100",
                "raw_data": {"command": "cat /etc/shadow"}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert output["assessed_severity"] == "HIGH"
    assert "TA0006: Credential Access" in output["mitre_tactics"]
    assert "Sensitive credential file access" in output["summary"]

# --- SCENARIO D: Suspicious Successful Login (Without Prior Brute Force) ---
def test_scenario_d_suspicious_login():
    inp = {
        "incident_id": "INC-2026-SCEN-D",
        "title": "Unusual Location SSH Login",
        "created_at": "2026-08-29T14:00:00Z",
        "initial_severity": "HIGH",
        "entities": {
            "hosts": ["prod-api-01"],
            "users": ["dev_user"],
            "ip_addresses": ["198.51.100.42"]
        },
        "events": [
            {
                "event_id": "EVT-D1",
                "timestamp": "2026-08-29T14:02:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_success",
                "severity": "HIGH",
                "host": "prod-api-01",
                "user": "dev_user",
                "ip_address": "198.51.100.42",
                "raw_data": {"suspicious": True}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert output["confidence_score"] == 0.75
    assert "TA0001: Initial Access" in output["mitre_tactics"]
    assert any("standalone authentication anomaly" in step["action"] for step in output["reasoning_steps"])

# --- SCENARIO E: Multiple Independent Suspicious Activities (Entity Separation) ---
def test_scenario_e_independent_activities_not_merged():
    inp = {
        "incident_id": "INC-2026-SCEN-E",
        "title": "Multi-Entity Incident",
        "created_at": "2026-08-29T15:00:00Z",
        "initial_severity": "HIGH",
        "entities": {
            "hosts": ["host-alpha", "host-beta"],
            "users": ["user1", "user2"],
            "ip_addresses": ["1.1.1.1", "2.2.2.2"]
        },
        "events": [
            {
                "event_id": "EVT-E1",
                "timestamp": "2026-08-29T15:01:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-alpha",
                "user": "user1",
                "ip_address": "1.1.1.1",
                "raw_data": {}
            },
            {
                "event_id": "EVT-E2",
                "timestamp": "2026-08-29T15:02:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "host-alpha",
                "user": "user1",
                "ip_address": "1.1.1.1",
                "raw_data": {}
            },
            {
                "event_id": "EVT-E3",
                "timestamp": "2026-08-29T15:03:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_success",
                "severity": "HIGH",
                "host": "host-beta",
                "user": "user2",
                "ip_address": "2.2.2.2",
                "raw_data": {}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    # Ensure brute force chain wasn't falsely formed between user1@1.1.1.1 and user2@2.2.2.2
    assert not any("brute force from 1.1.1.1" in step["finding"] and "user2" in step["finding"] for step in output["reasoning_steps"])
    assert len(output["evidence"]) == 3

# --- SCENARIO F: Benign Activity ---
def test_scenario_f_benign_activity():
    inp = {
        "incident_id": "INC-2026-SCEN-F",
        "title": "Routine Status Check",
        "created_at": "2026-08-29T16:00:00Z",
        "initial_severity": "LOW",
        "entities": {
            "hosts": ["web-01"],
            "users": ["app_user"],
            "ip_addresses": ["10.0.0.10"]
        },
        "events": [
            {
                "event_id": "EVT-F1",
                "timestamp": "2026-08-29T16:01:00Z",
                "source": "httpd.log",
                "event_type": "http_get_request",
                "severity": "LOW",
                "host": "web-01",
                "user": "app_user",
                "ip_address": "10.0.0.10",
                "raw_data": {"path": "/healthz"}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert output["assessed_severity"] == "LOW"
    assert output["confidence_score"] == 0.40
    assert "no confirmed exploit patterns detected" in output["summary"]

# --- SCENARIO G: Unknown or Unsupported Event Data ---
def test_scenario_g_unknown_data_resilience():
    inp = {
        "incident_id": "INC-2026-SCEN-G",
        "title": "Custom Third-Party Telemetry",
        "created_at": "2026-08-29T17:00:00Z",
        "initial_severity": "LOW",
        "entities": {
            "hosts": [],
            "users": [],
            "ip_addresses": []
        },
        "events": [
            {
                "event_id": "EVT-G1",
                "timestamp": "2026-08-29T17:01:00Z",
                "source": "custom_sensor",
                "event_type": "unknown_custom_signal",
                "severity": "LOW",
                "raw_data": {"custom_key": [1, 2, 3]}
            }
        ]
    }
    output = investigate(inp)
    validate_agent_output(output)
    
    assert output["incident_id"] == "INC-2026-SCEN-G"
    assert output["assessed_severity"] == "LOW"
    assert len(output["evidence"]) >= 1

def test_runner_execution(mock_agent_input):
    """Test standalone runner script module execution."""
    from src.runner import main
    old_argv = sys.argv
    try:
        sys.argv = ["runner.py"]
        main()
    finally:
        sys.argv = old_argv
