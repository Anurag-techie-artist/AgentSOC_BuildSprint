import os
import sys
import json
import pytest

# Add agent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent import investigate
from src.validator import validate_agent_input, validate_agent_output, ValidationError

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
