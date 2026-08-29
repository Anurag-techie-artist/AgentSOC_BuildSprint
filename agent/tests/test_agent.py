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

def test_investigate_phase2_brute_force_scenario(mock_agent_input):
    """Test Phase 2 investigation engine against SSH brute force + privilege escalation scenario."""
    output = investigate(mock_agent_input)
    
    # Contract checks
    validate_agent_output(output)
    assert output["incident_id"] == "INC-2026-0001"
    assert output["assessed_severity"] == "CRITICAL"
    assert output["confidence_score"] > 0.8
    
    # Check reasoning steps generated dynamically
    assert len(output["reasoning_steps"]) >= 3
    assert any("Ingested 4 security events" in step["action"] for step in output["reasoning_steps"])
    assert any("failed login attempts" in step["finding"] for step in output["reasoning_steps"])
    assert any("elevated command execution" in step["finding"] for step in output["reasoning_steps"])
    
    # Check evidence dynamically extracted
    assert len(output["evidence"]) == 4
    event_ids = [e["source_event_id"] for e in output["evidence"]]
    assert "EVT-1001" in event_ids
    assert "EVT-1004" in event_ids
    
    # Check MITRE tactics mapped
    assert "TA0001: Initial Access (Credential Stuffing / Brute Force)" in output["mitre_tactics"]
    assert "TA0004: Privilege Escalation" in output["mitre_tactics"]
    assert "TA0006: Credential Access" in output["mitre_tactics"]
    
    # Check response actions dynamically constructed
    action_titles = [a["title"] for a in output["response_actions"]]
    assert any("Block Source IP 192.168.1.105" in title for title in action_titles)
    assert any("Reset Credentials for User admin_user" in title for title in action_titles)
    assert any("Isolate Host srv-prod-db01" in title for title in action_titles)

def test_investigate_phase2_low_severity_single_event_scenario(mock_agent_input):
    """Test Phase 2 investigation with a single low severity event."""
    low_input = {
        "incident_id": "INC-2026-0002",
        "title": "Isolated Authentication Failure",
        "created_at": "2026-08-29T11:00:00Z",
        "initial_severity": "LOW",
        "entities": {
            "hosts": ["workstation-12"],
            "users": ["alice"],
            "ip_addresses": ["10.0.0.50"]
        },
        "events": [
            {
                "event_id": "EVT-9001",
                "timestamp": "2026-08-29T10:59:00Z",
                "source": "auth.log",
                "event_type": "ssh_login_failure",
                "severity": "LOW",
                "host": "workstation-12",
                "user": "alice",
                "ip_address": "10.0.0.50",
                "raw_data": {"attempts": 1}
            }
        ]
    }
    
    output = investigate(low_input)
    validate_agent_output(output)
    
    assert output["incident_id"] == "INC-2026-0002"
    assert output["assessed_severity"] == "LOW"
    assert "10.0.0.50" in output["summary"]
    assert len(output["evidence"]) == 1
    assert output["evidence"][0]["source_event_id"] == "EVT-9001"

def test_runner_execution(mock_agent_input):
    """Test standalone runner script module execution."""
    from src.runner import main
    old_argv = sys.argv
    try:
        sys.argv = ["runner.py"]
        main()
    finally:
        sys.argv = old_argv
