import os
import sys
import json
import pytest

# Add agent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent import investigate
from src.validator import validate_agent_input, validate_agent_output, ValidationError

@pytest.fixture
def valid_agent_input():
    mock_input_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks", "mock_agent_input.json")
    )
    with open(mock_input_path, "r", encoding="utf-8") as f:
        return json.load(f)

@pytest.fixture
def valid_agent_output():
    mock_output_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks", "mock_agent_output.json")
    )
    with open(mock_output_path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_validate_valid_input(valid_agent_input):
    """Test that valid input passes validation without error."""
    validate_agent_input(valid_agent_input)

def test_validate_invalid_input_missing_required(valid_agent_input):
    """Test that input missing a required field raises ValidationError."""
    invalid_input = dict(valid_agent_input)
    del invalid_input["incident_id"]
    with pytest.raises(ValidationError, match="missing required field 'incident_id'"):
        validate_agent_input(invalid_input)

def test_validate_invalid_input_wrong_type(valid_agent_input):
    """Test that input with wrong type raises ValidationError."""
    invalid_input = dict(valid_agent_input)
    invalid_input["initial_severity"] = 12345  # should be enum string
    with pytest.raises(ValidationError, match="initial_severity"):
        validate_agent_input(invalid_input)

def test_validate_valid_output(valid_agent_output):
    """Test that valid output passes validation without error."""
    validate_agent_output(valid_agent_output)

def test_validate_invalid_output_out_of_bounds(valid_agent_output):
    """Test that output with confidence_score > 1.0 raises ValidationError."""
    invalid_output = dict(valid_agent_output)
    invalid_output["confidence_score"] = 1.5
    with pytest.raises(ValidationError, match="greater than maximum 1.0"):
        validate_agent_output(invalid_output)

def test_validate_invalid_output_additional_properties(valid_agent_output):
    """Test that output with additional properties raises ValidationError."""
    invalid_output = dict(valid_agent_output)
    invalid_output["unknown_extra_field"] = "bad"
    with pytest.raises(ValidationError, match="unexpected additional property"):
        validate_agent_output(invalid_output)

def test_investigate_interface(valid_agent_input):
    """Test the investigate() interface with valid input."""
    output = investigate(valid_agent_input)
    assert output["incident_id"] == valid_agent_input["incident_id"]
    assert output["assessed_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert isinstance(output["confidence_score"], float)
    assert 0.0 <= output["confidence_score"] <= 1.0

def test_runner_execution(valid_agent_input):
    """Test standalone runner script module execution."""
    from src.runner import main
    old_argv = sys.argv
    try:
        sys.argv = ["runner.py"]
        # Should execute main() without raising SystemExit or errors
        main()
    finally:
        sys.argv = old_argv
