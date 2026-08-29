import os
import json
from typing import Dict, Any
from .validator import validate_agent_input, validate_agent_output

def _get_mock_agent_output() -> Dict[str, Any]:
    """Load mock output template from contracts/mocks/mock_agent_output.json."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks"))
    mock_path = os.path.join(base_dir, "mock_agent_output.json")
    if not os.path.exists(mock_path):
        raise FileNotFoundError(f"Mock output file not found: {mock_path}")
    with open(mock_path, "r", encoding="utf-8") as f:
        return json.load(f)

def investigate(agent_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main AI Agent investigation entry point.
    
    1. Validates input schema against agent_input.json
    2. Performs investigation logic (Phase 1: returns deterministic mock result keyed to input)
    3. Validates output schema against agent_output.json
    4. Returns structured output
    """
    # 1. Validate Input
    validate_agent_input(agent_input)

    # 2. Phase 1 Deterministic Response Generation
    mock_output = _get_mock_agent_output()
    output = dict(mock_output)
    # Bind result to the provided incident_id
    output["incident_id"] = agent_input["incident_id"]

    # 3. Validate Output
    validate_agent_output(output)

    return output
