from typing import Dict, Any
from .validator import validate_agent_input, validate_agent_output
from .analyzer import analyze_events

def investigate(agent_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main AI Agent investigation entry point.
    
    1. Validates input schema against agent_input.json
    2. Performs deterministic event correlation and attack investigation logic
    3. Validates output schema against agent_output.json
    4. Returns structured output
    """
    # 1. Validate Input
    validate_agent_input(agent_input)

    # 2. Phase 2 Deterministic Investigation Logic
    output = analyze_events(agent_input)

    # 3. Validate Output
    validate_agent_output(output)

    return output
