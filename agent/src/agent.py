from typing import Dict, Any, Optional
from .validator import validate_agent_input, validate_agent_output
from .analyzer import analyze_events
from .reasoning import apply_ai_reasoning
from .providers import LLMProvider

def investigate(
    agent_input: Dict[str, Any],
    provider: Optional[LLMProvider] = None
) -> Dict[str, Any]:
    """
    Main AI Agent investigation entry point.
    
    1. Validates input schema against agent_input.json
    2. Performs deterministic event correlation and attack investigation logic
    3. Enriches findings using AI reasoning layer (with safe fallback)
    4. Validates output schema against agent_output.json
    5. Returns structured output
    """
    # 1. Validate Input
    validate_agent_input(agent_input)

    # 2. Deterministic Investigation Layer (Evidence / Reliability Foundation)
    det_output = analyze_events(agent_input)

    # 3. AI Reasoning Layer (Grounded Synthesis & Verification)
    output = apply_ai_reasoning(agent_input, det_output, provider=provider)

    # 4. Validate Output Schema
    validate_agent_output(output)

    return output
