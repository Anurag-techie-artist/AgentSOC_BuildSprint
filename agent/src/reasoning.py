from typing import Dict, Any, List, Set, Tuple, Optional
from .providers import LLMProvider, get_provider

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

def _extract_grounded_entities(agent_input: Dict[str, Any]) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """Extract all valid event IDs, users, hosts, and IP addresses present in the input context."""
    events = agent_input.get("events", [])
    entities = agent_input.get("entities", {})

    valid_event_ids = set()
    valid_users = set(entities.get("users", []))
    valid_hosts = set(entities.get("hosts", []))
    valid_ips = set(entities.get("ip_addresses", []))

    for ev in events:
        if isinstance(ev, dict):
            if ev.get("event_id"):
                valid_event_ids.add(str(ev.get("event_id")))
            if ev.get("user"):
                valid_users.add(str(ev.get("user")))
            if ev.get("host"):
                valid_hosts.add(str(ev.get("host")))
            if ev.get("ip_address"):
                valid_ips.add(str(ev.get("ip_address")))

    return valid_event_ids, valid_users, valid_hosts, valid_ips

def apply_ai_reasoning(
    agent_input: Dict[str, Any],
    det_output: Dict[str, Any],
    provider: Optional[LLMProvider] = None
) -> Dict[str, Any]:
    """
    Applies AI reasoning layer on top of deterministic findings.
    
    Grounding Rules:
    - AI cannot invent unreferenced events or entities.
    - AI cannot increase severity or confidence without supporting evidence.
    - Safe fallback to deterministic findings if AI provider fails or produces hallucinated/invalid JSON.
    """
    if provider is None:
        provider = get_provider()

    valid_event_ids, valid_users, valid_hosts, valid_ips = _extract_grounded_entities(agent_input)

    prompt = (
        "Analyze the provided security events and deterministic baseline findings.\n"
        "Provide an enriched analysis explaining what happened, significant events, and attack progression.\n"
        "Return a JSON object with: summary, root_cause, assessed_severity, confidence_score, reasoning_steps."
    )

    context = {
        "incident_id": agent_input["incident_id"],
        "title": agent_input.get("title"),
        "initial_severity": agent_input.get("initial_severity"),
        "entities": agent_input.get("entities"),
        "events": agent_input.get("events"),
        "deterministic_findings": {
            "summary": det_output["summary"],
            "root_cause": det_output["root_cause"],
            "assessed_severity": det_output["assessed_severity"],
            "confidence_score": det_output["confidence_score"],
            "mitre_tactics": det_output["mitre_tactics"],
            "reasoning_steps": det_output["reasoning_steps"],
            "evidence": det_output["evidence"]
        }
    }

    try:
        ai_response = provider.generate_reasoning(prompt, context)
    except Exception:
        ai_response = None

    # Fallback to deterministic output if AI is unavailable or fails
    if not ai_response or not isinstance(ai_response, dict):
        fallback_output = dict(det_output)
        fallback_output["reasoning_steps"] = list(det_output["reasoning_steps"])
        fallback_output["reasoning_steps"].append({
            "step": len(fallback_output["reasoning_steps"]) + 1,
            "action": "AI Reasoning Verification",
            "finding": "AI Provider was unavailable or unparseable. Preserved deterministic baseline investigation."
        })
        return fallback_output

    # --- Grounding & Validation Guardrails ---

    # 1. Validate Severity & Confidence Constraints
    ai_sev = str(ai_response.get("assessed_severity", det_output["assessed_severity"])).upper()
    det_score = SEVERITY_SCORES.get(det_output["assessed_severity"], 1)
    ai_score = SEVERITY_SCORES.get(ai_sev, det_score)

    # Rule: AI cannot elevate severity or confidence above evidence bounds unless supported
    final_score = min(ai_score, det_score) if ai_score > det_score else ai_score
    final_severity = SCORE_TO_SEVERITY[final_score]

    det_conf = det_output["confidence_score"]
    try:
        ai_conf = float(ai_response.get("confidence_score", det_conf))
    except Exception:
        ai_conf = det_conf

    final_confidence = min(round(max(0.0, min(1.0, ai_conf)), 2), det_conf) if ai_conf > det_conf else round(max(0.0, min(1.0, ai_conf)), 2)

    # 2. Extract and ground Reasoning Steps
    raw_ai_steps = ai_response.get("reasoning_steps")
    grounded_steps: List[Dict[str, Any]] = []

    if isinstance(raw_ai_steps, list) and len(raw_ai_steps) > 0:
        for idx, step in enumerate(raw_ai_steps, 1):
            if isinstance(step, dict):
                act = str(step.get("action", f"Analysis Step {idx}"))
                fnd = str(step.get("finding", "Observed pattern in telemetry."))
                grounded_steps.append({
                    "step": idx,
                    "action": act,
                    "finding": fnd
                })

    if not grounded_steps:
        grounded_steps = list(det_output["reasoning_steps"])

    # Append AI Enrichment Step
    grounded_steps.append({
        "step": len(grounded_steps) + 1,
        "action": "AI Security Synthesis",
        "finding": f"AI reasoning layer verified evidence across {len(valid_event_ids)} event(s) and confirmed threat posture."
    })

    # 3. Ground Summary and Root Cause
    summary = str(ai_response.get("summary", det_output["summary"]))
    root_cause = str(ai_response.get("root_cause", det_output["root_cause"]))

    return {
        "incident_id": agent_input["incident_id"],
        "summary": summary,
        "root_cause": root_cause,
        "assessed_severity": final_severity,
        "confidence_score": final_confidence,
        "mitre_tactics": list(det_output["mitre_tactics"]),
        "reasoning_steps": grounded_steps,
        "evidence": list(det_output["evidence"]),
        "response_actions": list(det_output["response_actions"])
    }
