import json
import os
from typing import Dict, Any, List, Tuple

class ValidationError(Exception):
    """Custom exception raised when contract validation fails."""
    pass

def _load_schema(schema_name: str) -> Dict[str, Any]:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "schemas"))
    schema_path = os.path.join(base_dir, schema_name)
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)

def _get_schemas() -> Dict[str, Dict[str, Any]]:
    schemas = {
        "security_event.json": _load_schema("security_event.json"),
        "agent_input.json": _load_schema("agent_input.json"),
        "agent_output.json": _load_schema("agent_output.json"),
    }
    schemas["agent_input.json"]["properties"]["events"]["items"] = schemas["security_event.json"]
    return schemas

def _validate_value(val: Any, schema: Dict[str, Any], path: str) -> List[str]:
    errors = []
    
    expected_types = schema.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
        
    if expected_types:
        type_matched = False
        for exp in expected_types:
            if exp == "string" and isinstance(val, str):
                type_matched = True
            elif exp == "number" and (isinstance(val, (int, float)) and not isinstance(val, bool)):
                type_matched = True
            elif exp == "integer" and isinstance(val, int) and not isinstance(val, bool):
                type_matched = True
            elif exp == "array" and isinstance(val, list):
                type_matched = True
            elif exp == "object" and isinstance(val, dict):
                type_matched = True
            elif exp == "null" and val is None:
                type_matched = True
            elif exp == "boolean" and isinstance(val, bool):
                type_matched = True
                
        if not type_matched:
            return [f"{path}: expected type {expected_types}, got {type(val).__name__}"]

    # Min/Max numerical bounds
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        if "minimum" in schema and val < schema["minimum"]:
            errors.append(f"{path}: value {val} is less than minimum {schema['minimum']}")
        if "maximum" in schema and val > schema["maximum"]:
            errors.append(f"{path}: value {val} is greater than maximum {schema['maximum']}")

    # Enum checks
    if "enum" in schema:
        if val not in schema["enum"]:
            errors.append(f"{path}: value '{val}' not in allowed enum {schema['enum']}")

    # Object properties validation
    if schema.get("type") == "object" and isinstance(val, dict):
        required = schema.get("required", [])
        for req in required:
            if req not in val:
                errors.append(f"{path}: missing required field '{req}'")
        
        props = schema.get("properties", {})
        for k, v in val.items():
            if k in props:
                errors.extend(_validate_value(v, props[k], f"{path}.{k}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected additional property '{k}'")

    # Array items validation
    if schema.get("type") == "array" and isinstance(val, list):
        items_schema = schema.get("items", {})
        for idx, item in enumerate(val):
            errors.extend(_validate_value(item, items_schema, f"{path}[{idx}]"))

    return errors

def validate_agent_input(agent_input: Dict[str, Any]) -> None:
    """Validate input data against contracts/schemas/agent_input.json."""
    schemas = _get_schemas()
    input_schema = schemas["agent_input.json"]
    errors = _validate_value(agent_input, input_schema, "agent_input")
    if errors:
        raise ValidationError(f"Invalid AgentInput:\n" + "\n".join(f" - {e}" for e in errors))

def validate_agent_output(agent_output: Dict[str, Any]) -> None:
    """Validate output data against contracts/schemas/agent_output.json."""
    schemas = _get_schemas()
    output_schema = schemas["agent_output.json"]
    errors = _validate_value(agent_output, output_schema, "agent_output")
    if errors:
        raise ValidationError(f"Invalid AgentOutput:\n" + "\n".join(f" - {e}" for e in errors))
