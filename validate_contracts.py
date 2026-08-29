import json
import os
import sys

def validate_dict(data, schema, name, path=""):
    errors = []
    
    # Check type
    if schema.get("type") == "object":
        if not isinstance(data, dict):
            return [f"{path}: expected object/dict, got {type(data).__name__}"]
        
        # Required properties
        required = schema.get("required", [])
        for req in required:
            if req not in data:
                errors.append(f"{path}: missing required field '{req}'")
        
        # Properties check
        props = schema.get("properties", {})
        for key, val in data.items():
            if key in props:
                sub_schema = props[key]
                errors.extend(validate_val(val, sub_schema, name, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected additional property '{key}'")
                
    return errors

def validate_val(val, schema, name, path):
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
            errors.append(f"{path}: expected type {expected_types}, got {type(val).__name__}")
            return errors

    # Check Enum
    if "enum" in schema:
        if val not in schema["enum"]:
            errors.append(f"{path}: value '{val}' not in allowed enum {schema['enum']}")

    # Check object properties
    if schema.get("type") == "object" and isinstance(val, dict):
        errors.extend(validate_dict(val, schema, name, path))

    # Check array items
    if schema.get("type") == "array" and isinstance(val, list):
        items_schema = schema.get("items", {})
        for idx, item in enumerate(val):
            errors.extend(validate_val(item, items_schema, name, f"{path}[{idx}]"))

    return errors

def main():
    schemas_dir = os.path.abspath("contracts/schemas")
    mocks_dir = os.path.abspath("contracts/mocks")

    schemas = {}
    for filename in os.listdir(schemas_dir):
        if filename.endswith(".json"):
            with open(os.path.join(schemas_dir, filename), "r", encoding="utf-8") as f:
                schemas[filename] = json.load(f)

    # For agent_input.json, expand $ref for security_event.json
    schemas["agent_input.json"]["properties"]["events"]["items"] = schemas["security_event.json"]

    validations = [
        ("security_event.json", "sample_events.json", True),
        ("incident.json", "sample_incident.json", False),
        ("agent_input.json", "mock_agent_input.json", False),
        ("agent_output.json", "mock_agent_output.json", False)
    ]

    print("=== RUNNING CONTRACT STRUCTURE VALIDATION ===")
    all_passed = True
    for schema_file, mock_file, is_list in validations:
        schema = schemas[schema_file]
        mock_path = os.path.join(mocks_dir, mock_file)
        with open(mock_path, "r", encoding="utf-8") as f:
            mock_data = json.load(f)

        errors = []
        if is_list:
            for idx, item in enumerate(mock_data):
                errs = validate_dict(item, schema, schema_file, f"root[{idx}]")
                errors.extend(errs)
        else:
            errors = validate_dict(mock_data, schema, schema_file, "root")

        if errors:
            print(f"FAILED: {mock_file} against {schema_file}")
            for e in errors:
                print(f"  - {e}")
            all_passed = False
        else:
            print(f"PASSED: {mock_file} successfully validated against {schema_file}")

    if all_passed:
        print("\nAll contract schemas and mock data validated successfully!")
    else:
        print("\nContract validation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
