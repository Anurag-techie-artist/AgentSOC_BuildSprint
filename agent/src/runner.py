import os
import sys
import json

# Ensure agent/ directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agent import investigate
from src.validator import ValidationError

def main():
    default_input_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "mocks", "mock_agent_input.json")
    )
    
    input_path = sys.argv[1] if len(sys.argv) > 1 else default_input_path
    
    print(f"=== AgentSOC Standalone Runner ===")
    print(f"Loading input file: {input_path}")
    
    if not os.path.exists(input_path):
        print(f"Error: Input file does not exist: {input_path}")
        sys.exit(1)
        
    with open(input_path, "r", encoding="utf-8") as f:
        try:
            agent_input = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse JSON input: {e}")
            sys.exit(1)

    print("Running investigate(agent_input)...")
    try:
        output = investigate(agent_input)
        print("\n=== Investigation Completed Successfully ===")
        print(json.dumps(output, indent=2))
    except ValidationError as e:
        print(f"\n[Validation Error] Investigation Failed:\n{e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[Error] Unexpected exception during investigation:\n{e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
