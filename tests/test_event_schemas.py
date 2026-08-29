import json
import glob
import os
import unittest


class TestEventSchemas(unittest.TestCase):
    REQUIRED_EVENT_KEYS = {
        "event_id",
        "timestamp",
        "source",
        "event_type",
        "severity",
        "host",
        "user",
        "ip_address",
        "raw_data",
    }

    REQUIRED_INCIDENT_KEYS = {
        "incident_id",
        "title",
        "created_at",
        "initial_severity",
        "entities",
        "events",
    }

    REQUIRED_ENTITY_KEYS = {"hosts", "users", "ip_addresses"}

    ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.scenarios_dir = os.path.join(self.base_dir, "data", "scenarios")

    def test_scenarios_exist(self):
        scenario_files = glob.glob(os.path.join(self.scenarios_dir, "*.json"))
        self.assertGreater(
            len(scenario_files), 0, "No scenario JSON files found in data/scenarios/"
        )

    def test_scenario_event_schemas(self):
        scenario_files = glob.glob(os.path.join(self.scenarios_dir, "*.json"))
        for file_path in scenario_files:
            with self.subTest(file=os.path.basename(file_path)):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Validate top-level incident fields
                for key in self.REQUIRED_INCIDENT_KEYS:
                    self.assertIn(
                        key,
                        data,
                        f"Missing required incident field '{key}' in {file_path}",
                    )

                self.assertIn(
                    data["initial_severity"],
                    self.ALLOWED_SEVERITIES,
                    f"Invalid initial_severity '{data.get('initial_severity')}' in {file_path}",
                )

                entities = data.get("entities", {})
                self.assertIsInstance(entities, dict, f"'entities' must be an object in {file_path}")
                for entity_key in self.REQUIRED_ENTITY_KEYS:
                    self.assertIn(
                        entity_key,
                        entities,
                        f"Missing required entity key '{entity_key}' in {file_path}",
                    )
                    self.assertIsInstance(
                        entities[entity_key],
                        list,
                        f"Entity list '{entity_key}' must be a list in {file_path}",
                    )

                events = data.get("events", [])
                self.assertIsInstance(events, list, f"'events' must be a list in {file_path}")
                self.assertGreater(
                    len(events), 0, f"Scenario {file_path} contains no events"
                )

                # Validate each event structure against security_event schema contract
                for idx, event in enumerate(events):
                    for req_key in self.REQUIRED_EVENT_KEYS:
                        self.assertIn(
                            req_key,
                            event,
                            f"Event index {idx} in {file_path} missing required key '{req_key}'",
                        )

                    self.assertIn(
                        event["severity"],
                        self.ALLOWED_SEVERITIES,
                        f"Event index {idx} in {file_path} has invalid severity '{event.get('severity')}'",
                    )
                    self.assertIsInstance(
                        event["raw_data"],
                        dict,
                        f"Event index {idx} in {file_path} 'raw_data' must be a dictionary",
                    )


if __name__ == "__main__":
    unittest.main()
