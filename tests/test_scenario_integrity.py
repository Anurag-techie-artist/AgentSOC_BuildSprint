from datetime import datetime
import glob
import json
import os
import unittest


class TestScenarioIntegrity(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.scenarios_dir = os.path.join(self.base_dir, "data", "scenarios")

    def parse_iso8601(self, timestamp_str):
        # Handle ISO 8601 timestamps ending in 'Z'
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        return datetime.fromisoformat(timestamp_str)

    def test_chronological_timestamp_order(self):
        scenario_files = glob.glob(os.path.join(self.scenarios_dir, "*.json"))
        for file_path in scenario_files:
            with self.subTest(file=os.path.basename(file_path)):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                events = data.get("events", [])
                timestamps = [
                    self.parse_iso8601(evt["timestamp"]) for evt in events
                ]

                for i in range(1, len(timestamps)):
                    self.assertGreaterEqual(
                        timestamps[i],
                        timestamps[i - 1],
                        f"Event timestamps out of chronological order in {file_path} at index {i}: "
                        f"{events[i-1]['timestamp']} > {events[i]['timestamp']}",
                    )

    def test_entity_mapping_consistency(self):
        scenario_files = glob.glob(os.path.join(self.scenarios_dir, "*.json"))
        for file_path in scenario_files:
            with self.subTest(file=os.path.basename(file_path)):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                entities = data.get("entities", {})
                scenario_hosts = set(entities.get("hosts", []))
                scenario_users = set(entities.get("users", []))
                scenario_ips = set(entities.get("ip_addresses", []))

                events = data.get("events", [])
                event_ids = set()

                for idx, evt in enumerate(events):
                    # Unique event ID check
                    evt_id = evt["event_id"]
                    self.assertNotIn(
                        evt_id,
                        event_ids,
                        f"Duplicate event_id '{evt_id}' found in {file_path}",
                    )
                    event_ids.add(evt_id)

                    # Host entity consistency check
                    if evt.get("host"):
                        self.assertIn(
                            evt["host"],
                            scenario_hosts,
                            f"Host '{evt['host']}' in event {evt_id} not present in top-level entities.hosts in {file_path}",
                        )

                    # User entity consistency check
                    if evt.get("user"):
                        self.assertIn(
                            evt["user"],
                            scenario_users,
                            f"User '{evt['user']}' in event {evt_id} not present in top-level entities.users in {file_path}",
                        )

                    # IP entity consistency check
                    if evt.get("ip_address") and evt["ip_address"] != "127.0.0.1":
                        self.assertIn(
                            evt["ip_address"],
                            scenario_ips,
                            f"IP address '{evt['ip_address']}' in event {evt_id} not present in top-level entities.ip_addresses in {file_path}",
                        )


if __name__ == "__main__":
    unittest.main()
