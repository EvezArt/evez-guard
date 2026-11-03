import json
import tempfile
import unittest
from pathlib import Path
from agent_guard import Guard, HashChainLedger, Policy, decide, verify_ledger

class PolicyTests(unittest.TestCase):
    def test_safe_read_allowed(self):
        self.assertEqual(decide("list_directory", {"path": "/tmp"})["action"], "allow")
    def test_destructive_tool_denied(self):
        self.assertEqual(decide("delete_file", {"path": "/tmp/x"})["action"], "deny")
    def test_unknown_tool_review(self):
        self.assertEqual(decide("launch_drone", {})["action"], "review")
    def test_network_requires_approval(self):
        self.assertEqual(decide("http_get", {"url": "https://example.org"})["action"], "review")
    def test_credential_read_review(self):
        self.assertEqual(decide("read_file", {"path": "/home/user/.env"})["action"], "review")
    def test_credential_to_network_denied(self):
        self.assertEqual(decide("http_post", {"body": "token"}, prior_sensitive_read=True)["action"], "deny")
    def test_missing_session_denied(self):
        self.assertEqual(Guard().before_tool_call("", "list_directory", {}) .action, "deny")
    def test_session_sequence(self):
        guard = Guard()
        first = guard.before_tool_call("s1", "read_file", {"path": "/home/u/.env"})
        self.assertEqual(first.action, "review")
        # A reviewed call is not assumed to have executed; state is not elevated.
        self.assertEqual(guard.before_tool_call("s1", "http_post", {"url": "https://example.org"}).action, "review")

class LedgerTests(unittest.TestCase):
    def test_hash_chain_valid_and_tamper_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "audit.jsonl"
            ledger = HashChainLedger(p)
            ledger.append({"timestamp":"2026-11-03T00:00:00Z","session_id":"s","call_id":"c1","tool":"list_directory","action":"allow","reason":"ok","rule_id":"EG-000","prompt":"must not be stored"})
            self.assertTrue(verify_ledger(p)["valid"])
            row = json.loads(p.read_text())
            self.assertNotIn("prompt", row["event"])
            row["event"]["action"] = "deny"
            p.write_text(json.dumps(row) + "\n")
            self.assertFalse(verify_ledger(p)["valid"])
    def test_capacity_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = HashChainLedger(Path(tmp)/"audit.jsonl", max_bytes=80)
            with self.assertRaises(RuntimeError):
                ledger.append({"tool":"list_directory","action":"allow","reason":"x"*100})

if __name__ == "__main__":
    unittest.main()
