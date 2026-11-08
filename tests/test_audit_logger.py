import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.audit import audit_logger


class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_dir = Path(self.temp_dir.name)
        self.audit_file = self.audit_dir / "audit_log.jsonl"

        self.patches = [
            patch.object(audit_logger, "AUDIT_DIR", self.audit_dir),
            patch.object(audit_logger, "AUDIT_FILE", self.audit_file)
        ]

        for item in self.patches:
            item.start()

        self.decision = {
            "instance_id": "i-test123",
            "risk_score": 100,
            "decision": "QUARANTINE_RECOMMENDED",
            "dependency_safety": {
                "status": "NETWORK_REVIEW_REQUIRED",
                "execution_allowed": False
            }
        }

    def tearDown(self):
        for item in self.patches:
            item.stop()

        self.temp_dir.cleanup()

    def test_audit_record_contains_security_assessment(self):
        audit_logger.record_audit_event(
            self.decision,
            evidence_file="evidence.json",
            evidence_hash="abc123"
        )

        with self.audit_file.open() as file:
            event = json.loads(file.readline())

        self.assertEqual(event["instance_id"], "i-test123")
        self.assertEqual(event["risk_score"], 100)
        self.assertEqual(
            event["risk_decision"],
            "QUARANTINE_RECOMMENDED"
        )
        self.assertEqual(
            event["dependency_safety"],
            "NETWORK_REVIEW_REQUIRED"
        )
        self.assertFalse(event["execution_allowed"])
        self.assertEqual(event["evidence_sha256"], "abc123")
        self.assertFalse(event["aws_resources_modified"])

    def test_multiple_events_are_appended(self):
        audit_logger.record_audit_event(self.decision)
        audit_logger.record_audit_event(self.decision)

        with self.audit_file.open() as file:
            events = [json.loads(line) for line in file]

        self.assertEqual(len(events), 2)


if __name__ == "__main__":
    unittest.main()
