import unittest

from app.config import PROTECTED_INSTANCES

from app.quarantine.quarantine_decision import (
    evaluate_quarantine,
    consolidate_decisions
)


class TestQuarantineDecision(unittest.TestCase):

    def setUp(self):
        PROTECTED_INSTANCES.add("i-protected-test")

    def tearDown(self):
        PROTECTED_INSTANCES.discard("i-protected-test")


    def test_critical_risk_recommends_quarantine(self):
        finding = {
            "instance_id": "i-target-test",
            "risk_score": 100
        }

        result = evaluate_quarantine(finding)

        self.assertEqual(
            result["decision"],
            "QUARANTINE_RECOMMENDED"
        )

    def test_protected_instance_never_quarantined(self):
        finding = {
            "instance_id": "i-protected-test",
            "risk_score": 100
        }

        result = evaluate_quarantine(finding)

        self.assertEqual(result["decision"], "NO_ACTION")

    def test_low_risk_does_not_recommend_quarantine(self):
        finding = {
            "instance_id": "i-test123",
            "risk_score": 40
        }

        result = evaluate_quarantine(finding)

        self.assertEqual(result["decision"], "NO_ACTION")

    def test_quarantine_remains_dry_run(self):
        finding = {
            "instance_id": "i-target-test",
            "risk_score": 100
        }

        result = evaluate_quarantine(finding)

        self.assertEqual(result["mode"], "DRY_RUN")

    def test_duplicate_findings_produce_one_decision(self):
        findings = [
            {
                "instance_id": "i-test123",
                "risk_score": 75
            },
            {
                "instance_id": "i-test123",
                "risk_score": 100
            }
        ]

        decisions = [
            evaluate_quarantine(finding)
            for finding in findings
        ]

        result = consolidate_decisions(decisions)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
