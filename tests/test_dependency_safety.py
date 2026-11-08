import unittest

from app.config import PROTECTED_INSTANCES
from app.quarantine.dependency_safety import assess_dependency_safety


class TestDependencySafety(unittest.TestCase):

    def setUp(self):
        PROTECTED_INSTANCES.add("i-protected-test")

        self.dependencies = {
            "i-target": {
                "network_interfaces": ["eni-target"],
                "security_groups": ["sg-target"],
                "volumes": ["vol-target"],
                "subnet_id": "subnet-target",
                "vpc_id": "vpc-target"
            },
            "i-other": {
                "network_interfaces": ["eni-other"],
                "security_groups": ["sg-other"],
                "volumes": ["vol-other"],
                "subnet_id": "subnet-other",
                "vpc_id": "vpc-other"
            }
        }

    def tearDown(self):
        PROTECTED_INSTANCES.discard("i-protected-test")

    def test_protected_instance_is_blocked(self):
        result = assess_dependency_safety(
            "i-protected-test",
            self.dependencies
        )
        self.assertEqual(result["status"], "BLOCKED_PROTECTED_INSTANCE")
        self.assertFalse(result["execution_allowed"])

    def test_missing_dependency_data_is_blocked(self):
        result = assess_dependency_safety("i-missing", {})
        self.assertEqual(
            result["status"],
            "BLOCKED_MISSING_DEPENDENCY_DATA"
        )

    def test_incomplete_dependency_data_is_blocked(self):
        result = assess_dependency_safety(
            "i-target",
            {"i-target": {"security_groups": ["sg-target"]}}
        )
        self.assertEqual(
            result["status"],
            "BLOCKED_INCOMPLETE_DEPENDENCY_DATA"
        )

    def test_shared_security_group_requires_manual_review(self):
        self.dependencies["i-other"]["security_groups"] = ["sg-target"]

        result = assess_dependency_safety("i-target", self.dependencies)

        self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertIn("security_groups", result["shared_resources"])

    def test_shared_subnet_requires_network_review(self):
        self.dependencies["i-other"]["subnet_id"] = "subnet-target"

        result = assess_dependency_safety("i-target", self.dependencies)

        self.assertEqual(result["status"], "NETWORK_REVIEW_REQUIRED")

    def test_no_shared_dependencies_still_requires_review(self):
        result = assess_dependency_safety("i-target", self.dependencies)

        self.assertEqual(
            result["status"],
            "NO_DIRECT_SHARED_DEPENDENCIES_FOUND"
        )
        self.assertFalse(result["execution_allowed"])


if __name__ == "__main__":
    unittest.main()
