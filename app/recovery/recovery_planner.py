
from datetime import datetime, timezone

from app.config import PROTECTED_INSTANCES


def generate_recovery_plan(instance_id, evidence):
    """Generate a recovery plan using preserved evidence."""

    if instance_id in PROTECTED_INSTANCES:
        return {
            "instance_id": instance_id,
            "status": "BLOCKED",
            "reason": "Protected project-hosting instance"
        }

    instance_data = evidence.get("instance", {})

    if instance_data.get("instance_id") != instance_id:
        return {
            "instance_id": instance_id,
            "status": "BLOCKED",
            "reason": "Evidence does not match the requested instance"
        }

    plan = {
        "instance_id": instance_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "DRY_RUN",
        "steps": [
            "Review the original security findings",
            "Verify preserved EC2 configuration",
            "Inspect security group ingress rules",
            "Confirm required network dependencies",
            "Obtain security approval before restoring access",
            "Restore only approved security group rules",
            "Verify instance connectivity and application health",
            "Document the recovery operation"
        ],
        "evidence_available": True,
        "execution_status": "NOT_EXECUTED"
    }

    return plan


if __name__ == "__main__":

    import json
    from pathlib import Path

    evidence_file = Path(
        "reports/evidence/demo-instance_evidence.json"
    )

    if not evidence_file.exists():
        print("Evidence file not found:", evidence_file)

    else:
        with evidence_file.open("r", encoding="utf-8") as file:
            evidence = json.load(file)

        instance_id = evidence["instance"]["instance_id"]

        recovery_plan = generate_recovery_plan(
            instance_id,
            evidence
        )

        print("\nINFRASTRUCTURE RECOVERY PLAN")
        print("============================")

        for key, value in recovery_plan.items():
            if key == "steps":
                print("\nRecovery Steps:")
                for number, step in enumerate(value, start=1):
                    print(f"{number}. {step}")
            else:
                print(f"{key}: {value}")

        print("\nRECOVERY PLAN GENERATED")
        print("No AWS resources were modified.")
