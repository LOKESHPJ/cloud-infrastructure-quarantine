
from app.config import PROTECTED_INSTANCES

QUARANTINE_THRESHOLD = 70


def evaluate_quarantine(finding):
    """Decide whether an EC2 instance qualifies for quarantine."""

    instance_id = finding.get("instance_id")
    risk_score = finding.get("risk_score", 0)

    decision = {
        "instance_id": instance_id,
        "risk_score": risk_score,
        "decision": "NO_ACTION",
        "mode": "DRY_RUN",
        "reason": ""
    }

    # Never quarantine the instance hosting this project.
    if instance_id in PROTECTED_INSTANCES:
        decision["reason"] = "Protected project-hosting instance"
        return decision

    # Require sufficient risk before recommending isolation.
    if risk_score >= QUARANTINE_THRESHOLD:
        decision["decision"] = "QUARANTINE_RECOMMENDED"
        decision["reason"] = "Risk score exceeds quarantine threshold"

    else:
        decision["reason"] = "Risk score below quarantine threshold"

    return decision


def evaluate_findings(findings):
    """Evaluate all findings and generate quarantine recommendations."""

    decisions = []

    for finding in findings:
        decisions.append(evaluate_quarantine(finding))

    return decisions

def consolidate_decisions(decisions):
    """Keep one quarantine decision per EC2 instance."""

    consolidated = {}

    for decision in decisions:
        instance_id = decision["instance_id"]
        existing = consolidated.get(instance_id)

        if existing is None:
            consolidated[instance_id] = decision

        elif decision["risk_score"] > existing["risk_score"]:
            consolidated[instance_id] = decision

    return list(consolidated.values())

if __name__ == "__main__":

    sample_findings = [
        {
            "instance_id": "i-demo-target",
            "risk_score": 100
        },
        {
            "instance_id": "i-demo-protected",
            "risk_score": 100
        },
        {
            "instance_id": "i-example-003",
            "risk_score": 40
        }
    ]

    results = evaluate_findings(sample_findings)

    print("\nQUARANTINE DECISION ENGINE")
    print("==========================")

    for result in results:
        print("\n------------------------------")

        for key, value in result.items():
            print(f"{key}: {value}")

    print("\nDECISION ENGINE COMPLETED")
    print("DRY RUN ONLY - NO AWS RESOURCES MODIFIED")
