import json
from datetime import datetime, timezone
from pathlib import Path


AUDIT_DIR = Path("reports/audit")
AUDIT_FILE = AUDIT_DIR / "audit_log.jsonl"


def record_audit_event(
    decision,
    evidence_file=None,
    evidence_hash=None
):
    """Append a security assessment event to the local audit log."""

    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    safety = decision.get("dependency_safety", {})

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "instance_id": decision["instance_id"],
        "risk_score": decision["risk_score"],
        "risk_decision": decision["decision"],
        "execution_mode": "DRY_RUN",
        "dependency_safety": safety.get("status", "UNKNOWN"),
        "execution_allowed": safety.get("execution_allowed", False),
        "evidence_file": str(evidence_file) if evidence_file else None,
        "evidence_sha256": evidence_hash,
        "aws_resources_modified": False
    }

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return AUDIT_FILE
