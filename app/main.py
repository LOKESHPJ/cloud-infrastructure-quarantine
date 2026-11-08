
import json
from pathlib import Path

from app.discovery.ec2_discovery import discover_ec2_instances
from app.detection.security_group_detector import detect_public_exposure
from app.dependency.dependency_mapper import map_instance_dependencies
from app.risk.risk_scorer import assess_findings
from app.quarantine.quarantine_decision import evaluate_findings, consolidate_decisions
from app.quarantine.dependency_safety import assess_dependency_safety
from app.evidence.evidence_collector import collect_instance_evidence, calculate_file_hash
from app.audit.audit_logger import record_audit_event
from app.recovery.recovery_planner import generate_recovery_plan


def run_pipeline():

    print("\nCLOUD INFRASTRUCTURE QUARANTINE SYSTEM")
    print("======================================")
    print("Starting integrated security pipeline...\n")

    # Stage 1: AWS discovery
    instances = discover_ec2_instances()
    print(f"[1/7] EC2 discovery: {len(instances)} instances")

    # Stage 2: Threat detection
    findings = detect_public_exposure()
    print(f"[2/7] Threat detection: {len(findings)} findings")

    # Stage 3: Risk assessment
    assessed = assess_findings(findings)
    print(f"[3/7] Risk assessment: {len(assessed)} findings assessed")

    # Stage 4: Dependency mapping
    dependencies = map_instance_dependencies()
    dependency_lookup = {
        item["instance_id"]: item for item in dependencies
    }
    print(f"[4/7] Dependency mapping: {len(dependencies)} instances mapped")

    # Stage 5: Quarantine decisions
    raw_decisions = evaluate_findings(assessed)
    decisions = consolidate_decisions(raw_decisions)

    for decision in decisions:
        instance_id = decision["instance_id"]

        decision["dependencies"] = dependency_lookup.get(
            instance_id, {}
        )

        safety = assess_dependency_safety(
            instance_id,
            dependency_lookup
        )

        decision["dependency_safety"] = safety

        print(
            f"  {instance_id}: "
            f"{decision['decision']} "
            f"(score: {decision['risk_score']})"
        )

        print(
            f"    Dependency safety: {safety['status']}"
        )

        print(
            f"    Execution allowed: {safety['execution_allowed']}"
        )

    print(f"[5/7] Quarantine decisions: {len(decisions)} generated")

    # Stage 6: Evidence preservation
    evidence_files = []
    evidence_by_instance = {}

    for decision in decisions:
        if decision["decision"] != "QUARANTINE_RECOMMENDED":
            continue

        try:
            report = collect_instance_evidence(
                decision["instance_id"]
            )
            evidence_files.append(str(report))
            evidence_by_instance[decision['instance_id']] = str(report)
            print(f"  Evidence saved: {report}")

        except Exception as error:
            print(
                f"  Evidence collection failed for "
                f"{decision['instance_id']}: {error}"
            )

    print(f"[6/7] Evidence reports created: {len(evidence_files)}")

    # Stage 7: Recovery planning
    recovery_plans = []

    for report in evidence_files:
        with Path(report).open("r", encoding="utf-8") as file:
            evidence = json.load(file)

        plan = generate_recovery_plan(
            evidence["instance"]["instance_id"],
            evidence
        )

        recovery_plans.append(plan)

    print(f"[7/7] Recovery plans generated: {len(recovery_plans)}")

    # Record security assessments in the local audit log
    audit_records = 0
    audit_path = None

    for decision in decisions:
        report = evidence_by_instance.get(decision["instance_id"])
        evidence_hash = calculate_file_hash(report) if report else None

        audit_path = record_audit_event(
            decision,
            evidence_file=report,
            evidence_hash=evidence_hash
        )
        audit_records += 1

    print(f"Audit records created: {audit_records}")
    if audit_path:
        print(f"Audit log: {audit_path}")


    print("\nPIPELINE SUMMARY")
    print("================")
    print("Discovered instances:", len(instances))
    print("Threat findings:", len(findings))
    print("Risk assessments:", len(assessed))
    print("Dependencies mapped:", len(dependencies))
    print("Quarantine recommendations:", sum(
        1 for item in decisions
        if item["decision"] == "QUARANTINE_RECOMMENDED"
    ))
    print("Evidence reports:", len(evidence_files))
    print("Recovery plans:", len(recovery_plans))

    print("\nDRY RUN ONLY")
    print("No AWS resources were modified.")
    print("Integrated pipeline completed.")


if __name__ == "__main__":
    try:
        run_pipeline()
    except Exception as error:
        print("\nPIPELINE FAILED:", error)
