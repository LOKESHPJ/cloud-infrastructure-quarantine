
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from app.aws_session import get_aws_session


REPORT_DIR = Path("reports/evidence")


def collect_instance_evidence(instance_id):
    """Collect read-only evidence for one EC2 instance."""

    session = get_aws_session("QuarantineEvidenceCollection")
    ec2 = session.client("ec2")
    cloudtrail = session.client("cloudtrail")

    instance_response = ec2.describe_instances(
        InstanceIds=[instance_id]
    )

    instances = [
        instance
        for reservation in instance_response["Reservations"]
        for instance in reservation["Instances"]
    ]

    if not instances:
        raise ValueError(f"Instance not found: {instance_id}")

    instance = instances[0]

    security_group_ids = [
        group["GroupId"]
        for group in instance.get("SecurityGroups", [])
    ]

    security_groups = []

    if security_group_ids:
        response = ec2.describe_security_groups(
            GroupIds=security_group_ids
        )
        security_groups = response["SecurityGroups"]

    network_interfaces = instance.get("NetworkInterfaces", [])

    cloudtrail_events = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "ResourceName",
                "AttributeValue": instance_id
            }
        ],
        MaxResults=20
    )

    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "instance": {
            "instance_id": instance["InstanceId"],
            "state": instance["State"]["Name"],
            "instance_type": instance["InstanceType"],
            "vpc_id": instance.get("VpcId"),
            "subnet_id": instance.get("SubnetId"),
            "private_ip": instance.get("PrivateIpAddress"),
            "security_groups": security_group_ids,
            "network_interfaces": [
                interface["NetworkInterfaceId"]
                for interface in network_interfaces
            ],
            "volumes": [
                mapping["Ebs"]["VolumeId"]
                for mapping in instance.get("BlockDeviceMappings", [])
                if mapping.get("Ebs", {}).get("VolumeId")
            ]
        },
        "security_group_details": security_groups,
        "cloudtrail_events": cloudtrail_events.get("Events", [])
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    filename = REPORT_DIR / f"{instance_id}_evidence.json"

    with filename.open("w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=4, default=str)

    hash_file = save_evidence_hash(filename)

    print(f"  Evidence SHA-256 saved: {hash_file}")

    return filename


def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of an evidence file."""

    sha256 = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def save_evidence_hash(file_path):
    """Save the SHA-256 fingerprint beside the evidence report."""

    report_path = Path(file_path)
    hash_value = calculate_file_hash(report_path)

    hash_path = report_path.with_suffix(
        report_path.suffix + ".sha256"
    )

    with hash_path.open("w", encoding="utf-8") as file:
        file.write(f"{hash_value}  {report_path.name}\n")

    return hash_path


def verify_evidence_integrity(file_path):
    """Verify evidence against its previously saved SHA-256 hash."""

    report_path = Path(file_path)

    hash_path = report_path.with_suffix(
        report_path.suffix + ".sha256"
    )

    if not hash_path.exists():
        return {
            "verified": False,
            "status": "HASH_FILE_MISSING"
        }

    with hash_path.open("r", encoding="utf-8") as file:
        saved_hash = file.read().split()[0]

    current_hash = calculate_file_hash(report_path)

    if saved_hash == current_hash:
        return {
            "verified": True,
            "status": "INTEGRITY_VERIFIED"
        }

    return {
        "verified": False,
        "status": "INTEGRITY_MISMATCH"
    }

if __name__ == "__main__":
    target_instance = "i-demo-target"

    try:
        report = collect_instance_evidence(target_instance)

        print("\nEVIDENCE COLLECTION COMPLETED")
        print("=============================")
        print("Instance:", target_instance)
        print("Evidence report:", report)
        print("AWS resources modified: None")

    except Exception as error:
        print("EVIDENCE COLLECTION FAILED:", error)
