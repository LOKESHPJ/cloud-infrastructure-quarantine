from app.config import PROTECTED_INSTANCES


RESOURCE_FIELDS = (
    "network_interfaces",
    "security_groups",
    "volumes"
)

NETWORK_FIELDS = (
    "subnet_id",
    "vpc_id"
)


def assess_dependency_safety(instance_id, dependency_lookup):
    """Review shared infrastructure dependencies before quarantine."""

    result = {
        "instance_id": instance_id,
        "status": "REVIEW_REQUIRED",
        "shared_resources": {},
        "shared_network_boundaries": {},
        "execution_allowed": False,
        "reason": ""
    }

    # Never allow the project-hosting instance to be quarantined.
    if instance_id in PROTECTED_INSTANCES:
        result["status"] = "BLOCKED_PROTECTED_INSTANCE"
        result["reason"] = "Protected project-hosting instance"
        return result

    target = dependency_lookup.get(instance_id)

    if not target:
        result["status"] = "BLOCKED_MISSING_DEPENDENCY_DATA"
        result["reason"] = "Target dependency information is missing"
        return result

    # Check for missing dependency fields.
    missing_fields = [
        field for field in RESOURCE_FIELDS + NETWORK_FIELDS
        if field not in target
    ]

    if missing_fields:
        result["status"] = "BLOCKED_INCOMPLETE_DEPENDENCY_DATA"
        result["reason"] = f"Missing fields: {missing_fields}"
        return result

    # Compare target resources against other EC2 instances.
    for other_id, other in dependency_lookup.items():

        if other_id == instance_id:
            continue

        for field in RESOURCE_FIELDS:
            target_resources = set(target.get(field) or [])
            other_resources = set(other.get(field) or [])

            shared = target_resources.intersection(other_resources)

            if shared:
                result["shared_resources"].setdefault(
                    field, {}
                )[other_id] = sorted(shared)

    # Identify shared subnet and VPC boundaries.
    for field in NETWORK_FIELDS:
        target_value = target.get(field)

        if not target_value:
            continue

        shared_instances = [
            other_id
            for other_id, other in dependency_lookup.items()
            if other_id != instance_id
            and other.get(field) == target_value
        ]

        if shared_instances:
            result["shared_network_boundaries"][field] = {
                "value": target_value,
                "other_instances": shared_instances
            }

    if result["shared_resources"]:
        result["status"] = "MANUAL_REVIEW_REQUIRED"
        result["reason"] = (
            "Potentially shared ENI, security group, or volume detected"
        )

    elif result["shared_network_boundaries"]:
        result["status"] = "NETWORK_REVIEW_REQUIRED"
        result["reason"] = (
            "Shared subnet or VPC detected; review network impact"
        )

    else:
        result["status"] = "NO_DIRECT_SHARED_DEPENDENCIES_FOUND"
        result["reason"] = (
            "No shared direct resources detected; further review is required"
        )

    return result
