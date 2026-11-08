from botocore.exceptions import ClientError

from app.aws_session import get_aws_session


def discover_ec2_instances():
    """Discover EC2 instances using read-only AWS permissions."""

    session = get_aws_session("QuarantineDiscovery")
    ec2 = session.client("ec2")

    instances = []

    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:

                instances.append({
                    "instance_id": instance["InstanceId"],
                    "state": instance["State"]["Name"],
                    "instance_type": instance["InstanceType"],
                    "vpc_id": instance.get("VpcId"),
                    "subnet_id": instance.get("SubnetId"),
                    "private_ip": instance.get("PrivateIpAddress"),
                    "security_groups": [
                        sg["GroupId"]
                        for sg in instance.get("SecurityGroups", [])
                    ]
                })

    return instances


if __name__ == "__main__":
    try:
        results = discover_ec2_instances()

        print("\nCLOUD INFRASTRUCTURE QUARANTINE SYSTEM")
        print("======================================")
        print(f"Discovered instances: {len(results)}")

        for instance in results:
            print("\n------------------------------")
            for key, value in instance.items():
                print(f"{key}: {value}")

        print("\nDISCOVERY COMPLETED SUCCESSFULLY")

    except ClientError as error:
        print(f"AWS ERROR: {error}")
