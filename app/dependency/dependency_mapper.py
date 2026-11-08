
import boto3

from app.aws_session import get_aws_session


def map_instance_dependencies():
    """Map EC2 instances to their infrastructure dependencies."""

    session = get_aws_session("QuarantineDependencyMapping")
    ec2 = session.client("ec2")

    inventory = ec2.describe_instances()
    dependency_map = []

    for reservation in inventory["Reservations"]:
        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            dependencies = {
                "instance_id": instance_id,
                "network_interfaces": [],
                "security_groups": [],
                "volumes": [],
                "subnet_id": instance.get("SubnetId"),
                "vpc_id": instance.get("VpcId")
            }

            for interface in instance.get(
                "NetworkInterfaces", []
            ):
                dependencies["network_interfaces"].append(
                    interface["NetworkInterfaceId"]
                )

            for group in instance.get("SecurityGroups", []):
                dependencies["security_groups"].append(
                    group["GroupId"]
                )

            for mapping in instance.get(
                "BlockDeviceMappings", []
            ):
                ebs = mapping.get("Ebs", {})

                volume_id = ebs.get("VolumeId")

                if volume_id:
                    dependencies["volumes"].append(volume_id)

            dependency_map.append(dependencies)

    return dependency_map


if __name__ == "__main__":

    results = map_instance_dependencies()

    print("\nINFRASTRUCTURE DEPENDENCY MAPPING")
    print("================================")

    print(f"Instances mapped: {len(results)}")

    for item in results:
        print("\n------------------------------")

        for key, value in item.items():
            print(f"{key}: {value}")

    print("\nDEPENDENCY MAPPING COMPLETED")
    print("No AWS resources were modified.")
