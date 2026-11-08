
from app.aws_session import get_aws_session

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP"
}



def detect_public_exposure():
    session = get_aws_session("QuarantineThreatDetection")
    ec2 = session.client("ec2")

    inventory = ec2.describe_instances()
    findings = []

    for reservation in inventory["Reservations"]:
        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            for group in instance.get("SecurityGroups", []):

                group_id = group["GroupId"]

                response = ec2.describe_security_groups(
                    GroupIds=[group_id]
                )

                for security_group in response["SecurityGroups"]:

                    for rule in security_group.get(
                        "IpPermissions", []
                    ):

                        exposed_cidrs = []

                        for item in rule.get("IpRanges", []):
                            if item.get("CidrIp") in PUBLIC_CIDRS:
                                exposed_cidrs.append(item["CidrIp"])

                        for item in rule.get("Ipv6Ranges", []):
                            if item.get("CidrIpv6") in PUBLIC_CIDRS:
                                exposed_cidrs.append(item["CidrIpv6"])

                        if not exposed_cidrs:
                            continue

                        protocol = rule.get("IpProtocol")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        if protocol == "-1":
                            severity = "CRITICAL"
                            service = "ALL_PROTOCOLS"

                        elif (
                            from_port is not None
                            and to_port is not None
                            and any(
                                from_port <= port <= to_port
                                for port in ADMIN_PORTS
                            )
                        ):
                            severity = "HIGH"
                            service = "ADMIN_ACCESS"

                        else:
                            severity = "MEDIUM"
                            service = "PUBLIC_INGRESS"

                        findings.append({
                            "instance_id": instance_id,
                            "security_group_id": group_id,
                            "severity": severity,
                            "service": service,
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "public_cidrs": exposed_cidrs
                        })

    return findings


if __name__ == "__main__":
    findings = detect_public_exposure()

    print("\nQUARANTINE THREAT DETECTION")
    print("===========================")
    print(f"Findings detected: {len(findings)}")

    for finding in findings:
        print("\n------------------------------")
        for key, value in finding.items():
            print(f"{key}: {value}")

    print("\nTHREAT SCAN COMPLETED")
    print("No AWS resources were modified.")
