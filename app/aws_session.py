import os
import boto3
from dotenv import load_dotenv

load_dotenv()


def get_aws_session(session_name):
    """Assume the dedicated quarantine role using the EC2 instance profile."""

    region = os.getenv("AWS_REGION")
    role_arn = os.getenv("QUARANTINE_ROLE_ARN")

    if not region or not role_arn:
        raise RuntimeError(
            "AWS_REGION and QUARANTINE_ROLE_ARN must be configured."
        )

    sts = boto3.client("sts", region_name=region)

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region
    )
