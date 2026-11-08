# Cloud Infrastructure Quarantine System

A Python-based AWS security analysis tool that discovers EC2 infrastructure, detects public network exposure, assesses risk, maps dependencies, preserves evidence, and generates quarantine recommendations.

## Features

- AWS EC2 instance discovery
- Public IPv4 and IPv6 ingress detection
- Security risk scoring
- Infrastructure dependency mapping
- Protected-instance safeguards
- Quarantine decision engine
- Evidence collection with SHA-256 integrity checks
- Recovery planning recommendations
- JSONL audit logging
- Docker support
- Unit tests

## Architecture

1. Discover EC2 instances.
2. Detect public security group exposure.
3. Assess security risks.
4. Map infrastructure dependencies.
5. Evaluate quarantine recommendations and dependency safety.
6. Preserve evidence.
7. Generate recovery plans and audit records.

## Technology Stack

- Python
- AWS EC2, IAM, STS and CloudTrail
- Boto3
- Docker
- python-dotenv
- unittest

## Requirements

- Python 3.9+
- AWS account and configured credentials or EC2 instance profile
- Required read-only IAM permissions

## Setup

Clone the repository and enter its directory.

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

Create your environment file:

    cp .env.example .env

Configure these variables in `.env`:

| Variable | Description |
|---|---|
| AWS_REGION | AWS region to inspect |
| QUARANTINE_ROLE_ARN | Dedicated inspection role ARN |
| PROTECTED_INSTANCE_IDS | Comma-separated protected EC2 instance IDs |

Never commit `.env`, credentials, or real infrastructure identifiers.

## AWS IAM Architecture

The application uses an EC2 instance profile to obtain temporary credentials and assumes a dedicated IAM role for inspection.

Configure the required trust relationship and least-privilege read-only permissions in your own AWS account.

## Run Locally

    python -m app.main

## Run Tests

    python -m unittest discover -s tests -v

## Docker

Build the image:

    docker build -t cloud-infrastructure-quarantine .

Run with environment configuration and persistent reports:

    mkdir -p reports/evidence reports/audit

    docker run --rm \
      --env-file .env \
      -v "$(pwd)/reports:/app/reports" \
      cloud-infrastructure-quarantine

## Safety and Execution Boundaries

**The current implementation operates exclusively in DRY_RUN mode.**

- No AWS resources are modified.
- Quarantine decisions are recommendations only.
- Execution remains disabled (`execution_allowed` is false).
- Protected instances are excluded from quarantine recommendations.
- Public ingress indicates exposure, not confirmed compromise.
- Shared infrastructure dependencies may require manual review.
- SHA-256 checks provide integrity verification, not tamper-proof storage.
- Audit records are stored locally and are not independently tamper-proof.
- Recovery plans are recommendations; automated restoration is not implemented.

Any future execution capability must require explicit human approval, target-scoped permissions, dependency validation, evidence preservation, and a tested rollback process.

## Project Status

Discovery, threat detection, risk assessment, dependency mapping, evidence collection, recovery planning, audit logging, and the integrated dry-run pipeline are implemented.

Automated quarantine and automated recovery are intentionally not implemented.
