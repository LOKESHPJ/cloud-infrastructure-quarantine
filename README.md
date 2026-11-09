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

## Container Security Hardening

The Docker image includes the following security measures:

- Uses the official Python 3.12 slim base image.
- Updates available Debian packages during the image build.
- Removes APT package lists after installation.
- Installs Python dependencies without retaining pip cache.
- Runs the application as a dedicated non-root user (`appuser`).
- Creates application report directories with appropriate ownership.

### Docker Build

Build the hardened v4 image:

    docker build --pull --no-cache -t cloud-infrastructure-quarantine:v4 .

Tag the hardened image as latest:

    docker tag cloud-infrastructure-quarantine:v4 cloud-infrastructure-quarantine:latest

### Container Security Verification

Runtime verification confirmed:

- Configured user: `appuser`
- Runtime UID: `1000`
- Runtime GID: `1000`
- Working directory: `/app`
- Application completed all seven pipeline stages successfully.

### Vulnerability Scanning

The image was scanned using Trivy with HIGH and CRITICAL severity filters.

Full scan:

    trivy image --scanners vuln --severity HIGH,CRITICAL cloud-infrastructure-quarantine:v4

Scan result snapshot (November 9, 2026):

- Debian OS packages: 47 HIGH, 0 CRITICAL findings.
- Python dependencies: 0 HIGH or CRITICAL findings.

Scan excluding vulnerabilities without available fixes:

    trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed cloud-infrastructure-quarantine:v4

Result: 0 HIGH or CRITICAL findings with available fixes under the scan criteria.

**Important:** The image is not vulnerability-free. The full scan still reports 47 HIGH findings, many without an available fix at the time of scanning. The filtered scan does not remediate or eliminate those findings.

### Unit Test Results

Command:

    python -m unittest discover -s tests -v

Result:

- 13 tests passed.
- 0 test failures.
- Dependency safety and protected-instance safeguards verified.
- Quarantine execution remains disabled.
