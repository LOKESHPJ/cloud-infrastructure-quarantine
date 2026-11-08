
SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 40,
    "LOW": 15
}


def calculate_risk(finding):
    """Calculate a numerical risk score for a security finding."""

    severity = finding.get("severity", "LOW")
    score = SEVERITY_SCORES.get(severity, 15)

    if "0.0.0.0/0" in finding.get("public_cidrs", []):
        score = min(score + 10, 100)

    if finding.get("service") == "ALL_PROTOCOLS":
        score = 100

    return score



SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 40,
    "LOW": 15
}


def calculate_risk(finding):
    """Calculate a numerical risk score for a security finding."""

    severity = finding.get("severity", "LOW")
    score = SEVERITY_SCORES.get(severity, 15)

    if "0.0.0.0/0" in finding.get("public_cidrs", []):
        score = min(score + 10, 100)

    if finding.get("service") == "ALL_PROTOCOLS":
        score = 100

    return score


def classify_risk(score):
    """Convert numerical score into a risk category."""

    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def assess_findings(findings):
    """Evaluate and prioritize all security findings."""

    assessed_findings = []

    for finding in findings:
        score = calculate_risk(finding)

        assessed = finding.copy()
        assessed["risk_score"] = score
        assessed["risk_category"] = classify_risk(score)

        assessed_findings.append(assessed)

    return sorted(
        assessed_findings,
        key=lambda item: item["risk_score"],
        reverse=True
    )


if __name__ == "__main__":
    sample_findings = [
        {
            "instance_id": "i-example-001",
            "severity": "CRITICAL",
            "service": "ALL_PROTOCOLS",
            "public_cidrs": ["0.0.0.0/0"]
        },
        {
            "instance_id": "i-example-002",
            "severity": "HIGH",
            "service": "ADMIN_ACCESS",
            "public_cidrs": ["0.0.0.0/0"]
        }
    ]

    results = assess_findings(sample_findings)

    print("\nQUARANTINE RISK ASSESSMENT")
    print("=========================")

    for finding in results:
        print("\n------------------------------")
        print("Instance:", finding["instance_id"])
        print("Risk Score:", finding["risk_score"])
        print("Risk Category:", finding["risk_category"])

    print("\nRISK ASSESSMENT COMPLETED")
