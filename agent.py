def calculate_severity(threat_type, evidence):
    """
    Determines severity based on attack type and evidence.
    """
    if threat_type in ["Brute Force Attack", "Credential Stuffing"]:
        max_attempts = max(evidence.values())
        if max_attempts >= 10:
            return "CRITICAL"
        elif max_attempts >= 5:
            return "HIGH"
        else:
            return "MEDIUM"

    if threat_type in ["Privileged Account Targeting"]:
        return "CRITICAL"

    if threat_type in ["IP Scanning / Reconnaissance"]:
        return "MEDIUM"

    if threat_type in ["Anomalous Login Behavior"]:
        return "HIGH"

    return "LOW"


def enrich_with_ai(threat_report):
    """
    Acts as the AI SOC Assistant.
    Adds severity and final recommendations.
    """
    threat_type = threat_report["threat"]
    evidence = threat_report.get("evidence", {})

    severity = calculate_severity(threat_type, evidence)

    threat_report["severity"] = severity
    threat_report["ai_summary"] = (
        f"The activity matches patterns of {threat_type.lower()} "
        f"and exceeds normal authentication behavior baselines."
    )

    return threat_report
