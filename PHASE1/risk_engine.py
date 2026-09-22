
# ============================================================
# SEVERITY WEIGHTS
# ============================================================

SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30
}


# ============================================================
# CONFIDENCE MULTIPLIERS
# ============================================================

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.0,
    "MEDIUM": 0.75,
    "LOW": 0.5
}


# ============================================================
# RISK LEVEL THRESHOLDS
# ============================================================

def determine_risk_level(score):
    """
    Convert a numerical risk score into a risk level.

    Score ranges:
        0-24   -> LOW
        25-49  -> MEDIUM
        50-74  -> HIGH
        75-100 -> CRITICAL
    """

    if score >= 75:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


# ============================================================
# FINDING IDENTITY
# ============================================================

def finding_identity(finding):
    """
    Create an identity for a finding.

    The same security weakness observed on multiple pages
    should not automatically be counted as multiple
    independent vulnerabilities.

    Example:

        CSP Missing on page A
        CSP Missing on page B
        CSP Missing on page C

    becomes one logical finding:
        CSP Missing
    """

    name = str(
        finding.get("name", "Unknown Finding")
    ).strip().lower()

    category = str(
        finding.get("category", "Unknown")
    ).strip().lower()

    return category, name


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_findings(findings):
    """
    Group logically identical findings.

    Repeated observations of the same issue across
    multiple pages are represented as one finding.

    The strongest severity and confidence are preserved.

    Evidence from repeated observations is retained
    where possible.
    """

    grouped = {}

    for finding in findings:

        identity = finding_identity(finding)

        if identity not in grouped:

            grouped[identity] = dict(finding)

            # Track affected pages
            grouped[identity]["affected_pages"] = []

            if finding.get("page"):
                grouped[identity]["affected_pages"].append(
                    finding["page"]
                )

            continue

        existing = grouped[identity]

        # ----------------------------------------------------
        # Preserve strongest severity
        # ----------------------------------------------------

        severity_order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3
        }

        existing_severity = str(
            existing.get("severity", "INFO")
        ).upper()

        new_severity = str(
            finding.get("severity", "INFO")
        ).upper()

        if severity_order.get(
            new_severity, 0
        ) > severity_order.get(
            existing_severity, 0
        ):

            existing["severity"] = new_severity

        # ----------------------------------------------------
        # Preserve strongest confidence
        # ----------------------------------------------------

        confidence_order = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2
        }

        existing_confidence = str(
            existing.get("confidence", "LOW")
        ).upper()

        new_confidence = str(
            finding.get("confidence", "LOW")
        ).upper()

        if confidence_order.get(
            new_confidence, 0
        ) > confidence_order.get(
            existing_confidence, 0
        ):

            existing["confidence"] = new_confidence

        # ----------------------------------------------------
        # Track affected pages
        # ----------------------------------------------------

        page = finding.get("page")

        if page and page not in existing["affected_pages"]:

            existing["affected_pages"].append(page)

    return list(grouped.values())


# ============================================================
# CALCULATE FINDING CONTRIBUTION
# ============================================================

def calculate_finding_score(finding):
    """
    Calculate how much a finding contributes to the
    overall risk score.

    Formula:

        Base Severity Weight
        ×
        Confidence Multiplier

    INFO findings contribute zero risk.

    The result is rounded to avoid unnecessary decimals.
    """

    severity = str(
        finding.get("severity", "INFO")
    ).upper()

    confidence = str(
        finding.get("confidence", "LOW")
    ).upper()

    base_score = SEVERITY_WEIGHTS.get(
        severity,
        0
    )

    confidence_multiplier = CONFIDENCE_MULTIPLIERS.get(
        confidence,
        0.5
    )

    score = base_score * confidence_multiplier

    return round(score, 2)


# ============================================================
# MAIN RISK CALCULATION
# ============================================================

def calculate_risk(findings):
    """
    Calculate the final WebSentinel risk assessment.

    Input:
        findings
        List of findings produced by security_analyzer.py

    Output:
        Dictionary containing:

            score
            level
            high
            medium
            low
            informational
            finding_count
            evaluated_findings
    """

    if not findings:

        return {
            "score": 0,
            "level": "LOW",
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "finding_count": 0,
            "evaluated_findings": []
        }

    # --------------------------------------------------------
    # STEP 1
    # Remove duplicate logical findings
    # --------------------------------------------------------

    unique_findings = deduplicate_findings(
        findings
    )

    # --------------------------------------------------------
    # STEP 2
    # Calculate severity counts
    # --------------------------------------------------------

    high_count = 0
    medium_count = 0
    low_count = 0
    informational_count = 0

    total_score = 0

    evaluated_findings = []

    for finding in unique_findings:

        severity = str(
            finding.get("severity", "INFO")
        ).upper()

        # -----------------------------------------------
        # Count severity
        # -----------------------------------------------

        if severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        elif severity == "LOW":
            low_count += 1

        else:
            informational_count += 1

        # -----------------------------------------------
        # Calculate contribution
        # -----------------------------------------------

        contribution = calculate_finding_score(
            finding
        )

        total_score += contribution

        evaluated_finding = dict(finding)

        evaluated_finding[
            "risk_contribution"
        ] = contribution

        evaluated_findings.append(
            evaluated_finding
        )

    # --------------------------------------------------------
    # STEP 3
    # Normalize final score
    # --------------------------------------------------------

    final_score = min(
        100,
        round(total_score)
    )

    # --------------------------------------------------------
    # STEP 4
    # Determine overall risk level
    # --------------------------------------------------------

    risk_level = determine_risk_level(
        final_score
    )

    return {
        "score": final_score,
        "level": risk_level,

        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "informational": informational_count,

        "finding_count": len(unique_findings),

        "evaluated_findings": evaluated_findings
    }


# ============================================================
# COMPATIBILITY FUNCTION
# ============================================================

def classify_risk(observations):
    """
    Compatibility wrapper for the earlier WebSentinel
    Phase 1 architecture.

    If the input contains Security Analyzer findings,
    use calculate_risk().

    This keeps older main.py code from breaking
    immediately during the transition.
    """

    return calculate_risk(
        observations
    )


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    test_findings = [

        {
            "name": "Content-Security-Policy Missing",
            "category": "Security Headers",
            "severity": "LOW",
            "confidence": "HIGH",
            "page": "https://example.com"
        },

        {
            "name": "Content-Security-Policy Missing",
            "category": "Security Headers",
            "severity": "LOW",
            "confidence": "HIGH",
            "page": "https://example.com/about"
        },

        {
            "name": "Wildcard CORS Policy",
            "category": "CORS",
            "severity": "INFO",
            "confidence": "HIGH",
            "page": "https://example.com"
        }
    ]

    result = calculate_risk(
        test_findings
    )

    print("=" * 60)
    print("WEBSENTINEL RISK ENGINE TEST")
    print("=" * 60)

    print(
        f"Risk Score    : "
        f"{result['score']}/100"
    )

    print(
        f"Risk Level    : "
        f"{result['level']}"
    )

    print(
        f"High          : "
        f"{result['high']}"
    )

    print(
        f"Medium        : "
        f"{result['medium']}"
    )

    print(
        f"Low           : "
        f"{result['low']}"
    )

    print(
        f"Informational : "
        f"{result['informational']}"
    )

    print(
        f"Unique Findings : "
        f"{result['finding_count']}"
    )

    print("=" * 60)