# ============================================================
# WEBSENTINEL - RISK ENGINE
# ============================================================
#
# Responsibilities:
#
#   1. Preserve the original Phase 1 risk calculation
#   2. Aggregate repeated security findings
#   3. Deduplicate page-level observations
#   4. Apply severity weighting
#   5. Apply confidence weighting
#   6. Produce final risk score
#
# ============================================================


# ============================================================
# SEVERITY WEIGHTS
# ============================================================

SEVERITY_WEIGHTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30,
    "CRITICAL": 40
}


# ============================================================
# CONFIDENCE MULTIPLIERS
# ============================================================

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.0,
    "MEDIUM": 0.75,
    "LOW": 0.50
}


# ============================================================
# BASIC PHASE 1 RISK
# ============================================================

def classify_risk(observations):
    """
    Original Phase 1 risk calculation.

    Retained for the initial website check.
    """

    risk_score = 0

    for observation in observations:

        risk_score += observation.get(
            "score",
            0
        )

    if risk_score >= 50:

        risk_level = "HIGH"

    elif risk_score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "score": risk_score,
        "level": risk_level
    }


# ============================================================
# FINDING KEY
# ============================================================

def get_finding_key(finding):
    """
    Generate a logical key.

    Example:

        Missing CSP on /
        Missing CSP on /about
        Missing CSP on /contact

    become one logical finding:

        Missing Content-Security-Policy
    """

    category = finding.get(
        "category",
        "Unknown Category"
    )

    name = finding.get(
        "name",
        "Unknown Finding"
    )

    return (
        category.strip().lower(),
        name.strip().lower()
    )


# ============================================================
# STRONGER SEVERITY
# ============================================================

def stronger_severity(
    current,
    new
):

    current_weight = SEVERITY_WEIGHTS.get(
        current.upper(),
        0
    )

    new_weight = SEVERITY_WEIGHTS.get(
        new.upper(),
        0
    )

    if new_weight > current_weight:

        return new.upper()

    return current.upper()


# ============================================================
# STRONGER CONFIDENCE
# ============================================================

def stronger_confidence(
    current,
    new
):

    current_weight = CONFIDENCE_MULTIPLIERS.get(
        current.upper(),
        0
    )

    new_weight = CONFIDENCE_MULTIPLIERS.get(
        new.upper(),
        0
    )

    if new_weight > current_weight:

        return new.upper()

    return current.upper()


# ============================================================
# AGGREGATE FINDINGS
# ============================================================

def aggregate_findings(findings):
    """
    Convert repeated page-level findings into
    unique logical findings.
    """

    aggregated = {}

    for finding in findings:

        key = get_finding_key(
            finding
        )

        if key not in aggregated:

            aggregated[key] = {
                "name": finding.get(
                    "name",
                    "Unknown Finding"
                ),

                "category": finding.get(
                    "category",
                    "Unknown Category"
                ),

                "severity": finding.get(
                    "severity",
                    "INFO"
                ).upper(),

                "confidence": finding.get(
                    "confidence",
                    "LOW"
                ).upper(),

                "description": finding.get(
                    "description",
                    ""
                ),

                "recommendation": finding.get(
                    "recommendation",
                    ""
                ),

                "affected_pages": [],

                "evidence": []
            }

        result = aggregated[key]

        result["severity"] = stronger_severity(
            result["severity"],
            finding.get(
                "severity",
                "INFO"
            )
        )

        result["confidence"] = stronger_confidence(
            result["confidence"],
            finding.get(
                "confidence",
                "LOW"
            )
        )

        page = finding.get(
            "page"
        )

        # Page-level findings normally carry a direct `page` field.
        # Some analyzer findings aggregate multiple pages into one finding
        # and store those URLs inside evidence["pages"]. Preserve those
        # affected pages during aggregation as well.
        if (
            page
            and page not in result[
                "affected_pages"
            ]
        ):

            result[
                "affected_pages"
            ].append(page)

        evidence = finding.get(
            "evidence"
        )

        if evidence is not None:

            if isinstance(evidence, dict):
                evidence_pages = evidence.get("pages", [])
                if isinstance(evidence_pages, list):
                    for evidence_page in evidence_pages:
                        if (
                            evidence_page
                            and evidence_page not in result["affected_pages"]
                        ):
                            result["affected_pages"].append(evidence_page)

            result[
                "evidence"
            ].append(
                {
                    "page": page,
                    "evidence": evidence
                }
            )

    return list(
        aggregated.values()
    )


# ============================================================
# FINAL SECURITY RISK
# ============================================================

def calculate_security_risk(findings):
    """
    Calculate the final risk from Security Analyzer findings.

    Repeated findings on multiple pages are counted as
    one logical security issue.
    """

    aggregated_findings = aggregate_findings(
        findings
    )

    score = 0

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    # --------------------------------------------------------
    # SCORE UNIQUE FINDINGS
    # --------------------------------------------------------

    for finding in aggregated_findings:

        severity = finding.get(
            "severity",
            "INFO"
        ).upper()

        confidence = finding.get(
            "confidence",
            "LOW"
        ).upper()

        base_weight = SEVERITY_WEIGHTS.get(
            severity,
            0
        )

        confidence_multiplier = (
            CONFIDENCE_MULTIPLIERS.get(
                confidence,
                0.5
            )
        )

        contribution = (
            base_weight
            * confidence_multiplier
        )

        score += contribution

        severity_counts[
            severity
        ] += 1

    # --------------------------------------------------------
    # CAP SCORE
    # --------------------------------------------------------

    score = min(
        round(score),
        100
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 75:

        level = "CRITICAL"

    elif score >= 50:

        level = "HIGH"

    elif score >= 25:

        level = "MEDIUM"

    else:

        level = "LOW"

    # --------------------------------------------------------
    # AFFECTED PAGES
    # --------------------------------------------------------

    affected_pages = set()

    for finding in aggregated_findings:

        for page in finding.get(
            "affected_pages",
            []
        ):

            affected_pages.add(
                page
            )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "score": score,
        "level": level,

        "critical": severity_counts[
            "CRITICAL"
        ],

        "high": severity_counts[
            "HIGH"
        ],

        "medium": severity_counts[
            "MEDIUM"
        ],

        "low": severity_counts[
            "LOW"
        ],

        "informational": severity_counts[
            "INFO"
        ],

        "finding_count": len(
            aggregated_findings
        ),

        "affected_pages": len(
            affected_pages
        ),

        "findings": aggregated_findings
    }


# ============================================================
# DISPLAY FINAL RISK
# ============================================================

def display_security_risk(risk):

    print(
        "\n"
        + "=" * 65
    )

    print(
        "RISK ENGINE"
    )

    print(
        "=" * 65
    )

    print(
        f"Risk Score           : "
        f"{risk['score']}/100"
    )

    print(
        f"Risk Level           : "
        f"{risk['level']}"
    )

    print(
        f"Unique Findings      : "
        f"{risk['finding_count']}"
    )

    print(
        f"Affected Pages       : "
        f"{risk['affected_pages']}"
    )

    print(
        "\nSEVERITY BREAKDOWN"
    )

    print(
        "-" * 65
    )

    print(
        f"Critical             : "
        f"{risk['critical']}"
    )

    print(
        f"High                 : "
        f"{risk['high']}"
    )

    print(
        f"Medium               : "
        f"{risk['medium']}"
    )

    print(
        f"Low                  : "
        f"{risk['low']}"
    )

    print(
        f"Informational        : "
        f"{risk['informational']}"
    )

    print(
        "\nUNIQUE SECURITY FINDINGS"
    )

    print(
        "-" * 65
    )

    if not risk["findings"]:

        print(
            "No security findings."
        )

    for finding in risk["findings"]:

        print(
            f"\n{finding['name']}"
        )

        print(
            f"  Category       : "
            f"{finding['category']}"
        )

        print(
            f"  Severity       : "
            f"{finding['severity']}"
        )

        print(
            f"  Confidence     : "
            f"{finding['confidence']}"
        )

        print(
            f"  Affected Pages : "
            f"{len(finding['affected_pages'])}"
        )

    print(
        "=" * 65
    )