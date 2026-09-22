
from datetime import datetime, timezone

AUTH_WORDS = ("session", "sess", "sid", "auth", "token", "jwt", "access", "refresh")


def make_finding(name, category, severity, score, confidence,
                 description, evidence, page=None, recommendation=""):
    return {
        "name": name, "category": category, "severity": severity,
        "score": score, "confidence": confidence,
        "description": description, "evidence": evidence,
        "page": page, "recommendation": recommendation
    }


def is_html(page):
    return "text/html" in (page.get("content_type") or "").lower()


def auth_cookie(name):
    name = (name or "").lower()
    return any(word in name for word in AUTH_WORDS)


def hsts_max_age(value):
    if not value:
        return None
    for part in value.split(";"):
        if part.strip().lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


def has_frame_ancestors(page):
    value = page.get("security_headers", {}).get(
        "content_security_policy", {}
    ).get("value")
    return bool(value) and "frame-ancestors" in value.lower()


def add_transport(result, findings):
    redirect = result.get("http_redirect")
    if redirect and redirect.get("tested") and redirect.get("redirects_to_https") is False:
        findings.append(make_finding(
            "HTTP Not Redirected to HTTPS", "Transport Security", "MEDIUM", 20, "HIGH",
            "The tested HTTP URL did not redirect to HTTPS.",
            {"status_code": redirect.get("status_code"),
             "location": redirect.get("location")},
            recommendation="Redirect HTTP requests to HTTPS."
        ))

    tls = result.get("tls") or {}
    if tls.get("tls_version") in ("TLSv1", "TLSv1.1"):
        findings.append(make_finding(
            "Obsolete TLS Version", "Transport Security", "HIGH", 30, "HIGH",
            f"The server negotiated {tls['tls_version']}.",
            {"tls_version": tls["tls_version"]},
            recommendation="Disable obsolete TLS versions."
        ))

    if tls.get("certificate_valid") is False:
        findings.append(make_finding(
            "TLS Certificate Validation Failure", "Transport Security",
            "HIGH", 30, "HIGH",
            "The passive TLS check could not validate the certificate.",
            {"error": tls.get("error")},
            recommendation="Install and configure a valid TLS certificate."
        ))

    days = tls.get("days_until_expiry")
    if isinstance(days, int) and days <= 30:
        if days < 0:
            severity, score, name = "HIGH", 30, "Expired TLS Certificate"
        elif days <= 7:
            severity, score, name = "MEDIUM", 15, "TLS Certificate Expiring Soon"
        else:
            severity, score, name = "LOW", 5, "TLS Certificate Nearing Expiry"

        findings.append(make_finding(
            name, "Transport Security", severity, score, "HIGH",
            f"The certificate has {days} days remaining.",
            {"expires": tls.get("certificate_expires"), "days": days},
            recommendation="Renew the certificate before expiry."
        ))


def add_hsts(result, findings):
    pages = {
        u: p for u, p in result.get("pages", {}).items()
        if is_html(p) and p.get("https", {}).get("used") is True
    }
    if not pages:
        return

    missing, disabled = [], []
    for url, page in pages.items():
        header = page.get("security_headers", {}).get(
            "strict_transport_security", {}
        )
        if not header.get("present"):
            missing.append(url)
        elif hsts_max_age(header.get("value")) == 0:
            disabled.append(url)

    if disabled:
        findings.append(make_finding(
            "HSTS Disabled", "Transport Security", "MEDIUM", 15, "HIGH",
            "HSTS is present with max-age=0.",
            {"pages": disabled[:20]},
            recommendation="Use a suitable positive HSTS max-age."
        ))

    if missing:
        findings.append(make_finding(
            "HSTS Missing", "Transport Security", "LOW", 5, "HIGH",
            "HSTS is absent on some analyzed HTTPS pages. This is a "
            "hardening gap, not proof of an exploitable vulnerability.",
            {"missing": len(missing), "analyzed": len(pages)},
            recommendation="Consider enabling HSTS after validating HTTPS."
        ))


def add_headers(result, findings):
    pages = {
        u: p for u, p in result.get("pages", {}).items() if is_html(p)
    }
    if not pages:
        return

    checks = {
        "content_security_policy": "Content-Security-Policy",
        "x_frame_options": "X-Frame-Options",
        "x_content_type_options": "X-Content-Type-Options",
        "referrer_policy": "Referrer-Policy",
        "permissions_policy": "Permissions-Policy"
    }

    for field, label in checks.items():
        missing = []
        for url, page in pages.items():
            present = page.get("security_headers", {}).get(field, {}).get("present")
            if not present:
                if field == "x_frame_options" and has_frame_ancestors(page):
                    continue
                missing.append(url)

        if missing:
            findings.append(make_finding(
                f"{label} Missing", "Security Headers", "LOW", 5, "HIGH",
                f"{label} is absent on {len(missing)} of {len(pages)} "
                "HTML pages. This is a defense-in-depth weakness, not "
                "proof of a vulnerability.",
                {"missing": len(missing), "analyzed": len(pages)},
                recommendation=f"Review whether {label} should be enabled."
            ))


def add_cookies(result, findings):
    for url, page in result.get("pages", {}).items():
        if not is_html(page):
            continue
        https = page.get("https", {}).get("used") is True

        for cookie in page.get("cookies", []):
            name = cookie.get("name") or "unnamed"
            is_auth = auth_cookie(name)

            if https and not cookie.get("secure"):
                findings.append(make_finding(
                    "Cookie Missing Secure Attribute", "Cookie Security",
                    "MEDIUM" if is_auth else "LOW",
                    15 if is_auth else 5, "HIGH",
                    f"Cookie '{name}' was set from HTTPS without Secure.",
                    {"cookie": name, "secure": cookie.get("secure")},
                    url, "Set Secure on cookies that should only use HTTPS."
                ))

            if is_auth and not cookie.get("httponly"):
                findings.append(make_finding(
                    "Authentication Cookie Missing HttpOnly", "Cookie Security",
                    "MEDIUM", 15, "MEDIUM",
                    f"Cookie '{name}' appears related to session/authentication "
                    "state and lacks HttpOnly.",
                    {"cookie": name, "httponly": cookie.get("httponly")},
                    url, "Use HttpOnly unless client-side access is required."
                ))

            if str(cookie.get("samesite") or "").lower() == "none" and not cookie.get("secure"):
                findings.append(make_finding(
                    "SameSite=None Without Secure", "Cookie Security",
                    "MEDIUM", 15, "HIGH",
                    f"Cookie '{name}' uses SameSite=None without Secure.",
                    {"cookie": name},
                    url, "Set Secure when using SameSite=None."
                ))


def add_forms(result, findings):
    for url, page in result.get("pages", {}).items():
        for form in page.get("forms", []):
            if form.get("password_fields", 0) > 0 and not form.get("uses_https"):
                findings.append(make_finding(
                    "Password Form Uses Non-HTTPS Action",
                    "Transport Security", "HIGH", 30, "HIGH",
                    "A password form submits to a non-HTTPS action.",
                    {"action": form.get("action"), "method": form.get("method")},
                    url, "Submit authentication credentials only over HTTPS."
                ))


def add_mixed_content(result, findings):
    for url, page in result.get("pages", {}).items():
        mixed = page.get("mixed_content", {})
        if mixed.get("detected"):
            findings.append(make_finding(
                "Mixed Content Reference", "Transport Security",
                "LOW", 5, "HIGH",
                "An HTTPS page references one or more HTTP resources.",
                {"resources": mixed.get("resources", [])[:20]},
                url, "Serve referenced resources over HTTPS."
            ))


def add_cors(result, findings):
    for url, page in result.get("pages", {}).items():
        cors = page.get("cors", {})
        if not cors.get("present"):
            continue

        origin = (cors.get("allow_origin") or "").strip()
        credentials = (cors.get("allow_credentials") or "").strip().lower()

        # '*' with credentials is rejected by browsers; do not report
        # it as a credentialed CORS vulnerability.
        if origin == "*" and credentials == "true":
            continue

        if origin == "*":
            findings.append(make_finding(
                "Wildcard CORS Policy", "CORS", "INFO", 0, "HIGH",
                "The response allows cross-origin access from any origin. "
                "This is only a concern when the resource is private.",
                {"allow_origin": origin}, url,
                "Restrict CORS to required origins for private resources."
            ))

        elif origin.lower() == "null":
            findings.append(make_finding(
                "CORS Allows Null Origin", "CORS", "LOW", 5, "HIGH",
                "The response explicitly allows the null origin.",
                {"allow_origin": origin}, url,
                "Allow only explicitly required origins."
            ))


def add_exposure(result, findings):
    for url, page in result.get("pages", {}).items():
        directory = page.get("directory_listing", {})
        if directory.get("detected"):
            findings.append(make_finding(
                "Directory Listing Detected", "Information Exposure",
                "MEDIUM", 15, "HIGH",
                "The page contains directory-listing indicators.",
                {"indicators": directory.get("indicators", [])},
                url, "Disable directory indexing unless explicitly required."
            ))

        errors = page.get("error_indicators", {})
        # The crawler's generic "warning:" pattern is intentionally ignored.
        indicators = [x for x in errors.get("indicators", []) if x != "php warning"]

        if indicators:
            findings.append(make_finding(
                "Verbose Error Information Detected",
                "Information Exposure", "MEDIUM", 15, "MEDIUM",
                "The response contains patterns associated with verbose errors.",
                {"indicators": indicators}, url,
                "Return generic errors to users and keep detailed traces in logs."
            ))


def add_information(result, findings):
    for url, page in result.get("pages", {}).items():
        server = page.get("server_information", {})
        if server.get("x_powered_by") or server.get("technology_headers"):
            findings.append(make_finding(
                "Technology Information Disclosure",
                "Information Disclosure", "INFO", 0, "HIGH",
                "Server/framework information is exposed in response headers.",
                {
                    "server": server.get("server"),
                    "x_powered_by": server.get("x_powered_by"),
                    "technology_headers": server.get("technology_headers", {})
                },
                url, "Minimize unnecessary technology disclosure where practical."
            ))

        params = page.get("sensitive_parameters", [])
        if params:
            findings.append(make_finding(
                "Sensitive-Looking URL Parameter",
                "Information Disclosure", "INFO", 0, "HIGH",
                "A discovered URL contains a parameter name that may carry "
                "sensitive data. The scanner does not assume it contains a secret.",
                {"parameters": params}, url,
                "Avoid placing secrets or session identifiers in URLs."
            ))


def analyze_crawler_result(result):
    """Main entry point for main.py."""

    if not isinstance(result, dict) or not result.get("pages"):
        return {
            "success": False,
            "error": "No valid crawler pages were available for analysis.",
            "findings": []
        }

    findings = []
    add_transport(result, findings)
    add_hsts(result, findings)
    add_headers(result, findings)
    add_cookies(result, findings)
    add_forms(result, findings)
    add_mixed_content(result, findings)
    add_cors(result, findings)
    add_exposure(result, findings)
    add_information(result, findings)

    score = min(100, sum(item["score"] for item in findings))

    if any(x["severity"] == "HIGH" for x in findings):
        level = "HIGH"
    elif any(x["severity"] == "MEDIUM" for x in findings):
        level = "MEDIUM"
    elif any(x["severity"] == "LOW" for x in findings):
        level = "LOW"
    else:
        level = "LOW"

    return {
        "success": True,
        "findings": findings,
        "summary": {
            "risk_score": score,
            "risk_level": level,
            "high": sum(x["severity"] == "HIGH" for x in findings),
            "medium": sum(x["severity"] == "MEDIUM" for x in findings),
            "low": sum(x["severity"] == "LOW" for x in findings),
            "informational": sum(x["severity"] == "INFO" for x in findings),
            "total_findings": len(findings)
        },
        "analyzed_at": datetime.now(timezone.utc).isoformat()
    }


def display_security_analysis(analysis):
    """Temporary console output for development/testing."""

    print("\n" + "=" * 70)
    print("                 SECURITY ANALYSIS")
    print("=" * 70)

    if not analysis.get("success"):
        print(f"[ERROR] {analysis.get('error')}")
        return

    summary = analysis["summary"]
    print(f"\nRisk Score    : {summary['risk_score']}/100")
    print(f"Risk Level    : {summary['risk_level']}")
    print(f"High          : {summary['high']}")
    print(f"Medium        : {summary['medium']}")
    print(f"Low           : {summary['low']}")
    print(f"Informational : {summary['informational']}")

    print("\nFINDINGS")
    print("-" * 70)

    for number, item in enumerate(analysis["findings"], 1):
        print(f"\n[{number}] {item['name']}")
        print(f"    Severity   : {item['severity']}")
        print(f"    Confidence : {item['confidence']}")
        print(f"    Score      : {item['score']}")
        print(f"    Category   : {item['category']}")
        print(f"    Description: {item['description']}")
        print(f"    Evidence   : {item['evidence']}")
        if item["page"]:
            print(f"    Page       : {item['page']}")
        print(f"    Recommendation: {item['recommendation']}")
