from datetime import datetime, timezone


# ============================================================
# FINDING CREATION
# ============================================================

def make_finding(
    name,
    category,
    severity,
    score,
    confidence,
    description,
    evidence,
    page,
    recommendation
):
    """
    Create a standardized security finding.

    The Security Analyzer interprets crawler evidence.
    It does not calculate the final website risk.
    """

    return {
        "name": name,
        "category": category,
        "severity": severity,
        "score": score,
        "confidence": confidence,
        "description": description,
        "evidence": evidence,
        "page": page,
        "recommendation": recommendation
    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_html(page):
    content_type = str(
        page.get("content_type", "")
    ).lower()

    return (
        "text/html" in content_type
        or content_type == ""
    )


def auth_cookie(cookie):
    """
    Identify cookies that appear to be authentication,
    session, or security-related cookies.
    """

    if isinstance(cookie, str):
        name = cookie.lower()
    else:
        name = str(
            cookie.get("name", "")
        ).lower()

    keywords = (
        "session",
        "sess",
        "auth",
        "token",
        "jwt",
        "login",
        "user",
        "sid"
    )

    return any(
        keyword in name
        for keyword in keywords
    )


def hsts_max_age(value):
    """
    Extract max-age from a Strict-Transport-Security
    header value.
    """

    if not value:
        return None

    value = str(value).lower()

    for part in value.split(";"):
        part = part.strip()

        if part.startswith("max-age="):
            try:
                return int(
                    part.split("=", 1)[1]
                )
            except ValueError:
                return None

    return None


def has_frame_ancestors(csp):
    """
    Check whether CSP contains frame-ancestors.
    """

    if not csp:
        return False

    return "frame-ancestors" in str(csp).lower()


# ============================================================
# TRANSPORT SECURITY
# ============================================================

def add_transport(findings, page):
    """
    Check whether an HTTP page is redirected to HTTPS.
    """

    scheme = str(
        page.get("scheme", "")
    ).lower()

    redirects = page.get(
        "redirects",
        []
    )

    final_url = str(
        page.get("final_url", "")
    ).lower()

    page_url = str(
        page.get("url", "")
    ).lower()

    if scheme != "http":
        return

    redirected_to_https = (
        "https://" in final_url
        or "https" in str(redirects).lower()
    )

    if not redirected_to_https:

        findings.append(
            make_finding(
                name="HTTP Without HTTPS Enforcement",
                category="Transport Security",
                severity="MEDIUM",
                score=20,
                confidence="HIGH",
                description=(
                    "The crawler observed an HTTP page that "
                    "was not redirected to HTTPS."
                ),
                evidence={
                    "url": page_url,
                    "final_url": final_url
                },
                page=page.get("url"),
                recommendation=(
                    "Redirect HTTP requests to HTTPS and "
                    "use HTTPS for all sensitive communication."
                )
            )
        )


# ============================================================
# TLS
# ============================================================

def add_tls(findings, crawl_result):
    """
    Analyze TLS information collected by the crawler.
    """

    tls = crawl_result.get(
        "tls",
        {}
    )

    if not tls:
        return

    version = str(
        tls.get("version", "")
    ).upper()

    if version in (
        "TLSV1",
        "TLSV1.0",
        "TLS 1.0",
        "TLSV1.1",
        "TLS 1.1"
    ):

        findings.append(
            make_finding(
                name="Outdated TLS Version",
                category="Transport Security",
                severity="HIGH",
                score=30,
                confidence="HIGH",
                description=(
                    "The target was observed using an outdated "
                    "TLS protocol version."
                ),
                evidence={
                    "tls_version": version
                },
                page=None,
                recommendation=(
                    "Disable outdated TLS versions and use "
                    "modern TLS configurations."
                )
            )
        )

    certificate_valid = tls.get(
        "certificate_valid"
    )

    if certificate_valid is False:

        findings.append(
            make_finding(
                name="Invalid TLS Certificate",
                category="Transport Security",
                severity="HIGH",
                score=30,
                confidence="HIGH",
                description=(
                    "The TLS certificate could not be "
                    "validated successfully."
                ),
                evidence={
                    "certificate_valid": certificate_valid
                },
                page=None,
                recommendation=(
                    "Install and maintain a valid certificate "
                    "for the website."
                )
            )
        )

    expired = tls.get("expired")
    if expired is True:

        findings.append(
            make_finding(
                name="Expired TLS Certificate",
                category="Transport Security",
                severity="HIGH",
                score=30,
                confidence="HIGH",
                description=(
                    "The TLS certificate has expired."
                ),
                evidence={
                    "expired": True
                },
                page=None,
                recommendation=(
                    "Renew the TLS certificate before expiration."
                )
            )
        )

    days_remaining = tls.get(
        "days_remaining"
    )

    if isinstance(days_remaining, (int, float)):

        if 0 <= days_remaining <= 7:

            findings.append(
                make_finding(
                    name="TLS Certificate Near Expiration",
                    category="Transport Security",
                    severity="MEDIUM",
                    score=15,
                    confidence="HIGH",
                    description=(
                        "The TLS certificate is close to "
                        "expiration."
                    ),
                    evidence={
                        "days_remaining": days_remaining
                    },
                    page=None,
                    recommendation=(
                        "Renew the TLS certificate before "
                        "it expires."
                    )
                )
            )

        elif days_remaining <= 30:

            findings.append(
                make_finding(
                    name="TLS Certificate Expiring Soon",
                    category="Transport Security",
                    severity="LOW",
                    score=5,
                    confidence="HIGH",
                    description=(
                        "The TLS certificate is approaching "
                        "its expiration date."
                    ),
                    evidence={
                        "days_remaining": days_remaining
                    },
                    page=None,
                    recommendation=(
                        "Plan certificate renewal before "
                        "the expiration date."
                    )
                )
            )


# ============================================================
# HSTS
# ============================================================

def add_hsts(findings, page):
    """
    Analyze Strict-Transport-Security.
    """

    if not is_html(page):
        return

    headers = page.get(
        "security_headers",
        {}
    )

    hsts = None

    for key, value in headers.items():

        if str(key).lower() == (
            "strict-transport-security"
        ):
            hsts = value
            break

    if hsts is not None:

        max_age = hsts_max_age(hsts)

        if max_age == 0:

            findings.append(
                make_finding(
                    name="HSTS Disabled",
                    category="Transport Security",
                    severity="MEDIUM",
                    score=15,
                    confidence="HIGH",
                    description=(
                        "The Strict-Transport-Security "
                        "header explicitly disables HSTS."
                    ),
                    evidence={
                        "strict_transport_security": hsts
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Configure HSTS with an appropriate "
                        "max-age value."
                    )
                )
            )

    else:

        if str(
            page.get("scheme", "")
        ).lower() == "https":

            findings.append(
                make_finding(
                    name="Missing HSTS",
                    category="Transport Security",
                    severity="LOW",
                    score=5,
                    confidence="HIGH",
                    description=(
                        "The HTTPS page does not include "
                        "a Strict-Transport-Security header."
                    ),
                    evidence={
                        "strict_transport_security": None
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Consider enabling HSTS to instruct "
                        "browsers to use HTTPS."
                    )
                )
            )


# ============================================================
# SECURITY HEADERS
# ============================================================

def add_headers(findings, page):
    """
    Analyze common security-related HTTP headers.
    """

    if not is_html(page):
        return

    headers = page.get(
        "security_headers",
        {}
    )

    normalized = {
        str(key).lower(): value
        for key, value in headers.items()
    }

    csp = normalized.get(
        "content-security-policy"
    )

    expected_headers = {
        "content-security-policy":
            "Content Security Policy",

        "x-content-type-options":
            "X-Content-Type-Options",

        "referrer-policy":
            "Referrer-Policy",

        "permissions-policy":
            "Permissions-Policy"
    }

    for header_name, display_name in expected_headers.items():

        if not normalized.get(header_name):

            findings.append(
                make_finding(
                    name=f"Missing {display_name}",
                    category="Security Headers",
                    severity="LOW",
                    score=5,
                    confidence="HIGH",
                    description=(
                        f"The {display_name} header was "
                        "not observed on the page."
                    ),
                    evidence={
                        "header": display_name
                    },
                    page=page.get("url"),
                    recommendation=(
                        f"Configure an appropriate "
                        f"{display_name} policy."
                    )
                )
            )

    # X-Frame-Options is not necessarily required if
    # CSP frame-ancestors is already present.

    x_frame = normalized.get(
        "x-frame-options"
    )

    if not x_frame and not has_frame_ancestors(csp):

        findings.append(
            make_finding(
                name="Missing Clickjacking Protection",
                category="Security Headers",
                severity="LOW",
                score=5,
                confidence="HIGH",
                description=(
                    "Neither X-Frame-Options nor a CSP "
                    "frame-ancestors directive was observed."
                ),
                evidence={
                    "x-frame-options": x_frame,
                    "frame-ancestors": False
                },
                page=page.get("url"),
                recommendation=(
                    "Configure X-Frame-Options or "
                    "CSP frame-ancestors."
                )
            )
        )


# ============================================================
# COOKIES
# ============================================================

def add_cookies(findings, page):
    """
    Analyze cookie security attributes.
    """

    cookies = page.get(
        "cookies",
        []
    )

    if not isinstance(cookies, list):
        return

    for cookie in cookies:

        if not isinstance(cookie, dict):
            continue

        name = cookie.get(
            "name",
            "Unknown"
        )

        secure = cookie.get(
            "secure"
        )

        httponly = cookie.get(
            "httponly"
        )

        samesite = str(
            cookie.get(
                "samesite",
                ""
            )
        ).lower()

        likely_auth = auth_cookie(cookie)

        if secure is False:

            if likely_auth:

                findings.append(
                    make_finding(
                        name="Authentication Cookie Missing Secure",
                        category="Cookie Security",
                        severity="MEDIUM",
                        score=15,
                        confidence="HIGH",
                        description=(
                            "A likely authentication or session "
                            "cookie was observed without the "
                            "Secure attribute."
                        ),
                        evidence={
                            "cookie": name,
                            "secure": secure
                        },
                        page=page.get("url"),
                        recommendation=(
                            "Set the Secure attribute on "
                            "authentication and session cookies."
                        )
                    )
                )

            else:

                findings.append(
                    make_finding(
                        name="Cookie Missing Secure",
                        category="Cookie Security",
                        severity="LOW",
                        score=5,
                        confidence="HIGH",
                        description=(
                            "A cookie was observed without "
                            "the Secure attribute."
                        ),
                        evidence={
                            "cookie": name,
                            "secure": secure
                        },
                        page=page.get("url"),
                        recommendation=(
                            "Use the Secure attribute for "
                            "cookies transmitted over HTTPS."
                        )
                    )
                )

        if (
            httponly is False
            and likely_auth
        ):

            findings.append(
                make_finding(
                    name="Authentication Cookie Missing HttpOnly",
                    category="Cookie Security",
                    severity="MEDIUM",
                    score=15,
                    confidence="MEDIUM",
                    description=(
                        "A likely authentication or session "
                        "cookie was observed without HttpOnly."
                    ),
                    evidence={
                        "cookie": name,
                        "httponly": httponly
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Set HttpOnly on authentication and "
                        "session cookies where appropriate."
                    )
                )
            )

        if (
            samesite == "none"
            and secure is False
        ):

            findings.append(
                make_finding(
                    name="SameSite=None Cookie Without Secure",
                    category="Cookie Security",
                    severity="MEDIUM",
                    score=15,
                    confidence="HIGH",
                    description=(
                        "A cookie uses SameSite=None without "
                        "the Secure attribute."
                    ),
                    evidence={
                        "cookie": name,
                        "samesite": samesite,
                        "secure": secure
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Use Secure when configuring "
                        "SameSite=None cookies."
                    )
                )
            )


# ============================================================
# FORMS
# ============================================================

def add_forms(findings, page):
    """
    Check whether password forms submit over HTTP.
    """

    forms = page.get(
        "forms",
        []
    )

    if not isinstance(forms, list):
        return

    for form in forms:

        if not isinstance(form, dict):
            continue

        method = str(
            form.get("method", "")
        ).upper()

        action = str(
            form.get("action", "")
        )

        has_password = form.get(
            "has_password"
        )

        if has_password is None:

            inputs = form.get(
                "inputs",
                []
            )

            if isinstance(inputs, list):

                has_password = any(
                    str(
                        item.get("type", "")
                    ).lower() == "password"
                    for item in inputs
                    if isinstance(item, dict)
                )

        if not has_password:
            continue

        if action.startswith("http://"):

            findings.append(
                make_finding(
                    name="Password Form Uses HTTP",
                    category="Transport Security",
                    severity="HIGH",
                    score=30,
                    confidence="HIGH",
                    description=(
                        "A password form was observed "
                        "submitting to an HTTP URL."
                    ),
                    evidence={
                        "method": method,
                        "action": action
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Submit password and authentication "
                        "data only over HTTPS."
                    )
                )
            )


# ============================================================
# MIXED CONTENT
# ============================================================

def add_mixed_content(findings, page):
    """
    Analyze mixed-content observations collected by crawler.
    """

    mixed_content = page.get(
        "mixed_content"
    )

    if not mixed_content:
        return

    if isinstance(mixed_content, bool):

        detected = mixed_content

        evidence = {
            "mixed_content": mixed_content
        }

    elif isinstance(mixed_content, dict):

        detected = mixed_content.get(
            "detected",
            False
        )

        evidence = mixed_content

    else:

        detected = False
        evidence = {
            "mixed_content": mixed_content
        }

    if detected:

        findings.append(
            make_finding(
                name="Mixed Content",
                category="Transport Security",
                severity="LOW",
                score=5,
                confidence="HIGH",
                description=(
                    "An HTTPS page was observed referencing "
                    "HTTP resources."
                ),
                evidence=evidence,
                page=page.get("url"),
                recommendation=(
                    "Serve page resources over HTTPS."
                )
            )
        )


# ============================================================
# CORS
# ============================================================

def add_cors(findings, page):
    """
    Analyze CORS observations conservatively.

    Wildcard CORS alone is informational because it can
    be intentional for public resources.
    """

    cors = page.get(
        "cors"
    )

    if not cors:
        return

    if isinstance(cors, dict):

        allow_origin = str(
            cors.get(
                "allow_origin",
                ""
            )
        ).strip()

        allow_credentials = cors.get(
            "allow_credentials",
            False
        )

        if (
            allow_origin == "*"
            and allow_credentials is True
        ):
            # Browsers reject credentialed requests with
            # wildcard origin. Do not create a false positive.
            return

        if allow_origin == "*":

            findings.append(
                make_finding(
                    name="Wildcard CORS Policy",
                    category="CORS",
                    severity="INFO",
                    score=0,
                    confidence="HIGH",
                    description=(
                        "The response allows requests from "
                        "any origin."
                    ),
                    evidence={
                        "allow_origin": allow_origin,
                        "allow_credentials":
                            allow_credentials
                    },
                    page=page.get("url"),
                    recommendation=(
                        "If cross-origin access is not intended "
                        "to be public, restrict allowed origins."
                    )
                )
            )

        elif allow_origin.lower() == "null":

            findings.append(
                make_finding(
                    name="Null Origin Allowed",
                    category="CORS",
                    severity="LOW",
                    score=5,
                    confidence="HIGH",
                    description=(
                        "The response allows the null origin."
                    ),
                    evidence={
                        "allow_origin": allow_origin
                    },
                    page=page.get("url"),
                    recommendation=(
                        "Allow only explicitly required origins."
                    )
                )
            )


# ============================================================
# EXPOSURE
# ============================================================

def add_exposure(findings, page):
    """
    Analyze directory listing and verbose error indicators.
    """

    directory_listing = page.get(
        "directory_listing"
    )

    if isinstance(directory_listing, dict):

        detected = directory_listing.get(
            "detected",
            False
        )

        if detected:

            findings.append(
                make_finding(
                    name="Directory Listing Detected",
                    category="Information Exposure",
                    severity="MEDIUM",
                    score=15,
                    confidence="HIGH",
                    description=(
                        "The page contains indicators "
                        "of directory listing."
                    ),
                    evidence=directory_listing,
                    page=page.get("url"),
                    recommendation=(
                        "Disable directory indexing unless "
                        "it is intentionally required."
                    )
                )
            )

    error_indicators = page.get(
        "error_indicators"
    )

    if isinstance(error_indicators, dict):

        detected = error_indicators.get(
            "detected",
            False
        )

        if detected:

            findings.append(
                make_finding(
                    name="Verbose Error Information",
                    category="Information Exposure",
                    severity="MEDIUM",
                    score=15,
                    confidence="MEDIUM",
                    description=(
                        "The response contains indicators "
                        "of verbose error or stack-trace information."
                    ),
                    evidence=error_indicators,
                    page=page.get("url"),
                    recommendation=(
                        "Disable verbose production errors and "
                        "return generic error responses."
                    )
                )
            )

# ============================================================
# INFORMATION DISCLOSURE
# ============================================================

def add_information(findings, page):
    """
    Record useful observations that are not automatically
    vulnerabilities.
    """

    server = page.get(
        "server_information"
    )

    if server:

        findings.append(
            make_finding(
                name="Server Information Disclosed",
                category="Information Disclosure",
                severity="INFO",
                score=0,
                confidence="HIGH",
                description=(
                    "The server response exposes "
                    "server or technology information."
                ),
                evidence={
                    "server_information": server
                },
                page=page.get("url"),
                recommendation=(
                    "Consider minimizing unnecessary "
                    "technology disclosure."
                )
            )
        )

    sensitive_parameters = page.get(
        "sensitive_parameters"
    )

    if sensitive_parameters:

        findings.append(
            make_finding(
                name="Sensitive-Looking URL Parameters",
                category="Information Disclosure",
                severity="INFO",
                score=0,
                confidence="HIGH",
                description=(
                    "A discovered URL contains parameter "
                    "names that may represent sensitive data."
                ),
                evidence={
                    "parameters": sensitive_parameters
                },
                page=page.get("url"),
                recommendation=(
                    "Avoid placing sensitive secrets or "
                    "credentials in URLs."
                )
            )
        )


# ============================================================
# MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_crawler_result(crawler_result):
    """
    Convert crawler observations into structured
    security findings.

    The analyzer does NOT perform active testing.
    It only interprets evidence already collected
    by the passive crawler.
    """

    findings = []

    if not isinstance(crawler_result, dict):

        return {
            "success": False,
            "findings": [],
            "error": "Invalid crawler result."
        }

    if not crawler_result.get("success"):

        return {
            "success": False,
            "findings": [],
            "error": crawler_result.get(
                "error",
                "Crawler failed."
            )
        }

    # --------------------------------------------------------
    # SITE-WIDE TLS ANALYSIS
    # --------------------------------------------------------

    add_tls(
        findings,
        crawler_result
    )

    # --------------------------------------------------------
    # PAGE ANALYSIS
    # --------------------------------------------------------

    pages = crawler_result.get(
        "pages",
        {}
    )

    if isinstance(pages, dict):
        pages = pages.values()

    elif not isinstance(pages, list):
        pages = []

    for page in pages:

        if not isinstance(page, dict):
            continue

        add_transport(
            findings,
            page
        )

        add_hsts(
            findings,
            page
        )

        add_headers(
            findings,
            page
        )

        add_cookies(
            findings,
            page
        )

        add_forms(
            findings,
            page
        )

        add_mixed_content(
            findings,
            page
        )

        add_cors(
            findings,
            page
        )

        add_exposure(
            findings,
            page
        )

        add_information(
            findings,
            page
        )

    return {
        "success": True,
        "findings": findings,
        "analyzed_at":
            datetime.now(
                timezone.utc
            ).isoformat()
    }


# ============================================================
# DISPLAY SECURITY ANALYSIS
# ============================================================

def display_security_analysis(analysis):
    """
    Display security findings.

    Risk scoring is intentionally handled separately
    by risk_engine.py.
    """

    print("\n")
    print("=" * 70)
    print("                     SECURITY ANALYSIS")
    print("=" * 70)

    if not analysis.get("success"):

        print(
            "\n[ERROR] Security analysis failed."
        )

        print(
            f"Reason: {analysis.get('error')}"
        )

        print("=" * 70)

        return

    findings = analysis.get(
        "findings",
        []
    )

    print(
        f"\nTotal Findings : {len(findings)}"
    )

    if not findings:

        print(
            "\nNo security findings were generated."
        )

        print("=" * 70)

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print("\n" + "-" * 70)

        print(
            f"Finding #{index}"
        )

        print(
            f"Name         : "
            f"{finding.get('name')}"
        )

        print(
            f"Category     : "
            f"{finding.get('category')}"
        )

        print(
            f"Severity     : "
            f"{finding.get('severity')}"
        )

        print(
            f"Confidence   : "
            f"{finding.get('confidence')}"
        )

        print(
            f"Page         : "
            f"{finding.get('page')}"
        )

        print(
            f"Description  : "
            f"{finding.get('description')}"
        )

        print(
            f"Evidence     : "
            f"{finding.get('evidence')}"
        )

        print(
            f"Recommendation: "
            f"{finding.get('recommendation')}"
        )

    print("\n" + "=" * 70)