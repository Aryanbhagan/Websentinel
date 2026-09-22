from input_handler import (
    get_target_url,
    validate_url,
    parse_target
)

from risk_engine import classify_risk
from web_checker import check_website

from crawler import (
    crawl_website,
    display_crawl_results
)

from security_analyzer import (
    analyze_crawler_result,
    display_security_analysis
)


def collect_basic_observations(target, web_data):
    """Perform basic Phase 1 security observations."""

    observations = []

    # HTTPS check
    if target["scheme"] == "https":

        observations.append({
            "name": "HTTPS",
            "status": "PASS",
            "description": "Target URL uses HTTPS.",
            "score": 0
        })

    else:

        observations.append({
            "name": "HTTPS",
            "status": "WARNING",
            "description": (
                "Target URL uses HTTP instead of HTTPS."
            ),
            "score": 30
        })

    # Hostname format check
    if target["hostname"]:

        observations.append({
            "name": "Hostname Format",
            "status": "PASS",
            "description": (
                "A hostname was successfully extracted "
                "from the URL."
            ),
            "score": 0
        })

    # DNS resolution
    if web_data["dns_resolved"]:

        observations.append({
            "name": "DNS Resolution",
            "status": "PASS",
            "description": (
                "The hostname successfully resolved "
                "through DNS."
            ),
            "score": 0
        })

    else:

        observations.append({
            "name": "DNS Resolution",
            "status": "FAIL",
            "description": (
                "The hostname could not be resolved. "
                "The target may not exist or may be "
                "temporarily unavailable."
            ),
            "score": 30
        })

        return observations

    # Server connection
    if web_data["server_connection"]:

        observations.append({
            "name": "Server Connection",
            "status": "PASS",
            "description": (
                "The resolved server successfully "
                "responded to the HTTP request."
            ),
            "score": 0
        })

    else:

        observations.append({
            "name": "Server Connection",
            "status": "FAIL",
            "description": web_data["error"],
            "score": 30
        })

        return observations

    # HTTP status / page availability
    status_code = web_data["status_code"]

    if 200 <= status_code < 300:

        observations.append({
            "name": "Page Availability",
            "status": "PASS",
            "description": (
                f"The requested resource returned "
                f"HTTP {status_code}."
            ),
            "score": 0
        })

    elif 300 <= status_code < 400:

        observations.append({
            "name": "Page Availability",
            "status": "REDIRECT",
            "description": (
                f"The server returned HTTP {status_code} "
                "and redirected the request."
            ),
            "score": 0
        })

    elif 400 <= status_code < 500:

        observations.append({
            "name": "Page Availability",
            "status": "WARNING",
            "description": (
                f"The server returned HTTP {status_code} "
                f"{web_data['reason']}."
            ),
            "score": 10
        })

    else:

        observations.append({
            "name": "Page Availability",
            "status": "WARNING",
            "description": (
                f"The server returned HTTP {status_code} "
                f"{web_data['reason']}."
            ),
            "score": 15
        })

    return observations


def display_results(
    target,
    observations,
    risk,
    web_data
):
    """Display the Phase 1 assessment."""

    print("\n" + "=" * 55)
    print("              WEBSENTINEL - PHASE 1")
    print("         Passive Web Security Foundation")
    print("=" * 55)

    # -------------------------------------------------
    # TARGET INFORMATION
    # -------------------------------------------------

    print("\nTARGET INFORMATION")
    print("-" * 55)

    print(f"URL              : {target['url']}")
    print(f"Scheme           : {target['scheme']}")
    print(f"Hostname         : {target['hostname']}")

    if target["port"]:
        print(f"Port             : {target['port']}")

    # -------------------------------------------------
    # BASIC OBSERVATIONS
    # -------------------------------------------------

    print("\nBASIC OBSERVATIONS")
    print("-" * 55)

    for observation in observations:

        print(
            f"{observation['name']:<20}: "
            f"{observation['status']}"
        )

        print(
            f"  {observation['description']}"
        )

    # -------------------------------------------------
    # DNS ANALYSIS
    # -------------------------------------------------

    print("\nDNS ANALYSIS")
    print("-" * 55)

    if web_data["dns_resolved"]:

        print("DNS Resolution   : SUCCESS")

        print(
            "IP Address(es)   : "
            + ", ".join(
                web_data["ip_addresses"]
            )
        )

    else:

        print("DNS Resolution   : FAILED")

        print(
            f"Reason           : "
            f"{web_data['dns_error']}"
        )

    # -------------------------------------------------
    # SERVER / HTTP ANALYSIS
    # -------------------------------------------------

    print("\nSERVER / HTTP ANALYSIS")
    print("-" * 55)

    if web_data["server_connection"]:

        print("Server Connection : SUCCESS")

        print(
            f"HTTP Status       : "
            f"{web_data['status_code']} "
            f"{web_data['reason']}"
        )

        print(
            f"Response Time     : "
            f"{web_data['response_time']} seconds"
        )

        print(
            f"Content Type      : "
            f"{web_data['content_type']}"
        )

        print(
            f"Server            : "
            f"{web_data['server'] or 'Not disclosed'}"
        )

        print(
            f"Final URL         : "
            f"{web_data['final_url']}"
        )

        print(
            f"Redirected        : "
            f"{'YES' if web_data['redirected'] else 'NO'}"
        )

        if web_data["page_available"]:

            print("Page Available    : YES")

        else:

            print("Page Available    : NO")

    else:

        print("Server Connection : NOT COMPLETED")

        if web_data["error"]:

            print(
                f"Reason            : "
                f"{web_data['error']}"
            )

    # -------------------------------------------------
    # BASIC RISK SUMMARY
    # -------------------------------------------------

    print("\nRISK SUMMARY")
    print("-" * 55)

    print(
        f"Risk Score        : "
        f"{risk['score']}/100"
    )

    print(
        f"Risk Level        : "
        f"{risk['level']}"
    )

    print("\nPhase 1 assessment complete.")
    print("=" * 55)


def main():

    print("=" * 55)
    print("                  WEBSENTINEL")
    print("           Passive Web Security Platform")
    print("=" * 55)

    # =================================================
    # STEP 1: GET TARGET
    # =================================================

    url = get_target_url()

    if not validate_url(url):

        print("\n[ERROR] Invalid URL.")

        print(
            "Please enter a valid HTTP/HTTPS URL."
        )

        return

    # =================================================
    # STEP 2: PARSE TARGET
    # =================================================

    target = parse_target(url)

    print("\nPerforming target assessment...")

    # =================================================
    # STEP 3: BASIC WEB CHECK
    # =================================================

    web_data = check_website(
        url,
        target["hostname"]
    )

    # =================================================
    # STEP 4: BASIC OBSERVATIONS
    # =================================================

    observations = collect_basic_observations(
        target,
        web_data
    )

    # =================================================
    # STEP 5: CURRENT BASIC RISK
    # =================================================

    risk = classify_risk(
        observations
    )

    # =================================================
    # STEP 6: DISPLAY BASIC RESULTS
    # =================================================

    display_results(
        target,
        observations,
        risk,
        web_data
    )

    # =================================================
    # STEP 7: START HTML CRAWLER
    # =================================================

    print("\n")
    print("=" * 55)
    print("Starting HTML crawler...")
    print("=" * 55)

    crawl_result = crawl_website(
        url,
        max_pages=20
    )

    # =================================================
    # STEP 8: DISPLAY CRAWLER RESULTS
    # =================================================

    display_crawl_results(
        crawl_result
    )

    # =================================================
    # STEP 9: SECURITY ANALYSIS
    # =================================================

    print("\n")
    print("=" * 55)
    print("Starting security analysis...")
    print("=" * 55)

    security_analysis = analyze_crawler_result(
        crawl_result
    )

    # =================================================
    # STEP 10: DISPLAY SECURITY FINDINGS
    # =================================================

    display_security_analysis(
        security_analysis
    )


if __name__ == "__main__":
    main()