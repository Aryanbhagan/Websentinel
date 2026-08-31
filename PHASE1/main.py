from input_handler import (
    get_target_url,
    validate_url,
    parse_target
)

from risk_engine import classify_risk
from web_checker import check_website


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

        # No HTTP request should be considered successful
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


def display_results(target, observations, risk, web_data):
    """Display the Phase 1 assessment."""

    print("\n" + "=" * 55)
    print("              WEBSENTINEL - PHASE 1")
    print("         Passive Web Security Foundation")
    print("=" * 55)

    # Target information
    print("\nTARGET INFORMATION")
    print("-" * 55)

    print(f"URL              : {target['url']}")
    print(f"Scheme           : {target['scheme']}")
    print(f"Hostname         : {target['hostname']}")

    if target["port"]:
        print(f"Port             : {target['port']}")

    # Basic observations
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

    # DNS analysis
    print("\nDNS ANALYSIS")
    print("-" * 55)

    if web_data["dns_resolved"]:

        print("DNS Resolution   : SUCCESS")

        print(
            "IP Address(es)   : "
            + ", ".join(web_data["ip_addresses"])
        )

    else:

        print("DNS Resolution   : FAILED")

        print(
            f"Reason           : "
            f"{web_data['dns_error']}"
        )

    # Server / HTTP analysis
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

    # Risk summary
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

    # Get target
    url = get_target_url()

    # Validate URL structure
    if not validate_url(url):

        print("\n[ERROR] Invalid URL.")
        print(
            "Please enter a valid HTTP/HTTPS URL."
        )
        return

    # Parse target
    target = parse_target(url)

    print("\nPerforming target assessment...")

    # IMPORTANT:
    # check_website() requires both the URL
    # and the hostname for DNS resolution.
    web_data = check_website(
        url,
        target["hostname"]
    )

    # Collect observations
    observations = collect_basic_observations(
        target,
        web_data
    )

    # Calculate risk
    risk = classify_risk(observations)

    # Display complete results
    display_results(
        target,
        observations,
        risk,
        web_data
    )


if __name__ == "__main__":
    main()