from input_handler import (
    get_target_url,
    validate_url,
    parse_target
)

from risk_engine import (
    classify_risk,
    calculate_security_risk,
    display_security_risk
)

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
    observations = []

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
            "description": "Target URL uses HTTP instead of HTTPS.",
            "score": 30
        })

    if target["hostname"]:
        observations.append({
            "name": "Hostname Format",
            "status": "PASS",
            "description": "A hostname was successfully extracted from the URL.",
            "score": 0
        })

    if web_data["dns_resolved"]:
        observations.append({
            "name": "DNS Resolution",
            "status": "PASS",
            "description": "The hostname successfully resolved through DNS.",
            "score": 0
        })
    else:
        observations.append({
            "name": "DNS Resolution",
            "status": "FAIL",
            "description": "The hostname could not be resolved.",
            "score": 30
        })
        return observations

    if web_data["server_connection"]:
        observations.append({
            "name": "Server Connection",
            "status": "PASS",
            "description": "The resolved server successfully responded to the HTTP request.",
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

    status_code = web_data["status_code"]

    if 200 <= status_code < 300:
        observations.append({
            "name": "Page Availability",
            "status": "PASS",
            "description": f"The requested resource returned HTTP {status_code}.",
            "score": 0
        })
    elif 300 <= status_code < 400:
        observations.append({
            "name": "Page Availability",
            "status": "REDIRECT",
            "description": f"The server returned HTTP {status_code} and redirected the request.",
            "score": 0
        })
    elif 400 <= status_code < 500:
        observations.append({
            "name": "Page Availability",
            "status": "WARNING",
            "description": f"The server returned HTTP {status_code} {web_data['reason']}.",
            "score": 10
        })
    else:
        observations.append({
            "name": "Page Availability",
            "status": "WARNING",
            "description": f"The server returned HTTP {status_code} {web_data['reason']}.",
            "score": 15
        })

    return observations


def display_results(target, observations, risk, web_data):
    print("\n" + "=" * 55)
    print("              WEBSENTINEL - PHASE 1")
    print("         Passive Web Security Foundation")
    print("=" * 55)

    print("\nTARGET INFORMATION")
    print("-" * 55)
    print(f"URL              : {target['url']}")
    print(f"Scheme           : {target['scheme']}")
    print(f"Hostname         : {target['hostname']}")

    if target["port"]:
        print(f"Port             : {target['port']}")

    print("\nBASIC OBSERVATIONS")
    print("-" * 55)
    for observation in observations:
        print(
            f"{observation['name']:<20}: "
            f"{observation['status']}"
        )
        print(f"  {observation['description']}")

    print("\nDNS ANALYSIS")
    print("-" * 55)
    if web_data["dns_resolved"]:
        print("DNS Resolution   : SUCCESS")
        print("IP Address(es)   : " + ", ".join(web_data["ip_addresses"]))
    else:
        print("DNS Resolution   : FAILED")
        print(f"Reason           : {web_data['dns_error']}")

    print("\nSERVER / HTTP ANALYSIS")
    print("-" * 55)
    if web_data["server_connection"]:
        print("Server Connection : SUCCESS")
        print(f"HTTP Status       : {web_data['status_code']} {web_data['reason']}")
        print(f"Response Time     : {web_data['response_time']} seconds")
        print(f"Content Type      : {web_data['content_type']}")
        print(f"Server            : {web_data['server'] or 'Not disclosed'}")
        print(f"Final URL         : {web_data['final_url']}")
        print(f"Redirected        : {'YES' if web_data['redirected'] else 'NO'}")
        print(f"Page Available    : {'YES' if web_data['page_available'] else 'NO'}")
    else:
        print("Server Connection : NOT COMPLETED")
        if web_data["error"]:
            print(f"Reason            : {web_data['error']}")

    print("\nRISK SUMMARY")
    print("-" * 55)
    print(f"Risk Score        : {risk['score']}/100")
    print(f"Risk Level        : {risk['level']}")


def display_website_structure(crawl_result):
    print("\n" + "=" * 75)
    print("WEBSITE STRUCTURE")
    print("=" * 75)

    graph = crawl_result.get("website_graph", {})

    if not graph:
        print("No website structure available.")
        print("=" * 75)
        return

    children_map = {}

    for url, node in graph.items():
        parent = node.get("parent")
        children_map.setdefault(parent, []).append(url)

    roots = [
        url for url, node in graph.items()
        if node.get("parent") is None
    ]

    if not roots:
        roots = [next(iter(graph))]

    visited = set()

    def print_node(url, prefix="", is_last=True):
        if url in visited:
            return

        visited.add(url)
        connector = "└── " if is_last else "├── "
        print(prefix + connector + url)

        children = [
            child for child in children_map.get(url, [])
            if child not in visited
        ]

        for index, child in enumerate(children):
            last = index == len(children) - 1
            child_prefix = prefix + ("    " if is_last else "│   ")
            print_node(child, child_prefix, last)

    for index, root in enumerate(roots):
        print_node(root, "", index == len(roots) - 1)

    print("\nTotal graph nodes : " + str(len(graph)))
    print("=" * 75)


def main():
    print("=" * 55)
    print("                  WEBSENTINEL")
    print("           Passive Web Security Platform")
    print("=" * 55)

    url = get_target_url()

    if not validate_url(url):
        print("\n[ERROR] Invalid URL.")
        print("Please enter a valid HTTP/HTTPS URL.")
        return

    target = parse_target(url)
    print("\nPerforming target assessment...")

    web_data = check_website(url, target["hostname"])
    observations = collect_basic_observations(target, web_data)
    basic_risk = classify_risk(observations)
    display_results(target, observations, basic_risk, web_data)

    print("\n")
    print("=" * 55)
    print("Starting HTML crawler...")
    print("=" * 55)

    crawl_result = crawl_website(url, max_pages=20)
    display_crawl_results(crawl_result)
    display_website_structure(crawl_result)

    print("\n")
    print("=" * 55)
    print("Starting security analysis...")
    print("=" * 55)

    security_analysis = analyze_crawler_result(crawl_result)
    display_security_analysis(security_analysis)

    print("\n")
    
    if not security_analysis.get("success"):
        print("=" * 70)
        print("                    RISK ENGINE")
        print("=" * 70)
        print("[ERROR] Security analysis failed.")
        return

    final_risk = calculate_security_risk(
        security_analysis.get("findings", [])
    )

    display_security_risk(final_risk)

    print("\nRisk assessment complete.")


if __name__ == "__main__":
    main()
