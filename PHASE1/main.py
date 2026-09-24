from input_handler import get_target_url, validate_url, parse_target
from web_checker import check_website
from crawler import crawl_website, display_crawl_results
from security_analyzer import analyze_crawler_result, display_security_analysis
from risk_engine import calculate_risk


def display_basic_results(target, web_result):
    print("\n" + "=" * 60)
    print("BASIC WEBSITE CHECK")
    print("=" * 60)

    print(f"Target URL       : {target['url']}")
    print(f"Hostname         : {target['hostname']}")
    print(f"Scheme           : {target['scheme']}")

    print(f"\nDNS Resolved     : {web_result.get('dns_resolved')}")
    print(f"Server Connected : {web_result.get('server_connection')}")
    print(f"Page Available   : {web_result.get('page_available')}")
    print(f"Status Code      : {web_result.get('status_code')}")
    print(f"Reason            : {web_result.get('reason')}")
    print(f"Response Time     : {web_result.get('response_time')}")

    if web_result.get("redirected"):
        print(f"Redirected To     : {web_result.get('final_url')}")

    if web_result.get("error"):
        print(f"Error             : {web_result.get('error')}")


def main():
    print("=" * 60)
    print("WEBSENTINEL - WEBSITE SECURITY ANALYZER")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. GET TARGET
    # ---------------------------------------------------------
    url = get_target_url()

    if not url:
        print("\nNo URL entered.")
        return

    # ---------------------------------------------------------
    # 2. VALIDATE URL
    # ---------------------------------------------------------
    if not validate_url(url):
        print("\nInvalid URL.")
        return

    target = parse_target(url)

    # ---------------------------------------------------------
    # 3. BASIC WEBSITE CHECK
    # ---------------------------------------------------------
    print("\nChecking target website...")

    web_result = check_website(
        target["url"],
        target["hostname"]
    )

    display_basic_results(target, web_result)

    # Stop if the website cannot be reached
    if not web_result.get("page_available"):
        print("\nWebsite cannot be analyzed because the page is unavailable.")
        return

    # ---------------------------------------------------------
    # 4. CRAWLER
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("STARTING WEBSITE CRAWLER")
    print("=" * 60)

    crawler_result = crawl_website(target["url"])

    if not crawler_result.get("success"):
        print("\nCrawler failed.")
        print(crawler_result.get("error"))
        return

    # Display crawler observations
    display_crawl_results(crawler_result)

    # ---------------------------------------------------------
    # 5. SECURITY ANALYZER
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("STARTING SECURITY ANALYSIS")
    print("=" * 60)

    security_analysis = analyze_crawler_result(crawler_result)

    if not security_analysis.get("success"):
        print("\nSecurity analysis failed.")
        print(security_analysis.get("error"))
        return

    display_security_analysis(security_analysis)

    # ---------------------------------------------------------
    # 6. RISK ENGINE
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("RISK ENGINE")
    print("=" * 60)

    findings = security_analysis.get("findings", [])

    final_risk = calculate_risk(findings)

    print(f"\nRisk Score        : {final_risk['score']}/100")
    print(f"Risk Level        : {final_risk['level']}")

    print("\nFinding Summary")
    print("-" * 40)
    print(f"High              : {final_risk['high']}")
    print(f"Medium            : {final_risk['medium']}")
    print(f"Low               : {final_risk['low']}")
    print(f"Informational     : {final_risk['informational']}")
    print(f"Unique Findings   : {final_risk['finding_count']}")

    print("\n" + "=" * 60)
    print("WEBSENTINEL ANALYSIS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()