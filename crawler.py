import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque

MAX_PAGES = 20

def normalize_url(url):
    """
    Remove URL fragments and normalize basic URL formatting.
    """

    clean_url, _ = urldefrag(url)

    return clean_url.rstrip("/")


def is_internal_link(url, target_hostname):
    """
    Check whether a URL belongs to the target hostname.
    """

    parsed = urlparse(url)

    return parsed.hostname == target_hostname


def extract_links(html, current_url, target_hostname):
    """
    Extract internal and external HTTP/HTTPS links
    from a page.
    """

    soup = BeautifulSoup(html, "html.parser")

    anchor_tags = soup.find_all("a", href=True)

    internal_links = set()
    external_links = set()

    for anchor in anchor_tags:

        href = anchor.get("href", "").strip()

        if not href:
            continue

        # Ignore page fragments
        if href.startswith("#"):
            continue

        # Ignore non-web links
        if href.startswith((
            "mailto:",
            "tel:",
            "javascript:",
            "data:"
        )):
            continue

        # Convert relative URLs into absolute URLs
        absolute_url = urljoin(
            current_url,
            href
        )

        # Remove fragments
        absolute_url, _ = urldefrag(
            absolute_url
        )

        parsed_url = urlparse(
            absolute_url
        )

        # Only allow HTTP and HTTPS
        if parsed_url.scheme not in (
            "http",
            "https"
        ):
            continue

        normalized_url = normalize_url(
            absolute_url
        )

        if not normalized_url:
            continue

        # Internal or external classification
        if is_internal_link(
            normalized_url,
            target_hostname
        ):
            internal_links.add(
                normalized_url
            )
        else:
            external_links.add(
                normalized_url
            )

    return (
        sorted(internal_links),
        sorted(external_links),
        len(anchor_tags)
    )


def crawl_website(start_url, max_pages=MAX_PAGES):
    """
    WebSentinel Crawler V2

    Crawls multiple internal pages using a queue.
    Discovers and records external links without crawling them.
    """

    result = {
        "success": False,
        "start_url": start_url,
        "final_start_url": None,
        "pages": {},
        "visited": set(),
        "external_links": set(),
        "failed_pages": {},
        "total_anchor_tags": 0,
        "max_pages": max_pages,
        "error": None
    }

    start_url = normalize_url(
        start_url
    )

    # Queue stores pages waiting to be crawled
    queue = deque([
        start_url
    ])

    try:

        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent":
                "WebSentinel/1.0 Educational Security Crawler"
            }
        ) as client:

            while (
                queue
                and len(result["visited"]) < max_pages
            ):

                current_url = queue.popleft()

                current_url = normalize_url(
                    current_url
                )

                # Skip duplicates
                if current_url in result["visited"]:
                    continue

                print(
                    f"\n[{len(result['visited']) + 1}/"
                    f"{max_pages}] Crawling: "
                    f"{current_url}"
                )

                # Mark URL as visited
                result["visited"].add(
                    current_url
                )

                try:

                    response = client.get(
                        current_url
                    )

                    final_url = normalize_url(
                        str(response.url)
                    )

                    # Store final start URL
                    if (
                        current_url == start_url
                        and result["final_start_url"] is None
                    ):
                        result[
                            "final_start_url"
                        ] = final_url

                    content_type = response.headers.get(
                        "content-type",
                        ""
                    )

                    page_data = {
                        "url": current_url,
                        "final_url": final_url,
                        "status_code": response.status_code,
                        "reason": response.reason_phrase,
                        "content_type": content_type,
                        "html_size": len(
                            response.text
                        ),
                        "anchor_tags_found": 0,
                        "internal_links": [],
                        "external_links": []
                    }

                    # HTTP error
                    if response.status_code >= 400:

                        result["failed_pages"][
                            current_url
                        ] = (
                            f"HTTP "
                            f"{response.status_code} "
                            f"{response.reason_phrase}"
                        )

                        result["pages"][
                            current_url
                        ] = page_data

                        print(
                            f"    FAILED: HTTP "
                            f"{response.status_code} "
                            f"{response.reason_phrase}"
                        )

                        continue

                    # Ignore non-HTML responses
                    if (
                        "text/html"
                        not in content_type.lower()
                    ):

                        page_data[
                            "error"
                        ] = (
                            "Non-HTML response"
                        )

                        result["pages"][
                            current_url
                        ] = page_data

                        print(
                            "    SKIPPED: "
                            "Non-HTML response"
                        )

                        continue

                    # Target hostname based on final URL
                    target_hostname = urlparse(
                        final_url
                    ).hostname

                    (
                        internal_links,
                        external_links,
                        anchor_count
                    ) = extract_links(
                        response.text,
                        final_url,
                        target_hostname
                    )

                    # Store page information
                    page_data[
                        "anchor_tags_found"
                    ] = anchor_count

                    page_data[
                        "internal_links"
                    ] = internal_links

                    page_data[
                        "external_links"
                    ] = external_links

                    result[
                        "pages"
                    ][current_url] = page_data

                    result[
                        "total_anchor_tags"
                    ] += anchor_count

                    # Record external links
                    result[
                        "external_links"
                    ].update(
                        external_links
                    )

                    # Add internal links to queue
                    for link in internal_links:

                        if (
                            link
                            not in result["visited"]
                            and link not in queue
                        ):

                            if (
                                len(
                                    result["visited"]
                                )
                                + len(queue)
                                < max_pages
                            ):

                                queue.append(
                                    link
                                )

                    print(
                        f"    SUCCESS: "
                        f"{len(internal_links)} "
                        f"internal links, "
                        f"{len(external_links)} "
                        f"external links"
                    )

                except httpx.RequestError as error:

                    result["failed_pages"][
                        current_url
                    ] = str(error)

                    print(
                        "    FAILED: "
                        f"{error}"
                    )

        # Crawl is considered successful
        # if at least one page was processed
        if result["pages"]:

            result["success"] = True

        return result

    except Exception as error:

        result["error"] = str(error)

        return result


def display_crawl_results(result):
    """
    Display the complete multi-page crawl summary.
    """

    print("\n" + "=" * 65)
    print("              WEBSENTINEL - CRAWLER V2")
    print("           Multi-Page Static Web Crawling")
    print("=" * 65)

    print("\nTARGET INFORMATION")
    print("-" * 65)

    print(
        f"Starting URL       : "
        f"{result['start_url']}"
    )

    print(
        f"Pages Limit        : "
        f"{result['max_pages']}"
    )

    if result["final_start_url"]:

        print(
            f"Final Start URL    : "
            f"{result['final_start_url']}"
        )

    # Fatal error
    if result["error"]:

        print("\nCRAWL STATUS")
        print("-" * 65)

        print("Status             : FAILED")
        print(
            f"Reason             : "
            f"{result['error']}"
        )

        print("=" * 65)

        return

    # Crawled pages
    print("\nCRAWLED PAGES")
    print("-" * 65)

    if result["pages"]:

        for index, (
            url,
            page
        ) in enumerate(
            result["pages"].items(),
            start=1
        ):

            print(
                f"\n[{index}] {url}"
            )

            print(
                f"    HTTP Status    : "
                f"{page['status_code']} "
                f"{page['reason']}"
            )

            print(
                f"    Content Type   : "
                f"{page['content_type']}"
            )

            print(
                f"    Response Size  : "
                f"{page['html_size']} characters"
            )

            print(
                f"    <a> Tags       : "
                f"{page['anchor_tags_found']}"
            )

            print(
                f"    Internal Links : "
                f"{len(page['internal_links'])}"
            )

            print(
                f"    External Links : "
                f"{len(page['external_links'])}"
            )

    else:

        print(
            "No pages were successfully processed."
        )

    # Failed pages
    print("\nFAILED PAGES")
    print("-" * 65)

    if result["failed_pages"]:

        for url, reason in (
            result["failed_pages"].items()
        ):

            print(
                f"- {url}"
            )

            print(
                f"  Reason: {reason}"
            )

    else:

        print(
            "No failed pages."
        )

    # External links
    print("\nEXTERNAL LINKS DISCOVERED")
    print("-" * 65)

    if result["external_links"]:

        for index, link in enumerate(
            sorted(result["external_links"]),
            start=1
        ):

            print(
                f"{index}. {link}"
            )

    else:

        print(
            "No external links discovered."
        )

    # Summary
    print("\nCRAWL SUMMARY")
    print("-" * 65)

    print(
        f"Pages Visited      : "
        f"{len(result['visited'])}"
    )

    print(
        f"Pages Processed    : "
        f"{len(result['pages'])}"
    )

    print(
        f"Failed Pages       : "
        f"{len(result['failed_pages'])}"
    )

    print(
        f"External Links     : "
        f"{len(result['external_links'])}"
    )

    print(
        f"Total <a> Tags     : "
        f"{result['total_anchor_tags']}"
    )

    print(
        "\nCrawler Scope      : "
        "Multi-Page Static HTML Analysis"
    )

    print("=" * 65)


if __name__ == "__main__":

    print("=" * 65)
    print("                WEBSENTINEL CRAWLER V2")
    print("             Multi-Page Link Discovery")
    print("=" * 65)

    target_url = input(
        "\nEnter website URL: "
    ).strip()

    crawl_result = crawl_website(
        target_url,
        MAX_PAGES
    )

    display_crawl_results(
        crawl_result
    )