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


def extract_security_headers(response):
    """
    Passively collect commonly relevant security headers.
    No active testing is performed.
    """

    header_mapping = {
        "content-security-policy": "content_security_policy",
        "strict-transport-security": "strict_transport_security",
        "x-frame-options": "x_frame_options",
        "x-content-type-options": "x_content_type_options",
        "referrer-policy": "referrer_policy",
        "permissions-policy": "permissions_policy"
    }

    security_headers = {}

    for header_name, field_name in header_mapping.items():

        value = response.headers.get(
            header_name
        )

        security_headers[field_name] = {
            "present": value is not None,
            "value": value
        }

    return security_headers


def extract_cookies(response):
    """
    Passively collect cookie security attributes
    from Set-Cookie response headers.
    """

    cookies = []

    set_cookie_headers = response.headers.get_list(
        "set-cookie"
    )

    for cookie_header in set_cookie_headers:

        parts = [
            part.strip()
            for part in cookie_header.split(";")
        ]

        if not parts:
            continue

        name_value = parts[0]

        if "=" not in name_value:
            continue

        cookie_name = name_value.split(
            "=",
            1
        )[0].strip()

        cookie = {
            "name": cookie_name,
            "secure": False,
            "httponly": False,
            "samesite": None
        }

        for attribute in parts[1:]:

            attribute_lower = attribute.lower()

            if attribute_lower == "secure":
                cookie["secure"] = True

            elif attribute_lower == "httponly":
                cookie["httponly"] = True

            elif attribute_lower.startswith(
                "samesite="
            ):
                cookie["samesite"] = (
                    attribute.split(
                        "=",
                        1
                    )[1].strip()
                )

        cookies.append(cookie)

    return cookies


def extract_forms(html, current_url):
    """
    Passively inspect forms present in the HTML.
    Forms are never submitted.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    forms = []

    for form in soup.find_all("form"):

        method = (
            form.get("method", "GET")
            .upper()
        )

        action = form.get(
            "action",
            ""
        ).strip()

        if action:
            action = urljoin(
                current_url,
                action
            )

        inputs = []

        for field in form.find_all(
            ["input", "textarea", "select"]
        ):

            input_type = (
                field.get(
                    "type",
                    "text"
                )
                if field.name == "input"
                else field.name
            )

            inputs.append({
                "name": field.get("name"),
                "type": input_type
            })

        password_fields = [
            field
            for field in inputs
            if str(
                field.get("type", "")
            ).lower() == "password"
        ]

        forms.append({
            "method": method,
            "action": action,
            "inputs": inputs,
            "password_fields": len(
                password_fields
            )
        })

    return forms


def extract_scripts(html, current_url, target_hostname):
    """
    Passively inspect script elements and classify
    them as internal or external.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    scripts = []

    for script in soup.find_all("script"):

        src = script.get("src")

        if not src:
            scripts.append({
                "src": None,
                "type": "inline",
                "internal": None
            })

            continue

        absolute_url = urljoin(
            current_url,
            src
        )

        absolute_url, _ = urldefrag(
            absolute_url
        )

        parsed_url = urlparse(
            absolute_url
        )

        scripts.append({
            "src": absolute_url,
            "type": "external",
            "internal": (
                parsed_url.hostname
                == target_hostname
            )
        })

    return scripts


def extract_mixed_content(html, current_url):
    """
    Passively identify HTTP resources referenced
    by an HTTPS page.
    """

    parsed_current = urlparse(
        current_url
    )

    if parsed_current.scheme != "https":
        return []

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    insecure_resources = []

    resource_attributes = {
        "script": "src",
        "img": "src",
        "iframe": "src",
        "audio": "src",
        "video": "src",
        "source": "src",
        "link": "href"
    }

    for tag_name, attribute in resource_attributes.items():

        for tag in soup.find_all(
            tag_name
        ):

            resource = tag.get(
                attribute
            )

            if not resource:
                continue

            absolute_url = urljoin(
                current_url,
                resource
            )

            parsed_resource = urlparse(
                absolute_url
            )

            if parsed_resource.scheme == "http":

                insecure_resources.append(
                    absolute_url
                )

    return sorted(
        set(insecure_resources)
    )


def analyze_page_security(
    html,
    response,
    current_url,
    target_hostname
):
    """
    Collect passive security evidence from
    one HTTP response and its HTML.
    """

    return {
        "security_headers":
            extract_security_headers(
                response
            ),

        "cookies":
            extract_cookies(
                response
            ),

        "forms":
            extract_forms(
                html,
                current_url
            ),

        "scripts":
            extract_scripts(
                html,
                current_url,
                target_hostname
            ),

        "mixed_content":
            extract_mixed_content(
                html,
                current_url
            )
    }


def crawl_website(
    start_url,
    max_pages=MAX_PAGES
):
    """
    WebSentinel V4.1

    Multi-page static HTML crawler with
    passive security evidence collection.

    The crawler:
    - Crawls internal pages only
    - Records external links
    - Collects HTTP metadata
    - Collects security headers
    - Collects cookie attributes
    - Collects forms
    - Collects scripts
    - Detects passive mixed-content references

    No forms are submitted.
    No payloads are sent.
    No exploitation is performed.
    """

    result = {
        "success": False,
        "start_url": start_url,
        "final_start_url": None,

        "pages": {},

        "website_graph": {},

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

    queue = deque([
        start_url
    ])

    parent_map = {
        start_url: None
    }

    depth_map = {
        start_url: 0
    }

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
                and len(result["visited"])
                < max_pages
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
                        and result["final_start_url"]
                        is None
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

                        "parent_url": parent_map.get(current_url),

                        "depth": depth_map.get(current_url, 0),

                        "final_url":
                            final_url,

                        "status_code":
                            response.status_code,

                        "reason":
                            response.reason_phrase,

                        "content_type":
                            content_type,

                        "server": response.headers.get("server"),

                        "html_size":
                            len(response.text),

                        "anchor_tags_found":
                            0,

                        "internal_links":
                            [],

                        "external_links":
                            [],

                        # Passive security evidence
                        "security_headers":
                            {},

                        "cookies":
                            [],

                        "forms":
                            [],

                        "scripts":
                            [],

                        "mixed_content":
                            []
                    }

                    # HTTP error
                    if response.status_code >= 400:

                        result[
                            "failed_pages"
                        ][current_url] = (
                            f"HTTP "
                            f"{response.status_code} "
                            f"{response.reason_phrase}"
                        )

                        result[
                            "pages"
                        ][current_url] = page_data

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

                        result[
                            "pages"
                        ][current_url] = page_data

                        print(
                            "    SKIPPED: "
                            "Non-HTML response"
                        )

                        continue

                    # Target hostname based on final URL
                    target_hostname = urlparse(
                        final_url
                    ).hostname

                    # -----------------------------------------
                    # LINK EXTRACTION
                    # -----------------------------------------

                    (
                        internal_links,
                        external_links,
                        anchor_count
                    ) = extract_links(
                        response.text,
                        final_url,
                        target_hostname
                    )

                    page_data[
                        "anchor_tags_found"
                    ] = anchor_count

                    page_data[
                        "internal_links"
                    ] = internal_links

                    page_data[
                        "external_links"
                    ] = external_links

                    # -----------------------------------------
                    # SECURITY EVIDENCE COLLECTION
                    # -----------------------------------------

                    security_data = (
                        analyze_page_security(
                            response.text,
                            response,
                            final_url,
                            target_hostname
                        )
                    )

                    page_data[
                        "security_headers"
                    ] = security_data[
                        "security_headers"
                    ]

                    page_data[
                        "cookies"
                    ] = security_data[
                        "cookies"
                    ]

                    page_data[
                        "forms"
                    ] = security_data[
                        "forms"
                    ]

                    page_data[
                        "scripts"
                    ] = security_data[
                        "scripts"
                    ]

                    page_data[
                        "mixed_content"
                    ] = security_data[
                        "mixed_content"
                    ]

                    # Website graph
                    result["website_graph"][current_url] = {
                        "parent": parent_map.get(current_url),
                        "depth": depth_map.get(current_url, 0),
                        "children": internal_links
                    }

                    # Store page information
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
                            parent_map[link] = current_url
                            depth_map[link] = (
                                depth_map.get(current_url, 0) + 1
                            )
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

                    print(
                        f"    Security Evidence: "
                        f"{len(security_data['security_headers'])} "
                        f"headers, "
                        f"{len(security_data['cookies'])} "
                        f"cookies, "
                        f"{len(security_data['forms'])} "
                        f"forms, "
                        f"{len(security_data['scripts'])} "
                        f"scripts"
                    )

                    if security_data[
                        "mixed_content"
                    ]:

                        print(
                            f"    Mixed Content: "
                            f"{len(security_data['mixed_content'])} "
                            f"resources"
                        )

                except httpx.TimeoutException:

                    result[
                        "failed_pages"
                    ][current_url] = (
                        "Request timed out."
                    )

                    print(
                        "    FAILED: Request timed out."
                    )

                except httpx.RequestError as error:

                    result[
                        "failed_pages"
                    ][current_url] = (
                        f"HTTP request error: "
                        f"{error}"
                    )

                    print(
                        f"    FAILED: "
                        f"HTTP request error: "
                        f"{error}"
                    )

                except Exception as error:

                    result[
                        "failed_pages"
                    ][current_url] = (
                        f"Unexpected error: "
                        f"{error}"
                    )

                    print(
                        f"    FAILED: "
                        f"Unexpected error: "
                        f"{error}"
                    )

        result["success"] = True

    except Exception as error:

        result["error"] = (
            f"Crawler error: {error}"
        )

    return result


def display_crawl_results(result):
    """
    Display crawler results in the terminal.
    """

    print("\n" + "=" * 60)
    print("       WEBSENTINEL - CRAWLER V4.1")
    print("   Multi-Page Static Web Crawling")
    print("   + Passive Security Evidence")
    print("=" * 60)

    print("\nCRAWL INFORMATION")
    print("-" * 60)

    print(
        f"Start URL          : "
        f"{result['start_url']}"
    )

    print(
        f"Final Start URL    : "
        f"{result['final_start_url']}"
    )

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
        f"Maximum Pages      : "
        f"{result['max_pages']}"
    )

    print("\nPAGE DETAILS")
    print("-" * 60)

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
            f"    Final URL      : "
            f"{page['final_url']}"
        )

        print(
            f"    Status         : "
            f"{page['status_code']} "
            f"{page['reason']}"
        )

        print(
            f"    Content Type   : "
            f"{page['content_type']}"
        )

        print(
            f"    HTML Size      : "
            f"{page['html_size']} bytes"
        )

        print(
            f"    Anchor Tags    : "
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

        print(
            f"    Forms          : "
            f"{len(page['forms'])}"
        )

        print(
            f"    Scripts        : "
            f"{len(page['scripts'])}"
        )

        print(
            f"    Cookies        : "
            f"{len(page['cookies'])}"
        )

        mixed_count = len(
            page.get(
                "mixed_content",
                []
            )
        )

        print(
            f"    Mixed Content  : "
            f"{mixed_count}"
        )

    print("\nEXTERNAL LINKS DISCOVERED")
    print("-" * 60)

    if result["external_links"]:

        for link in sorted(
            result["external_links"]
        ):

            print(
                f"  - {link}"
            )

    else:

        print(
            "No external links discovered."
        )

    print("\nFAILED PAGES")
    print("-" * 60)

    if result["failed_pages"]:

        for url, reason in (
            result["failed_pages"].items()
        ):

            print(
                f"  - {url}"
            )

            print(
                f"    {reason}"
            )

    else:

        print(
            "No failed pages."
        )

    print("\nCRAWL SUMMARY")
    print("-" * 60)

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

    print("=" * 60)