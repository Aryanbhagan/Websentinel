import httpx
import ssl
import socket

from bs4 import BeautifulSoup
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from datetime import datetime

MAX_PAGES = 20
# URL HELPERS


def normalize_url(url):
    """
    Remove URL fragments and trailing slashes.
    """

    clean_url, _ = urldefrag(url)

    return clean_url.rstrip("/")


def is_internal_link(url, target_hostname):
    """
    Check whether a URL belongs to the target hostname.
    """

    parsed = urlparse(url)

    return parsed.hostname == target_hostname


def is_url_in_queue(queue, url):
    """
    Check whether a URL is already waiting in the crawl queue.
    """

    return any(
        queued_url == url
        for queued_url, _, _ in queue
    )

# LINK EXTRACTION

def extract_links(html, current_url, target_hostname):
    """
    Extract internal and external HTTP/HTTPS links.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    anchor_tags = soup.find_all(
        "a",
        href=True
    )

    internal_links = set()
    external_links = set()

    for anchor in anchor_tags:

        href = anchor.get(
            "href",
            ""
        ).strip()

        if not href:
            continue

        if href.startswith("#"):
            continue

        if href.startswith((
            "mailto:",
            "tel:",
            "javascript:",
            "data:"
        )):
            continue

        absolute_url = urljoin(
            current_url,
            href
        )

        absolute_url, _ = urldefrag(
            absolute_url
        )

        parsed_url = urlparse(
            absolute_url
        )

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

# ROUTE ANALYSIS

def get_route_category(path):
    """
    Categorize a URL based on its route.
    """

    path_lower = path.lower()

    if path in (
        "",
        "/"
    ):
        return "homepage"

    if any(word in path_lower for word in (
        "login",
        "signin",
        "sign-in",
        "auth"
    )):
        return "authentication"

    if any(word in path_lower for word in (
        "admin",
        "administrator",
        "dashboard"
    )):
        return "administration"

    if "/api" in path_lower:
        return "api"

    if any(word in path_lower for word in (
        "upload",
        "file"
    )):
        return "upload"

    if any(word in path_lower for word in (
        "account",
        "profile",
        "user"
    )):
        return "account"

    if any(word in path_lower for word in (
        "register",
        "signup",
        "sign-up"
    )):
        return "registration"

    return "general"

# SECURITY HEADERS

def analyze_security_headers(headers):
    """
    Collect important HTTP security headers.
    """

    header_mapping = {
        "content-security-policy":
            "content_security_policy",

        "strict-transport-security":
            "strict_transport_security",

        "x-frame-options":
            "x_frame_options",

        "x-content-type-options":
            "x_content_type_options",

        "referrer-policy":
            "referrer_policy",

        "permissions-policy":
            "permissions_policy"
    }

    security_headers = {}

    for header_name, field_name in header_mapping.items():

        value = headers.get(
            header_name
        )

        if value:

            security_headers[field_name] = {
                "present": True,
                "value": value
            }

        else:

            security_headers[field_name] = {
                "present": False,
                "value": None
            }

    return security_headers

# FORM ANALYSIS

def analyze_forms(
    html,
    current_url,
    target_hostname
):
    """
    Collect information about forms without submitting them.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    forms = []

    for form in soup.find_all("form"):

        action = form.get(
            "action",
            ""
        ).strip()

        method = form.get(
            "method",
            "GET"
        ).upper()

        if action:

            action_url = urljoin(
                current_url,
                action
            )

        else:

            action_url = current_url

        action_url, _ = urldefrag(
            action_url
        )

        parsed_action = urlparse(
            action_url
        )

        action_type = (
            "internal"
            if parsed_action.hostname == target_hostname
            else "external"
        )

        fields = []

        for element in form.find_all([
            "input",
            "textarea",
            "select"
        ]):

            field_type = element.get(
                "type",
                element.name
            )

            field_name = element.get(
                "name"
            )

            fields.append({
                "type": field_type,
                "name": field_name
            })

        password_fields = sum(
            1
            for field in fields
            if field["type"].lower() == "password"
        )

        forms.append({
            "method": method,
            "action": action_url,
            "action_type": action_type,
            "uses_https": (
                parsed_action.scheme == "https"
            ),
            "password_fields": password_fields,
            "fields": fields
        })

    return forms

# COOKIE ANALYSIS

def analyze_cookies(response):
    """
    Collect cookie security attributes.
    """

    cookies = []

    try:

        set_cookie_headers = (
            response.headers.get_list(
                "set-cookie"
            )
        )

    except AttributeError:

        set_cookie_headers = []

    for header in set_cookie_headers:

        cookie = SimpleCookie()

        try:

            cookie.load(header)

        except Exception:

            continue

        for name, morsel in cookie.items():

            cookies.append({
                "name": name,
                "secure": bool(
                    morsel["secure"]
                ),
                "httponly": bool(
                    morsel["httponly"]
                ),
                "samesite":
                    morsel["samesite"]
                    or None,
                "domain":
                    morsel["domain"]
                    or None,
                "path":
                    morsel["path"]
                    or None
            })

    return cookies

# SCRIPT ANALYSIS

def analyze_scripts(
    html,
    current_url,
    target_hostname
):
    """
    Collect JavaScript source and SRI information.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    internal_scripts = []
    external_scripts = []
    script_details = []

    for script in soup.find_all(
        "script",
        src=True
    ):

        src = script.get(
            "src",
            ""
        ).strip()

        if not src:
            continue

        script_url = urljoin(
            current_url,
            src
        )

        script_url, _ = urldefrag(
            script_url
        )

        parsed_script = urlparse(
            script_url
        )

        script_type = (
            "internal"
            if parsed_script.hostname == target_hostname
            else "external"
        )

        script_info = {
            "url": script_url,
            "type": script_type,
            "domain": parsed_script.hostname,
            "async": script.has_attr("async"),
            "defer": script.has_attr("defer"),
            "sri": bool(
                script.get("integrity")
            )
        }

        script_details.append(
            script_info
        )

        if script_type == "internal":

            internal_scripts.append(
                script_url
            )

        else:

            external_scripts.append(
                script_url
            )

    return {
        "internal": internal_scripts,
        "external": external_scripts,
        "details": script_details
    }

# MIXED CONTENT

def analyze_mixed_content(
    html,
    current_url
):
    """
    Find HTTP resources referenced by HTTPS pages.
    """

    parsed_page = urlparse(
        current_url
    )

    if parsed_page.scheme != "https":

        return {
            "detected": False,
            "resources": []
        }

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    resources = []

    resource_attributes = [
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("audio", "src"),
        ("video", "src"),
        ("source", "src"),
        ("object", "data"),
        ("embed", "src"),
        ("link", "href")
    ]

    for tag_name, attribute in resource_attributes:

        for tag in soup.find_all(
            tag_name,
            **{
                "attrs": {
                    attribute: True
                }
            }
        ):

            value = tag.get(
                attribute,
                ""
            ).strip()

            if not value:
                continue

            absolute_url = urljoin(
                current_url,
                value
            )

            parsed_resource = urlparse(
                absolute_url
            )

            if parsed_resource.scheme == "http":

                resources.append(
                    absolute_url
                )

    return {
        "detected": bool(resources),
        "resources": sorted(
            set(resources)
        )
    }

# CORS

def analyze_cors(headers):
    """
    Collect CORS response headers.
    """

    origin = headers.get(
        "access-control-allow-origin"
    )

    credentials = headers.get(
        "access-control-allow-credentials"
    )

    methods = headers.get(
        "access-control-allow-methods"
    )

    allowed_headers = headers.get(
        "access-control-allow-headers"
    )

    return {
        "present": any([
            origin,
            credentials,
            methods,
            allowed_headers
        ]),

        "allow_origin": origin,

        "allow_credentials":
            credentials,

        "allow_methods":
            methods,

        "allow_headers":
            allowed_headers,

        "wildcard_origin": (
            origin.strip() == "*"
            if origin
            else False
        )
    }

# TLS CERTIFICATE

def analyze_tls(
    hostname,
    port=443
):
    """
    Collect basic TLS certificate information.
    """

    result = {
        "available": False,
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "certificate_valid": None,
        "certificate_expires": None,
        "days_until_expiry": None,
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                result["available"] = True

                result["tls_version"] = (
                    tls_socket.version()
                )

                not_after = certificate.get(
                    "notAfter"
                )

                if not_after:

                    expiry = datetime.strptime(
                        not_after,
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    result[
                        "certificate_expires"
                    ] = expiry.isoformat()

                    days_left = (
                        expiry
                        - datetime.utcnow()
                    ).days

                    result[
                        "days_until_expiry"
                    ] = days_left

                    result[
                        "certificate_valid"
                    ] = days_left >= 0

    except ssl.SSLCertVerificationError as error:

        result["error"] = (
            "Certificate verification failed: "
            f"{error}"
        )

        result["certificate_valid"] = False

    except Exception as error:

        result["error"] = str(error)

    return result

# HTTP -> HTTPS
def analyze_http_redirect(
    client,
    https_url
):
    """
    Check HTTP to HTTPS behavior.
    """

    parsed = urlparse(
        https_url
    )

    if parsed.scheme != "https":

        return {
            "tested": False,
            "http_url": None,
            "status_code": None,
            "location": None,
            "redirects_to_https": None,
            "error": None
        }

    http_url = (
        f"http://{parsed.hostname}"
    )

    if parsed.port and parsed.port != 443:

        http_url += (
            f":{parsed.port}"
        )

    if parsed.path:

        http_url += parsed.path

    if parsed.query:

        http_url += (
            f"?{parsed.query}"
        )

    try:

        response = client.get(
            http_url,
            follow_redirects=False
        )

        location = response.headers.get(
            "location"
        )

        redirects_to_https = False

        if location:

            redirect_url = urljoin(
                http_url,
                location
            )

            redirects_to_https = (
                urlparse(
                    redirect_url
                ).scheme == "https"
            )

        return {
            "tested": True,
            "http_url": http_url,
            "status_code": response.status_code,
            "location": location,
            "redirects_to_https":
                redirects_to_https,
            "error": None
        }

    except httpx.RequestError as error:

        return {
            "tested": True,
            "http_url": http_url,
            "status_code": None,
            "location": None,
            "redirects_to_https": None,
            "error": str(error)
        }

# SERVER INFORMATION

def analyze_server_information(headers):
    """
    Collect server and technology information exposed
    through HTTP response headers.
    """

    server = headers.get(
        "server"
    )

    powered_by = headers.get(
        "x-powered-by"
    )

    framework_headers = {}

    interesting_headers = [
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-varnish",
        "via"
    ]

    for header_name in interesting_headers:

        value = headers.get(
            header_name
        )

        if value:

            framework_headers[
                header_name
            ] = value

    return {
        "server": server,
        "x_powered_by": powered_by,
        "technology_headers":
            framework_headers
    }

# HTML TECHNOLOGY INDICATORS

def analyze_technology_indicators(html):
    """
    Look for technology information explicitly exposed
    in HTML metadata.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    generator = None

    generator_tag = soup.find(
        "meta",
        attrs={
            "name": lambda value:
                value and value.lower()
                == "generator"
        }
    )

    if generator_tag:

        generator = generator_tag.get(
            "content"
        )

    title = None

    if soup.title:

        title = soup.title.get_text(
            strip=True
        )

    return {
        "generator": generator,
        "title": title
    }

# ROBOTS.TXT

def analyze_robots(
    client,
    base_url
):
    """
    Retrieve and inspect robots.txt.

    This is a normal public resource and is not a
    vulnerability probe.
    """

    parsed = urlparse(
        base_url
    )

    robots_url = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}/robots.txt"
    )

    result = {
        "url": robots_url,
        "available": False,
        "status_code": None,
        "disallowed_paths": [],
        "sitemap_urls": [],
        "error": None
    }

    try:

        response = client.get(
            robots_url
        )

        result[
            "status_code"
        ] = response.status_code

        if response.status_code != 200:

            return result

        result[
            "available"
        ] = True

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            lower_line = line.lower()

            if lower_line.startswith(
                "disallow:"
            ):

                path = line.split(
                    ":",
                    1
                )[1].strip()

                if path:

                    result[
                        "disallowed_paths"
                    ].append(path)

            elif lower_line.startswith(
                "sitemap:"
            ):

                sitemap = line.split(
                    ":",
                    1
                )[1].strip()

                if sitemap:

                    result[
                        "sitemap_urls"
                    ].append(sitemap)

    except httpx.RequestError as error:

        result["error"] = str(error)

    return result

# SITEMAP

def analyze_sitemap(
    client,
    sitemap_url
):
    """
    Inspect a publicly referenced sitemap.

    Sitemap URLs are recorded but are not automatically
    crawled in V3.5.
    """

    result = {
        "url": sitemap_url,
        "available": False,
        "status_code": None,
        "urls": [],
        "error": None
    }

    try:

        response = client.get(
            sitemap_url
        )

        result[
            "status_code"
        ] = response.status_code

        if response.status_code != 200:

            return result

        result[
            "available"
        ] = True

        soup = BeautifulSoup(
            response.text,
            "xml"
        )

        for location in soup.find_all(
            "loc"
        ):

            url = location.get_text(
                strip=True
            )

            if url:

                result[
                    "urls"
                ].append(url)

    except Exception as error:

        result["error"] = str(error)

    return result

# SENSITIVE URL PARAMETERS

def analyze_sensitive_parameters(url):
    """
    Identify sensitive-looking parameter names in
    already discovered URLs.

    No values are submitted or modified.
    """

    parsed = urlparse(url)

    sensitive_names = {
        "token",
        "access_token",
        "auth",
        "authorization",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "key",
        "debug",
        "redirect",
        "return",
        "url",
        "file",
        "path"
    }

    findings = []

    for parameter in parsed.query.split("&"):

        if "=" in parameter:

            name, _ = parameter.split(
                "=",
                1
            )

        else:

            name = parameter

        name = name.strip().lower()

        if name in sensitive_names:

            findings.append(name)

    return sorted(
        set(findings)
    )

# DIRECTORY LISTING

def detect_directory_listing(
    html,
    current_url
):
    """
    Detect common indicators of directory listing pages.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    title = ""

    if soup.title:

        title = soup.title.get_text(
            " ",
            strip=True
        ).lower()

    page_text = soup.get_text(
        " ",
        strip=True
    ).lower()

    indicators = []

    if "index of /" in title:

        indicators.append(
            "Index of title"
        )

    if "index of /" in page_text:

        indicators.append(
            "Index of text"
        )

    if "parent directory" in page_text:

        indicators.append(
            "Parent Directory"
        )

    return {
        "detected": bool(indicators),
        "indicators": indicators
    }

# ERROR / STACK TRACE INDICATORS

def detect_error_indicators(html):
    """
    Look for common verbose error or stack trace
    indicators in the response body.

    This does not trigger an error.
    """

    text = html.lower()

    indicators = []

    patterns = {
        "python traceback":
            "traceback (most recent call last)",

        "php error":
            "fatal error:",

        "php warning":
            "warning:",

        "java exception":
            "java.lang.",

        "stack trace":
            "stack trace:",

        "asp.net error":
            "server error in '/' application",

        "node.js error":
            "node.js v",

        "sql error":
            "sql syntax"
    }

    for name, pattern in patterns.items():

        if pattern in text:

            indicators.append(name)

    return {
        "detected": bool(indicators),
        "indicators": indicators
    }

# HTML COMMENTS

def analyze_html_comments(html):
    """
    Collect HTML comments that may contain useful
    information for later analysis.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    comments = []

    for comment in soup.find_all(
        string=lambda text:
            text and text.__class__.__name__
            == "Comment"
    ):

        value = str(comment).strip()

        if value:

            comments.append(value)

    return comments

# EXPOSED PATHS

def identify_interesting_paths(
    urls
):
    """
    Identify security-relevant paths that were already
    discovered naturally during crawling.
    """

    keywords = [
        "admin",
        "login",
        "signin",
        "auth",
        "account",
        "upload",
        "backup",
        "config",
        "debug",
        "api",
        "internal",
        "private",
        "test",
        "dev",
        "staging",
        "database",
        "phpinfo"
    ]

    interesting = []

    for url in urls:

        path = urlparse(
            url
        ).path.lower()

        matched_keywords = [
            keyword
            for keyword in keywords
            if keyword in path
        ]

        if matched_keywords:

            interesting.append({
                "url": url,
                "keywords":
                    matched_keywords
            })

    return interesting

# MAIN CRAWLER

def crawl_website(
    start_url,
    max_pages=MAX_PAGES
):

    result = {

        "success": False,

        "start_url":
            start_url,

        "final_start_url":
            None,

        "pages": {},

        "visited":
            set(),

        "external_links":
            set(),

        "failed_pages":
            {},

        "total_anchor_tags":
            0,

        "website_graph":
            {},

        "http_redirect":
            None,

        "tls":
            None,

        "robots":
            None,

        "sitemap":
            None,

        "interesting_paths":
            [],

        "max_pages":
            max_pages,

        "error":
            None
    }

    start_url = normalize_url(
        start_url
    )

    queue = deque([
        (
            start_url,
            None,
            0
        )
    ])

    try:

        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent":
                    "WebSentinel/1.0 "
                    "Educational Security Crawler"
            }
        ) as client:

            # -------------------------------------------------
            # HTTP -> HTTPS
            # -------------------------------------------------

            if urlparse(
                start_url
            ).scheme == "https":

                result[
                    "http_redirect"
                ] = analyze_http_redirect(
                    client,
                    start_url
                )

            # -------------------------------------------------
            # ROBOTS.TXT
            # -------------------------------------------------

            result[
                "robots"
            ] = analyze_robots(
                client,
                start_url
            )

            # -------------------------------------------------
            # SITEMAP
            # -------------------------------------------------

            sitemap_urls = (
                result["robots"][
                    "sitemap_urls"
                ]
            )

            if sitemap_urls:

                result[
                    "sitemap"
                ] = analyze_sitemap(
                    client,
                    sitemap_urls[0]
                )

            else:

                parsed_start = urlparse(
                    start_url
                )

                default_sitemap = (
                    f"{parsed_start.scheme}://"
                    f"{parsed_start.netloc}"
                    f"/sitemap.xml"
                )

                result[
                    "sitemap"
                ] = analyze_sitemap(
                    client,
                    default_sitemap
                )

            # -------------------------------------------------
            # CRAWLING
            # -------------------------------------------------

            while (
                queue
                and len(result["visited"])
                < max_pages
            ):

                current_url, parent_url, depth = (
                    queue.popleft()
                )

                current_url = normalize_url(
                    current_url
                )

                if current_url in result[
                    "visited"
                ]:

                    continue

                print(
                    f"\n[{len(result['visited']) + 1}/"
                    f"{max_pages}] Crawling: "
                    f"{current_url}"
                )

                result[
                    "visited"
                ].add(
                    current_url
                )

                try:

                    response = client.get(
                        current_url
                    )

                    final_url = normalize_url(
                        str(response.url)
                    )

                    if (
                        current_url == start_url
                        and
                        result[
                            "final_start_url"
                        ] is None
                    ):

                        result[
                            "final_start_url"
                        ] = final_url

                        parsed_final = urlparse(
                            final_url
                        )

                        if (
                            parsed_final.scheme
                            == "https"
                        ):

                            tls_port = (
                                parsed_final.port
                                or 443
                            )

                            result[
                                "tls"
                            ] = analyze_tls(
                                parsed_final.hostname,
                                tls_port
                            )

                    content_type = (
                        response.headers.get(
                            "content-type",
                            ""
                        )
                    )

                    parsed_current = urlparse(
                        current_url
                    )

                    route = (
                        parsed_current.path
                        or "/"
                    )

                    # -------------------------------------------------
                    # PAGE DATA
                    # -------------------------------------------------

                    page_data = {

                        "url":
                            current_url,

                        "final_url":
                            final_url,

                        "depth":
                            depth,

                        "parent_url":
                            parent_url,

                        "route":
                            route,

                        "route_category":
                            get_route_category(
                                route
                            ),

                        "status_code":
                            response.status_code,

                        "reason":
                            response.reason_phrase,

                        "content_type":
                            content_type,

                        "html_size":
                            len(response.text),

                        "anchor_tags_found":
                            0,

                        "internal_links":
                            [],

                        "external_links":
                            [],

                        "security_headers":
                            analyze_security_headers(
                                response.headers
                            ),

                        "forms":
                            [],

                        "cookies":
                            [],

                        "scripts":
                            {},

                        "https": {

                            "used":
                                parsed_current.scheme
                                == "https",

                            "scheme":
                                parsed_current.scheme
                        },

                        "mixed_content": {

                            "detected":
                                False,

                            "resources":
                                []
                        },

                        "cors": {

                            "present":
                                False,

                            "allow_origin":
                                None,

                            "allow_credentials":
                                None,

                            "allow_methods":
                                None,

                            "allow_headers":
                                None,

                            "wildcard_origin":
                                False
                        },

                        "redirects":
                            [],

                        # V3.5
                        "server_information":
                            analyze_server_information(
                                response.headers
                            ),

                        "technology_indicators":
                            {},

                        "sensitive_parameters":
                            [],

                        "directory_listing":
                            {
                                "detected": False,
                                "indicators": []
                            },

                        "error_indicators":
                            {
                                "detected": False,
                                "indicators": []
                            },

                        "html_comments":
                            []
                    }

                    # -------------------------------------------------
                    # REDIRECT HISTORY
                    # -------------------------------------------------

                    for redirect in response.history:

                        page_data[
                            "redirects"
                        ].append({

                            "status_code":
                                redirect.status_code,

                            "from":
                                normalize_url(
                                    str(
                                        redirect.url
                                    )
                                ),

                            "location":
                                redirect.headers.get(
                                    "location"
                                )
                        })

                    # HTTP ERROR-

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

                    # NON HTML
                    
                    if (
                        "text/html"
                        not in content_type.lower()
                    ):

                        page_data[
                            "error"
                        ] = "Non-HTML response"

                        result[
                            "pages"
                        ][current_url] = page_data

                        print(
                            "    SKIPPED: "
                            "Non-HTML response"
                        )

                        continue

                    target_hostname = urlparse(
                        final_url
                    ).hostname

                    # LINKS


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

                    result[
                        "total_anchor_tags"
                    ] += anchor_count
                    # WEBSITE GRAPH
                    result[
                        "website_graph"
                    ][current_url] = {

                        "parent":
                            parent_url,

                        "depth":
                            depth,

                        "children":
                            internal_links
                    }
                    # V3.3

                    page_data[
                        "forms"
                    ] = analyze_forms(
                        response.text,
                        final_url,
                        target_hostname
                    )

                    page_data[
                        "cookies"
                    ] = analyze_cookies(
                        response
                    )

                    page_data[
                        "scripts"
                    ] = analyze_scripts(
                        response.text,
                        final_url,
                        target_hostname
                    )

                    # V3.4

                    page_data[
                        "mixed_content"
                    ] = analyze_mixed_content(
                        response.text,
                        final_url
                    )

                    page_data[
                        "cors"
                    ] = analyze_cors(
                        response.headers
                    )
                    # V3.5

                    page_data[
                        "technology_indicators"
                    ] = analyze_technology_indicators(
                        response.text
                    )

                    page_data[
                        "sensitive_parameters"
                    ] = analyze_sensitive_parameters(
                        final_url
                    )

                    page_data[
                        "directory_listing"
                    ] = detect_directory_listing(
                        response.text,
                        final_url
                    )

                    page_data[
                        "error_indicators"
                    ] = detect_error_indicators(
                        response.text
                    )

                    page_data[
                        "html_comments"
                    ] = analyze_html_comments(
                        response.text
                    )

                    # STORE PAGE

                    result[
                        "pages"
                    ][current_url] = page_data

                    # EXTERNAL LINKS

                    result[
                        "external_links"
                    ].update(
                        external_links
                    )

                    # QUEUE INTERNAL LINKS

                    for link in internal_links:

                        if (
                            link
                            not in result[
                                "visited"
                            ]

                            and

                            not is_url_in_queue(
                                queue,
                                link
                            )
                        ):

                            if (
                                len(
                                    result[
                                        "visited"
                                    ]
                                )
                                +
                                len(queue)
                                <
                                max_pages
                            ):

                                queue.append(
                                    (
                                        link,
                                        current_url,
                                        depth + 1
                                    )
                                )

                    print(
                        f"    SUCCESS: "
                        f"{len(internal_links)} "
                        f"internal links, "
                        f"{len(external_links)} "
                        f"external links"
                    )

                except httpx.RequestError as error:

                    result[
                        "failed_pages"
                    ][current_url] = str(error)

                    print(
                        f"    FAILED: {error}"
                    )

        # INTERESTING PATHS

        result[
            "interesting_paths"
        ] = identify_interesting_paths(
            result["pages"].keys()
        )

        if result["pages"]:

            result[
                "success"
            ] = True

        return result

    except Exception as error:

        result[
            "error"
        ] = str(error)

        return result

# DISPLAY RESULTS

def display_crawl_results(result):

    print("\n" + "=" * 75)

    print(
        "                 WEBSENTINEL CRAWLER V3.5"
    )

    print(
        "        Static Web Security Intelligence"
    )

    print("=" * 75)

    # TARGET
    print("\nTARGET INFORMATION")
    print("-" * 75)

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

    # HTTP -> HTTPS

    print("\nHTTP -> HTTPS")
    print("-" * 75)

    redirect = result[
        "http_redirect"
    ]

    if redirect is None:

        print(
            "Not tested "
            "(starting URL is not HTTPS)."
        )

    else:

        print(
            f"HTTP URL           : "
            f"{redirect['http_url']}"
        )

        print(
            f"Status Code        : "
            f"{redirect['status_code']}"
        )

        print(
            f"Location           : "
            f"{redirect['location']}"
        )

        print(
            f"Redirects to HTTPS : "
            f"{redirect['redirects_to_https']}"
        )

    # TLS

    print("\nTLS INFORMATION")
    print("-" * 75)

    tls = result["tls"]

    if tls is None:

        print(
            "TLS analysis not required."
        )

    else:

        print(
            f"TLS Available      : "
            f"{tls['available']}"
        )

        print(
            f"TLS Version        : "
            f"{tls['tls_version']}"
        )

        print(
            f"Certificate Valid  : "
            f"{tls['certificate_valid']}"
        )

        print(
            f"Certificate Expiry : "
            f"{tls['certificate_expires']}"
        )

        print(
            f"Days Until Expiry  : "
            f"{tls['days_until_expiry']}"
        )

    # ROBOTS

    robots = result[
        "robots"
    ]

    print("\nROBOTS.TXT")
    print("-" * 75)

    if robots:

        print(
            f"Available          : "
            f"{robots['available']}"
        )

        print(
            f"Status Code        : "
            f"{robots['status_code']}"
        )

        print(
            f"Disallowed Paths   : "
            f"{len(robots['disallowed_paths'])}"
        )

        for path in robots[
            "disallowed_paths"
        ]:

            print(
                f"    - {path}"
            )

        print(
            f"Sitemap References : "
            f"{len(robots['sitemap_urls'])}"
        )

        for sitemap in robots[
            "sitemap_urls"
        ]:

            print(
                f"    - {sitemap}"
            )

    # SITEMAP

    sitemap = result[
        "sitemap"
    ]

    print("\nSITEMAP")
    print("-" * 75)

    if sitemap:

        print(
            f"Available          : "
            f"{sitemap['available']}"
        )

        print(
            f"Status Code        : "
            f"{sitemap['status_code']}"
        )

        print(
            f"URLs Found         : "
            f"{len(sitemap['urls'])}"
        )

    # PAGES
    print("\nCRAWLED PAGES")
    print("-" * 75)

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
            f"    Depth           : "
            f"{page['depth']}"
        )

        print(
            f"    Parent          : "
            f"{page['parent_url']}"
        )

        print(
            f"    Route           : "
            f"{page['route']}"
        )

        print(
            f"    Route Category  : "
            f"{page['route_category']}"
        )

        print(
            f"    HTTP Status     : "
            f"{page['status_code']} "
            f"{page['reason']}"
        )

        print(
            f"    Final URL       : "
            f"{page['final_url']}"
        )

        print(
            f"    Response Size   : "
            f"{page['html_size']} characters"
        )

        print(
            f"    <a> Tags        : "
            f"{page['anchor_tags_found']}"
        )

        print(
            f"    Internal Links  : "
            f"{len(page['internal_links'])}"
        )

        print(
            f"    External Links  : "
            f"{len(page['external_links'])}"
        )

        # -----------------------------------------------------
        # SECURITY HEADERS
        # -----------------------------------------------------

        print("\n    SECURITY HEADERS")

        for name, data in page[
            "security_headers"
        ].items():

            if data["present"]:

                print(
                    f"        {name}: PRESENT"
                )

                print(
                    f"            Value: "
                    f"{data['value']}"
                )

            else:

                print(
                    f"        {name}: MISSING"
                )
        # FORMS

        print(
            f"\n    FORMS: "
            f"{len(page['forms'])}"
        )
        # COOKIES
        print(
            f"    COOKIES: "
            f"{len(page['cookies'])}"
        )
        # SCRIPTS
        scripts = page[
            "scripts"
        ]

        print("\n    SCRIPTS")

        print(
            f"        Internal : "
            f"{len(scripts['internal'])}"
        )

        print(
            f"        External : "
            f"{len(scripts['external'])}"
        )
        # HTTPS
        print("\n    HTTPS")

        print(
            f"        Used       : "
            f"{page['https']['used']}"
        )

        print(
            f"        Scheme     : "
            f"{page['https']['scheme']}"
        )
        # MIXED CONTENT

        mixed = page[
            "mixed_content"
        ]

        print("\n    MIXED CONTENT")

        print(
            f"        Detected : "
            f"{mixed['detected']}"
        )

        for resource in mixed[
            "resources"
        ]:

            print(
                f"        - {resource}"
            )
        # CORS
        cors = page[
            "cors"
        ]

        print("\n    CORS")

        print(
            f"        Present           : "
            f"{cors['present']}"
        )

        print(
            f"        Allow-Origin      : "
            f"{cors['allow_origin']}"
        )

        print(
            f"        Allow-Credentials : "
            f"{cors['allow_credentials']}"
        )

        print(
            f"        Wildcard Origin   : "
            f"{cors['wildcard_origin']}"
        )
        # V3.5 SERVER INFORMATION

        server_info = page[
            "server_information"
        ]

        print("\n    SERVER INFORMATION")

        print(
            f"        Server       : "
            f"{server_info['server']}"
        )

        print(
            f"        X-Powered-By : "
            f"{server_info['x_powered_by']}"
        )

        if server_info[
            "technology_headers"
        ]:

            print(
                "        Technology Headers:"
            )

            for name, value in (
                server_info[
                    "technology_headers"
                ].items()
            ):

                print(
                    f"            {name}: "
                    f"{value}"
                )
        # TECHNOLOGY INDICATORS
        technology = page[
            "technology_indicators"
        ]

        print(
            "\n    TECHNOLOGY INDICATORS"
        )

        print(
            f"        Page Title : "
            f"{technology['title']}"
        )

        print(
            f"        Generator  : "
            f"{technology['generator']}"
        )
        # SENSITIVE PARAMETERS

        print(
            "\n    SENSITIVE URL PARAMETERS"
        )

        if page[
            "sensitive_parameters"
        ]:

            for parameter in page[
                "sensitive_parameters"
            ]:

                print(
                    f"        - {parameter}"
                )

        else:

            print(
                "        None detected"
            )
        # DIRECTORY LISTING

        directory = page[
            "directory_listing"
        ]

        print(
            "\n    DIRECTORY LISTING"
        )

        print(
            f"        Detected : "
            f"{directory['detected']}"
        )

        for indicator in directory[
            "indicators"
        ]:

            print(
                f"        - {indicator}"
            )
        # ERROR INDICATORS

        errors = page[
            "error_indicators"
        ]

        print(
            "\n    ERROR INDICATORS"
        )

        print(
            f"        Detected : "
            f"{errors['detected']}"
        )

        for indicator in errors[
            "indicators"
        ]:

            print(
                f"        - {indicator}"
            )
        # HTML COMMENTS

        comments = page[
            "html_comments"
        ]

        print(
            "\n    HTML COMMENTS"
        )

        print(
            f"        Found : "
            f"{len(comments)}"
        )

        for comment in comments[:5]:

            print(
                f"        - {comment[:150]}"
            )

    # INTERESTING PATHS

    print(
        "\nINTERESTING PATHS DISCOVERED"
    )

    print("-" * 75)

    if result[
        "interesting_paths"
    ]:

        for item in result[
            "interesting_paths"
        ]:

            print(
                f"- {item['url']}"
            )

            print(
                f"  Keywords: "
                f"{', '.join(item['keywords'])}"
            )

    else:

        print(
            "No interesting paths discovered."
        )
    # WEBSITE STRUCTURE

    print("\nWEBSITE STRUCTURE")
    print("-" * 75)

    for url, page in result[
        "pages"
    ].items():

        indent = (
            "    "
            * page["depth"]
        )

        print(
            f"{indent}└── {url}"
        )

    # FAILED PAGES
    print("\nFAILED PAGES")
    print("-" * 75)

    if result[
        "failed_pages"
    ]:

        for url, reason in (
            result[
                "failed_pages"
            ].items()
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

    # ---------------------------------------------------------
    # EXTERNAL LINKS
    # ---------------------------------------------------------

    print(
        "\nEXTERNAL LINKS DISCOVERED"
    )

    print("-" * 75)

    if result[
        "external_links"
    ]:

        for index, link in enumerate(
            sorted(
                result[
                    "external_links"
                ]
            ),
            start=1
        ):

            print(
                f"{index}. {link}"
            )

    else:

        print(
            "No external links discovered."
        )

    # SUMMARY
    print("\nCRAWL SUMMARY")
    print("-" * 75)

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
        "Static Web Security Intelligence"
    )

    print(
        "Crawler Version    : V3.5"
    )

    print("=" * 75)
# PROGRAM ENTRY

if __name__ == "__main__":

    print("=" * 75)

    print(
        "                 WEBSENTINEL CRAWLER V3.5"
    )

    print(
        "        Static Web Security Intelligence"
    )

    print("=" * 75)

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