from urllib.parse import urlparse


def get_target_url():
    """Ask the user for the website URL."""

    url = input("Enter authorized target URL: ").strip()

    if not url:
        return None

    # Add HTTPS if no protocol was provided
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def validate_url(url):
    """Validate the basic structure of an HTTP/HTTPS URL."""

    if not url:
        return False

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.netloc:
            return False

        if not parsed.hostname:
            return False

        return True

    except Exception:
        return False


def parse_target(url):
    """Extract structured information from the target URL."""

    parsed = urlparse(url)

    return {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port
    }