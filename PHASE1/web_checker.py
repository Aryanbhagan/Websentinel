import socket
import time
import httpx


def resolve_hostname(hostname):
    """
    Check whether the hostname can be resolved through DNS.
    """

    result = {
        "resolved": False,
        "ip_addresses": [],
        "error": None
    }

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None
        )

        ip_addresses = set()

        for address in addresses:
            ip_addresses.add(address[4][0])

        result["resolved"] = True
        result["ip_addresses"] = sorted(ip_addresses)

    except socket.gaierror:
        result["error"] = (
            "Hostname could not be resolved through DNS."
        )

    except Exception as error:
        result["error"] = (
            f"DNS resolution error: {error}"
        )

    return result


def check_website(url, hostname):
    """
    Perform DNS resolution and, if successful,
    collect basic HTTP information.
    """

    result = {
        "server_connection": False,
        "page_available": False,

        "status_code": None,
        "reason": None,

        "response_time": None,
        "content_type": None,
        "server": None,

        "redirected": False,
        "final_url": None,

        "error": None
    }

    # -------------------------------------------------
    # STEP 1: DNS RESOLUTION
    # -------------------------------------------------

    dns_result = resolve_hostname(hostname)

    result["dns_resolved"] = dns_result["resolved"]
    result["ip_addresses"] = dns_result["ip_addresses"]
    result["dns_error"] = dns_result["error"]

    # If DNS fails, do NOT attempt HTTP
    if not result["dns_resolved"]:
        result["error"] = (
            "Hostname could not be resolved. "
            "HTTP connection was not attempted."
        )

        return result

    # -------------------------------------------------
    # STEP 2: SERVER CONNECTION
    # -------------------------------------------------

    try:
        start_time = time.perf_counter()

        with httpx.Client(
            follow_redirects=True,
            timeout=10.0
        ) as client:

            response = client.get(
                url,
                headers={
                    "User-Agent": "WebSentinel-Phase1/0.1"
                }
            )

        end_time = time.perf_counter()

        result["server_connection"] = True

        result["status_code"] = response.status_code
        result["reason"] = response.reason_phrase

        result["response_time"] = round(
            end_time - start_time,
            3
        )

        result["content_type"] = (
            response.headers.get("content-type")
        )

        result["server"] = (
            response.headers.get("server")
        )

        result["final_url"] = str(response.url)

        if str(response.url) != url:
            result["redirected"] = True

        # 2xx = successful resource response
        if 200 <= response.status_code < 300:
            result["page_available"] = True

    except httpx.TimeoutException:
        result["error"] = (
            "The server connection timed out."
        )

    except httpx.ConnectError:
        result["error"] = (
            "The hostname resolved, but a server "
            "connection could not be established."
        )

    except httpx.RequestError as error:
        result["error"] = (
            f"HTTP request error: {error}"
        )

    except Exception as error:
        result["error"] = (
            f"Unexpected error: {error}"
        )

    return result