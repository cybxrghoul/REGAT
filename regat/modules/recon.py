import socket
import requests


DEFAULT_HEADERS = {
    "User-Agent": "REGAT/1.0 (Security Research Tool; Authorized Use Only)"
}


def get_basic_recon(domain: str, timeout: int = 5) -> dict:
    result = {
        "domain": domain,
        "resolved_ip": None,
        "https_status": None,
        "http_status": None,
        "final_url": None,
        "server": None,
        "https_reachable": False,
        "http_reachable": False,
        "findings": []
    }

    try:
        result["resolved_ip"] = socket.gethostbyname(domain)
    except socket.gaierror:
        result["findings"].append({
            "severity": "MEDIUM",
            "title": "DNS resolution failed",
            "details": f"Could not resolve {domain} to an IP address."
        })

    try:
        response = requests.get(
            f"https://{domain}",
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True
        )
        result["https_status"] = response.status_code
        result["https_reachable"] = True
        result["final_url"] = response.url
        result["server"] = response.headers.get("Server", "Not disclosed")
    except requests.RequestException as exc:
        result["findings"].append({
            "severity": "LOW",
            "title": "HTTPS request unsuccessful",
            "details": f"HTTPS connection could not be established: {exc}"
        })

    try:
        response = requests.get(
            f"http://{domain}",
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True
        )
        result["http_status"] = response.status_code
        result["http_reachable"] = True
    except requests.RequestException:
        pass

    if result["http_reachable"] and not result["https_reachable"]:
        result["findings"].append({
            "severity": "HIGH",
            "title": "HTTP available but HTTPS unavailable",
            "details": "The target serves HTTP but does not appear to support HTTPS."
        })

    return result