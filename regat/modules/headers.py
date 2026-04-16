import requests


DEFAULT_HEADERS = {
    "User-Agent": "REGAT/1.0 (Security Research Tool; Authorized Use Only)"
}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "reason": "Helps reduce XSS and content injection risk."
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "reason": "Helps enforce HTTPS usage."
    },
    "X-Frame-Options": {
        "severity": "LOW",
        "reason": "Helps reduce clickjacking risk."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "reason": "Helps prevent MIME-type sniffing."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "reason": "Controls how referrer information is shared."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "reason": "Restricts access to sensitive browser features."
    }
}


def analyze_headers(domain: str, timeout: int = 5) -> dict:
    result = {
        "checked_url": f"https://{domain}",
        "present_headers": {},
        "missing_headers": [],
        "findings": []
    }

    try:
        response = requests.get(
            f"https://{domain}",
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            allow_redirects=True
        )
        headers = response.headers

        for header_name, metadata in SECURITY_HEADERS.items():
            if header_name in headers:
                result["present_headers"][header_name] = headers.get(header_name)
                result["findings"].append({
                    "severity": "INFO",
                    "title": f"{header_name} present",
                    "details": f"{header_name} is configured."
                })
            else:
                result["missing_headers"].append(header_name)
                result["findings"].append({
                    "severity": metadata["severity"],
                    "title": f"{header_name} missing",
                    "details": metadata["reason"]
                })

    except requests.RequestException as exc:
        result["findings"].append({
            "severity": "MEDIUM",
            "title": "Header analysis failed",
            "details": f"Unable to retrieve HTTPS headers: {exc}"
        })

    return result