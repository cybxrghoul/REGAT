from pathlib import Path
import requests


DEFAULT_HEADERS = {
    "User-Agent": "REGAT/1.0 (Security Research Tool; Authorized Use Only)"
}

INTERESTING_KEYWORDS = (
    "admin",
    "login",
    "dashboard",
    "portal",
    "backup",
    "config",
    "test",
    "api"
)


def discover_endpoints(
    domain: str,
    wordlist_path: str = "wordlists/endpoints.txt",
    timeout: int = 5
) -> dict:
    result = {
        "base_url": f"https://{domain}",
        "tested_count": 0,
        "discovered": [],
        "findings": []
    }

    wordlist_file = Path(wordlist_path)
    if not wordlist_file.is_file():
        result["findings"].append({
            "severity": "LOW",
            "title": "Endpoint wordlist not found",
            "details": f"Could not locate endpoint wordlist: {wordlist_path}"
        })
        return result

    with wordlist_file.open("r", encoding="utf-8") as file_handle:
        endpoints = [
            line.strip()
            for line in file_handle
            if line.strip() and not line.strip().startswith("#")
        ]

    session = requests.Session()
    result["tested_count"] = len(endpoints)

    for endpoint in endpoints:
        endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        url = f"https://{domain}{endpoint}"

        try:
            response = session.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=timeout,
                allow_redirects=False
            )

            if response.status_code in {200, 301, 302, 401, 403}:
                discovered_entry = {
                    "path": endpoint,
                    "url": url,
                    "status_code": response.status_code,
                    "location": response.headers.get("Location")
                }
                result["discovered"].append(discovered_entry)

                lowered = endpoint.lower().strip("/")
                if any(keyword in lowered for keyword in INTERESTING_KEYWORDS):
                    result["findings"].append({
                        "severity": "MEDIUM" if response.status_code == 200 else "INFO",
                        "title": "Interesting endpoint exposed",
                        "details": f"{endpoint} returned HTTP {response.status_code}."
                    })

        except requests.RequestException:
            continue

    if not result["discovered"]:
        result["findings"].append({
            "severity": "INFO",
            "title": "No interesting endpoints discovered",
            "details": "No endpoints from the provided wordlist returned notable responses."
        })

    return result