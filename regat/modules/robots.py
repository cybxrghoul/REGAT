import requests


DEFAULT_HEADERS = {
    "User-Agent": "REGAT/1.0 (Security Research Tool; Authorized Use Only)"
}

INTERESTING_KEYWORDS = (
    "admin",
    "backup",
    "private",
    "dashboard",
    "config",
    "internal",
    "test",
    "staging",
    "login"
)


def analyze_public_files(domain: str, timeout: int = 5) -> dict:
    result = {
        "files_checked": [],
        "findings": []
    }

    targets = [
        ("robots.txt", f"https://{domain}/robots.txt"),
        ("sitemap.xml", f"https://{domain}/sitemap.xml"),
    ]

    for name, url in targets:
        entry = {
            "name": name,
            "url": url,
            "reachable": False,
            "status_code": None,
            "interesting_lines": []
        }

        try:
            response = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=timeout,
                allow_redirects=True
            )
            entry["status_code"] = response.status_code
            entry["reachable"] = response.status_code == 200

            if response.status_code == 200:
                content = response.text.splitlines()

                for line in content:
                    lowered = line.strip().lower()
                    if any(keyword in lowered for keyword in INTERESTING_KEYWORDS):
                        entry["interesting_lines"].append(line.strip())

                if entry["interesting_lines"]:
                    result["findings"].append({
                        "severity": "MEDIUM",
                        "title": f"Interesting entries found in {name}",
                        "details": "Potentially sensitive paths or operational clues were exposed."
                    })
                else:
                    result["findings"].append({
                        "severity": "INFO",
                        "title": f"{name} reachable",
                        "details": f"{name} is publicly accessible."
                    })
            else:
                result["findings"].append({
                    "severity": "INFO",
                    "title": f"{name} not publicly available",
                    "details": f"{name} returned status code {response.status_code}."
                })

        except requests.RequestException as exc:
            result["findings"].append({
                "severity": "LOW",
                "title": f"Could not retrieve {name}",
                "details": str(exc)
            })

        result["files_checked"].append(entry)

    return result