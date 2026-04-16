import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def _resolve_subdomain(subdomain: str, timeout: int = 3) -> dict | None:
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(subdomain)
        return {
            "subdomain": subdomain,
            "ip": ip
        }
    except socket.gaierror:
        return None


def fuzz_subdomains(
    domain: str,
    wordlist_path: str = "wordlists/subdomains.txt",
    max_workers: int = 20,
    timeout: int = 3
) -> dict:
    result = {
        "wordlist_path": wordlist_path,
        "tested_count": 0,
        "discovered": [],
        "findings": []
    }

    path = Path(wordlist_path)
    if not path.is_file():
        result["findings"].append({
            "severity": "MEDIUM",
            "title": "Wordlist not found",
            "details": f"Could not locate wordlist: {wordlist_path}"
        })
        return result

    with path.open("r", encoding="utf-8") as file_handle:
        candidates = [
            f"{line.strip().lower()}.{domain}"
            for line in file_handle
            if line.strip() and not line.strip().startswith("#")
        ]

    result["tested_count"] = len(candidates)

    discovered = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_subdomain, sub, timeout): sub
            for sub in candidates
        }

        for future in as_completed(futures):
            try:
                resolved = future.result()
                if resolved:
                    discovered.append(resolved)
            except Exception:
                continue

    discovered.sort(key=lambda item: item["subdomain"])
    result["discovered"] = discovered

    if discovered:
        result["findings"].append({
            "severity": "INFO",
            "title": "Subdomains discovered",
            "details": f"{len(discovered)} active subdomains resolved from the wordlist."
        })
    else:
        result["findings"].append({
            "severity": "INFO",
            "title": "No active subdomains discovered",
            "details": "No subdomains from the provided wordlist resolved successfully."
        })

    return result