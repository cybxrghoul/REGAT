HEADER_WEIGHTS = {
    "Content-Security-Policy missing": 8,
    "Strict-Transport-Security missing": 8,
    "X-Frame-Options missing": 4,
    "X-Content-Type-Options missing": 4,
    "Referrer-Policy missing": 3,
    "Permissions-Policy missing": 3,
}

GENERAL_WEIGHTS = {
    "HTTP available but HTTPS unavailable": 25,
    "Header analysis failed": 8,
    "Interesting entries found in robots.txt": 6,
    "Interesting entries found in sitemap.xml": 6,
    "Wordlist not found": 3,
    "Subdomains discovered": 4,
    "SSL certificate expired": 20,
    "SSL certificate expiring soon": 10,
    "SSL handshake failed": 8,
    "Interesting endpoint exposed": 4,
    "Endpoint wordlist not found": 2,
}


def _collect_findings(*modules: dict) -> list[dict]:
    findings = []
    for module in modules:
        findings.extend(module.get("findings", []))
    return findings


def calculate_overall_risk(
    recon_data: dict,
    header_results: dict,
    dns_results: dict,
    robots_results: dict,
    fuzz_results: dict,
    ssl_results: dict,
    endpoint_results: dict
) -> dict:
    findings = _collect_findings(
        recon_data,
        header_results,
        dns_results,
        robots_results,
        fuzz_results,
        ssl_results,
        endpoint_results
    )

    if not recon_data.get("resolved_ip"):
        return {
            "score": 0,
            "risk_level": "UNSCANNABLE",
            "key_findings": [
                {
                    "severity": "INFO",
                    "title": "Exposure scoring skipped",
                    "details": "Base domain could not be resolved; the target may be invalid or unavailable."
                }
            ]
        }

    score = 0
    key_findings = []

    header_score = 0
    for finding in header_results.get("findings", []):
        title = finding.get("title", "")
        weight = HEADER_WEIGHTS.get(title, 0)
        header_score += weight
        if weight >= 8:
            key_findings.append(finding)


    header_score = min(header_score, 20)
    score += header_score

    general_score = 0
    for module in (
        recon_data,
        dns_results,
        robots_results,
        fuzz_results,
        ssl_results,
        endpoint_results,
    ):
        for finding in module.get("findings", []):
            title = finding.get("title", "")
            weight = GENERAL_WEIGHTS.get(title, 0)
            general_score += weight
            if weight >= 6:
                key_findings.append(finding)

    general_score = min(general_score, 40)
    score += general_score

    medium_or_higher_count = sum(
        1 for finding in findings
        if finding.get("severity") in {"MEDIUM", "HIGH"}
    )
    if medium_or_higher_count >= 4:
        score += 5

    ssl_findings = ssl_results.get("findings", [])
    ssl_valid = any(
        finding.get("title") == "SSL certificate valid"
        for finding in ssl_findings
    )
    days_remaining = ssl_results.get("days_remaining")

    if ssl_valid and days_remaining is not None:
        if days_remaining > 90:
            score -= 6
        elif days_remaining > 30:
            score -= 4

    score = max(0, min(score, 100))

    if score >= 55:
        risk_level = "ELEVATED"
    elif score >= 25:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"


    seen = set()
    unique_key_findings = []
    for finding in key_findings:
        key = (finding.get("title"), finding.get("details"))
        if key not in seen:
            seen.add(key)
            unique_key_findings.append(finding)

    return {
        "score": score,
        "risk_level": risk_level,
        "key_findings": unique_key_findings[:10]
    }