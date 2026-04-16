import socket

try:
    import dns.resolver
except ImportError:
    dns = None


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def enumerate_dns(domain: str) -> dict:
    result = {
        "domain": domain,
        "records": {},
        "findings": []
    }

    if dns is None:
        result["findings"].append({
            "severity": "LOW",
            "title": "dnspython not installed",
            "details": "DNS enumeration is limited. Install dnspython for complete results."
        })
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            values = [str(rdata).strip() for rdata in answers]
            result["records"][record_type] = values
        except Exception:
            result["records"][record_type] = []

    try:
        ips = socket.gethostbyname_ex(domain)[2]
        if ips and len(ips) > 1:
            result["findings"].append({
                "severity": "INFO",
                "title": "Multiple IP addresses resolved",
                "details": f"The domain resolves to multiple IPs: {', '.join(ips)}"
            })
    except socket.gaierror:
        pass

    if result["records"].get("TXT"):
        result["findings"].append({
            "severity": "INFO",
            "title": "TXT records discovered",
            "details": "TXT records may reveal SPF, verification, or service metadata."
        })

    if result["records"].get("MX"):
        result["findings"].append({
            "severity": "INFO",
            "title": "Mail infrastructure discovered",
            "details": "MX records were found for the target domain."
        })

    return result