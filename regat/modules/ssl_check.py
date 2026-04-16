import socket
import ssl
from datetime import datetime, timezone


def inspect_ssl_certificate(domain: str, port: int = 443, timeout: int = 5) -> dict:
    result = {
        "domain": domain,
        "port": port,
        "certificate_found": False,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "findings": []
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        result["certificate_found"] = True

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        result["subject"] = subject
        result["issuer"] = issuer
        result["not_before"] = cert.get("notBefore")
        result["not_after"] = cert.get("notAfter")

        expiry_raw = cert.get("notAfter")
        if expiry_raw:
            expiry_date = datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_remaining = (expiry_date - now).days
            result["days_remaining"] = days_remaining

            if days_remaining < 0:
                result["findings"].append({
                    "severity": "HIGH",
                    "title": "SSL certificate expired",
                    "details": f"The certificate expired {abs(days_remaining)} days ago."
                })
            elif days_remaining <= 30:
                result["findings"].append({
                    "severity": "MEDIUM",
                    "title": "SSL certificate expiring soon",
                    "details": f"The certificate expires in {days_remaining} days."
                })
            else:
                result["findings"].append({
                    "severity": "INFO",
                    "title": "SSL certificate valid",
                    "details": f"The certificate is valid and expires in {days_remaining} days."
                })

    except ssl.SSLError as exc:
        result["findings"].append({
            "severity": "MEDIUM",
            "title": "SSL handshake failed",
            "details": str(exc)
        })
    except socket.timeout:
        result["findings"].append({
            "severity": "LOW",
            "title": "SSL connection timed out",
            "details": f"Connection to {domain}:{port} timed out."
        })
    except OSError as exc:
        result["findings"].append({
            "severity": "LOW",
            "title": "SSL certificate retrieval failed",
            "details": str(exc)
        })

    return result