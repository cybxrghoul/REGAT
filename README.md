# REGAT - Reconnaissance Automation Tool

REGAT is a Python-based CLI reconnaissance tool designed for **authorized web application security assessments**. It automates early-stage reconnaissance tasks such as DNS enumeration, HTTP security header analysis, public file inspection, multithreaded subdomain discovery, SSL/TLS certificate inspection, endpoint discovery, and structured reporting.

> REGAT is intended for defensive security testing, learning, and authorized assessment workflows only.

---

## Features

- Basic domain reconnaissance
- HTTP / HTTPS reachability checks
- Security header analysis
- DNS enumeration
  - A
  - AAAA
  - MX
  - NS
  - TXT
  - CNAME
- `robots.txt` and `sitemap.xml` inspection
- Multithreaded subdomain fuzzing
- SSL/TLS certificate inspection
- Common endpoint discovery
- Exposure scoring
- JSON report export
- Installable CLI command:
  ```bash
  regat -h

## Custom Wordlists

REGAT allows users to provide custom wordlists for subdomain and endpoint discovery.

### Subdomains
```bash
regat example.com --wordlist custom_subdomains.txt