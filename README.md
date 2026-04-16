# REGAT – Reconnaissance Automation Tool

REGAT is a Python-based CLI tool designed to automate **early-stage web application reconnaissance** for authorized security assessments. It consolidates multiple reconnaissance techniques into a unified workflow to identify exposed assets, misconfigurations, and attack surface indicators.

> ⚠️ This tool is intended for **authorized use only** in environments where explicit permission has been granted.

---

## Features

- Domain reconnaissance and reachability checks  
- Security header analysis  
- DNS enumeration (A, AAAA, MX, NS, TXT, CNAME)  
- robots.txt and sitemap.xml analysis  
- Multithreaded subdomain fuzzing  
- SSL/TLS certificate inspection  
- Endpoint discovery using customizable wordlists  
- Heuristic-based exposure scoring  
- Structured JSON report export  
- Installable CLI tool (`regat -h`)  

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/cybxrghoul/REGAT.git
cd REGAT
```

### 2. Create a virtual environment
Windows (Powershell):
```bash
python -m venv venv
venv\Scripts\Activate
```
Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install the tool
```bash
pip install -e .
```
### 4. Usage
Basic scan:
```bash
regat example.com
```

Custom thread count:
```bash
regat example.com --threads 30
```

Custom timeout:
```bash 
regat example.com --timeout 3
```

Custom subdomain wordlist:
```bash
regat example.com --wordlist wordlists/subdomains.txt
```

Custom endpoint wordlist:
```bash
regat example.com --endpoint-wordlist wordlists/endpoints.txt
```

JSON-only output:
```bash
regat example.com --json-only
```

Version check:
```bash
regat --version
```
