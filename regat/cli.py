#!/usr/bin/env python3
"""
REGAT - Reconnaissance Automation Tool
Authorized security assessment only.
"""

import argparse
import json
import sys

from regat.modules.utils import normalize_domain, ensure_reports_dir, current_timestamp
from regat.modules.recon import get_basic_recon
from regat.modules.headers import analyze_headers
from regat.modules.dns_enum import enumerate_dns
from regat.modules.robots import analyze_public_files
from regat.modules.fuzzing import fuzz_subdomains
from regat.modules.ssl_check import inspect_ssl_certificate
from regat.modules.endpoints import discover_endpoints
from regat.modules.scoring import calculate_overall_risk
from regat.modules.report import build_report, save_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="regat",
        description=(
            "REGAT - Reconnaissance Automation Tool\n"
            "Automates early-stage web application security assessment.\n\n"
            "Authorized use only."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "domain",
        help="Target domain (example: example.com)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Number of threads for subdomain fuzzing (default: 20)"
    )
    parser.add_argument(
        "--wordlist",
        default="wordlists/subdomains.txt",
        help="Path to subdomain wordlist"
    )
    parser.add_argument(
        "--endpoint-wordlist",
        default="wordlists/endpoints.txt",
        help="Path to endpoint wordlist"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="HTTP/DNS timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print only final JSON report summary"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="REGAT v1.1.0"
    )

    return parser.parse_args()


def print_section(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(title)
    print(f"{'=' * 70}")


def print_findings_list(items: list[dict]) -> None:
    if not items:
        print("No findings.")
        return

    for item in items:
        severity = item.get("severity", "INFO")
        title = item.get("title", "Untitled finding")
        details = item.get("details", "")
        print(f"[{severity}] {title}")
        if details:
            print(f"  -> {details}")


def main() -> int:
    args = parse_args()

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    ensure_reports_dir("reports")
    timestamp = current_timestamp()

    if not args.json_only:
        print_section("REGAT V1.1 - Reconnaissance Automation Tool")
        print("Authorized security assessment only.")
        print(f"Target: {domain}")
        print(f"Timestamp: {timestamp}")

    recon_data = get_basic_recon(domain=domain, timeout=args.timeout)
    header_results = analyze_headers(domain=domain, timeout=args.timeout)
    dns_results = enumerate_dns(domain=domain)
    robots_results = analyze_public_files(domain=domain, timeout=args.timeout)
    fuzz_results = fuzz_subdomains(
        domain=domain,
        wordlist_path=args.wordlist,
        max_workers=args.threads,
        timeout=args.timeout
    )
    ssl_results = inspect_ssl_certificate(domain=domain, timeout=args.timeout)
    endpoint_results = discover_endpoints(
        domain=domain,
        wordlist_path=args.endpoint_wordlist,
        timeout=args.timeout
    )

    score_summary = calculate_overall_risk(
        recon_data=recon_data,
        header_results=header_results,
        dns_results=dns_results,
        robots_results=robots_results,
        fuzz_results=fuzz_results,
        ssl_results=ssl_results,
        endpoint_results=endpoint_results
    )

    report = build_report(
        domain=domain,
        timestamp=timestamp,
        recon_data=recon_data,
        header_results=header_results,
        dns_results=dns_results,
        robots_results=robots_results,
        fuzz_results=fuzz_results,
        ssl_results=ssl_results,
        endpoint_results=endpoint_results,
        score_summary=score_summary
    )

    report_path = save_json_report(report=report, output_dir="reports")

    if args.json_only:
        print(json.dumps(report, indent=4))
        return 0

    print_section("Basic Reconnaissance")
    for key, value in recon_data.items():
        if key != "findings":
            print(f"{key}: {value}")
    print_findings_list(recon_data.get("findings", []))

    print_section("Header Analysis")
    print_findings_list(header_results.get("findings", []))

    print_section("DNS Enumeration")
    for key, value in dns_results.get("records", {}).items():
        print(f"{key}: {value}")
    print_findings_list(dns_results.get("findings", []))

    print_section("robots.txt / sitemap.xml Analysis")
    for file_result in robots_results.get("files_checked", []):
        print(
            f"{file_result['name']}: "
            f"reachable={file_result['reachable']}, "
            f"status={file_result['status_code']}"
        )
        interesting_lines = file_result.get("interesting_lines", [])
        if interesting_lines:
            print("  Interesting lines:")
            for line in interesting_lines[:5]:
                print(f"    - {line}")
    print_findings_list(robots_results.get("findings", []))

    print_section("Subdomain Fuzzing")
    print(f"Total discovered subdomains: {len(fuzz_results.get('discovered', []))}")
    for sub in fuzz_results.get("discovered", []):
        print(f"- {sub['subdomain']} ({sub['ip']})")
    print_findings_list(fuzz_results.get("findings", []))

    print_section("SSL/TLS Inspection")
    print(f"Certificate Found: {ssl_results.get('certificate_found')}")
    print(f"Subject: {ssl_results.get('subject')}")
    print(f"Issuer: {ssl_results.get('issuer')}")
    print(f"Valid Until: {ssl_results.get('not_after')}")
    print(f"Days Remaining: {ssl_results.get('days_remaining')}")
    print_findings_list(ssl_results.get("findings", []))

    print_section("Endpoint Discovery")
    print(f"Total interesting endpoints: {len(endpoint_results.get('discovered', []))}")
    for item in endpoint_results.get("discovered", []):
        line = f"- {item['path']} -> HTTP {item['status_code']}"
        if item.get("location"):
            line += f" | Redirect: {item['location']}"
        print(line)
    print_findings_list(endpoint_results.get("findings", []))

    print_section("Exposure Summary")
    print(f"Score: {score_summary['score']}/100")
    print(f"Exposure Level: {score_summary['risk_level']}")
    print("Note: This score reflects reconnaissance indicators and missing controls, not confirmed exploitable vulnerabilities.")
    print_findings_list(score_summary.get("key_findings", []))

    print_section("Report Saved")
    print(f"JSON report: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())