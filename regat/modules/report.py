import json
from pathlib import Path

from regat.modules.utils import safe_filename


def build_report(
    domain: str,
    timestamp: str,
    recon_data: dict,
    header_results: dict,
    dns_results: dict,
    robots_results: dict,
    fuzz_results: dict,
    ssl_results: dict,
    endpoint_results: dict,
    score_summary: dict
) -> dict:
    return {
        "tool": "REGAT",
        "version": "1.1.0",
        "authorized_use_only": True,
        "domain": domain,
        "timestamp": timestamp,
        "modules": {
            "basic_recon": recon_data,
            "header_analysis": header_results,
            "dns_enumeration": dns_results,
            "robots_sitemap_analysis": robots_results,
            "subdomain_fuzzing": fuzz_results,
            "ssl_tls_inspection": ssl_results,
            "endpoint_discovery": endpoint_results
        },
        "exposure_summary": score_summary
    }


def save_json_report(report: dict, output_dir: str = "reports") -> str:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    domain = report.get("domain", "unknown")
    timestamp = report.get("timestamp", "unknown").replace(":", "-")
    filename = f"{safe_filename(domain)}_{safe_filename(timestamp)}.json"

    full_path = output_path / filename
    with full_path.open("w", encoding="utf-8") as file_handle:
        json.dump(report, file_handle, indent=4)

    return str(full_path)