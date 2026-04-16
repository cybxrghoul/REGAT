import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(raw_input: str) -> str:
    if not raw_input or not raw_input.strip():
        raise ValueError("Domain cannot be empty.")

    candidate = raw_input.strip().lower()

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc or parsed.path

    candidate = candidate.split("/")[0].split(":")[0].strip(".")
    if candidate.startswith("www."):
        candidate = candidate[4:]

    if not DOMAIN_REGEX.match(candidate):
        raise ValueError(f"Invalid domain format: {raw_input}")

    return candidate


def ensure_reports_dir(path: str) -> Path:
    reports_dir = Path(path)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)