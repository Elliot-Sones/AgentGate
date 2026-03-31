from __future__ import annotations

from collections.abc import Mapping


def normalize_public_base_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    return value.rstrip("/")


def resolve_public_base_url(env: Mapping[str, str]) -> str:
    for key in (
        "AGENTGATE_PUBLIC_BASE_URL",
        "RAILWAY_SERVICE_AGENTGATE_URL",
        "RAILWAY_PUBLIC_DOMAIN",
        "RAILWAY_STATIC_URL",
    ):
        value = normalize_public_base_url(str(env.get(key, "")))
        if value:
            return value
    return ""


def build_report_url(scan_id: str, base_url: str = "") -> str:
    path = f"/v1/scans/{scan_id}/report"
    normalized_base_url = normalize_public_base_url(base_url)
    if not normalized_base_url:
        return path
    return f"{normalized_base_url}{path}"


def build_events_url(scan_id: str, base_url: str = "", *, stream: bool = False) -> str:
    path = f"/v1/scans/{scan_id}/events"
    if stream:
        path = f"{path}?stream=true"
    normalized_base_url = normalize_public_base_url(base_url)
    if not normalized_base_url:
        return path
    return f"{normalized_base_url}{path}"
