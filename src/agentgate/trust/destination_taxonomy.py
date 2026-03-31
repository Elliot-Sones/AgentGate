from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from fnmatch import fnmatch
from collections.abc import Iterable

_PACKAGE_TELEMETRY_MAP: dict[str, list[str]] = {
    "streamlit": ["browser.gatherusagestats", "*.streamlit.io"],
    "langchain": ["api.langsmith.com", "api.smith.langchain.com"],
    "langchain-core": ["api.langsmith.com", "api.smith.langchain.com"],
    "langsmith": ["api.langsmith.com", "api.smith.langchain.com"],
    "langgraph": ["api.langsmith.com"],
    "sentry-sdk": ["*.ingest.sentry.io"],
    "sentry_sdk": ["*.ingest.sentry.io"],
    "opentelemetry-sdk": ["*.otel.collector"],
    "opentelemetry-api": ["*.otel.collector"],
    "wandb": ["api.wandb.ai"],
    "datadog": ["*.datadoghq.com"],
    "dd-trace": ["*.datadoghq.com"],
    "newrelic": ["*.newrelic.com"],
    "bugsnag": ["*.bugsnag.com"],
    "segment-analytics-python": ["api.segment.io"],
    "mixpanel": ["api.mixpanel.com"],
    "posthog": ["*.posthog.com"],
}

_FRAMEWORK_TELEMETRY_PACKAGES = {
    "sentry",
    "sentry-sdk",
    "sentry_sdk",
    "streamlit",
    "wandb",
    "opentelemetry",
    "opentelemetry-sdk",
    "opentelemetry-api",
    "datadog",
    "dd-trace",
    "newrelic",
    "bugsnag",
    "segment",
    "segment-analytics-python",
    "mixpanel",
    "posthog",
}

_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_RFC4193_NETWORK = ipaddress.IPv6Network("fc00::/7")


@dataclass(slots=True)
class DestinationContext:
    destination_class: str
    matched_rule: str = ""


def build_telemetry_registry(packages: Iterable[str]) -> dict[str, str]:
    """Build a destination-pattern registry from installed package names."""

    registry: dict[str, str] = {}
    for package in packages:
        normalized = _normalize_package_name(package)
        if not normalized:
            continue

        variants = (package.strip().lower(), normalized)
        for variant in variants:
            if not variant:
                continue
            for domain_pattern in _PACKAGE_TELEMETRY_MAP.get(variant, []):
                registry.setdefault(domain_pattern.lower(), variant)
    return registry


def classify_destination(
    destination: str,
    *,
    verified_internal_ips: set[str] | None = None,
    verified_internal_domains: set[str] | None = None,
    declared_domains: set[str] | None = None,
    telemetry_registry: dict[str, str] | None = None,
) -> DestinationContext:
    """Classify a network destination using the trust taxonomy order."""

    dest = destination.strip().lower()
    if not dest:
        return DestinationContext("unknown_external", "empty destination")

    normalized_verified_ips = _normalize_text_set(verified_internal_ips)
    if dest in normalized_verified_ips:
        return DestinationContext("platform_internal_verified", f"verified IP: {dest}")

    normalized_verified_domains = _normalize_text_set(verified_internal_domains)
    for pattern in normalized_verified_domains:
        if _matches_pattern(dest, pattern):
            return DestinationContext("platform_internal_verified", f"verified domain: {pattern}")

    if _is_private_ip(dest):
        return DestinationContext("private_unattributed", f"private IP: {dest}")

    normalized_declared_domains = _normalize_text_set(declared_domains)
    for pattern in normalized_declared_domains:
        if _matches_domain(dest, pattern):
            return DestinationContext("declared_business", f"declared: {pattern}")

    if telemetry_registry:
        for pattern, package in telemetry_registry.items():
            if _matches_pattern(dest, pattern):
                destination_class = (
                    "framework_telemetry"
                    if _is_framework_telemetry_package(package)
                    else "dependency_service"
                )
                return DestinationContext(destination_class, f"package: {package}")

    return DestinationContext("unknown_external", "")


def _normalize_package_name(package: str) -> str:
    return package.strip().lower().replace("_", "-")


def _normalize_text_set(values: set[str] | None) -> set[str]:
    if not values:
        return set()
    return {str(value).strip().lower() for value in values if str(value).strip()}


def _matches_domain(destination: str, pattern: str) -> bool:
    if _matches_pattern(destination, pattern):
        return True
    if pattern.startswith("*."):
        return _matches_pattern(destination, pattern[2:])
    return destination == pattern or destination.endswith(f".{pattern}")


def _matches_pattern(destination: str, pattern: str) -> bool:
    if not pattern:
        return False
    if "*" in pattern or "?" in pattern:
        return fnmatch(destination, pattern)
    return destination == pattern


def _is_private_ip(destination: str) -> bool:
    try:
        parsed = ipaddress.ip_address(destination)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv4Address):
        return any(parsed in network for network in _RFC1918_NETWORKS)
    return parsed in _RFC4193_NETWORK


def _is_framework_telemetry_package(package: str) -> bool:
    normalized = _normalize_package_name(package)
    compact = normalized.replace("-", "")
    for indicator in _FRAMEWORK_TELEMETRY_PACKAGES:
        normalized_indicator = _normalize_package_name(indicator)
        if normalized_indicator.replace("-", "") in compact:
            return True
    return False
