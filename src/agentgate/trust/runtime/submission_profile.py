from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.platform_integrations import (
    infer_platform_integrations,
    issue_platform_credentials,
    platform_allow_domains,
    resolve_platform_sandboxes,
)

_HTTP_HINTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bfastapi\b", re.IGNORECASE),
    re.compile(r"\bflask\b", re.IGNORECASE),
    re.compile(r"\buvicorn\b", re.IGNORECASE),
    re.compile(r"\bexpress\b", re.IGNORECASE),
    re.compile(r"\bapp\.listen\s*\(", re.IGNORECASE),
    re.compile(r"\bopenapi\b", re.IGNORECASE),
    re.compile(r"\bhttp://", re.IGNORECASE),
)
_PORT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"EXPOSE\s+(\d+)", re.IGNORECASE),
    re.compile(r"\bPORT\s*=\s*[\"']?(\d+)", re.IGNORECASE),
    re.compile(r"\bport\s*[:=]\s*(\d+)", re.IGNORECASE),
)
_PROBE_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/openapi\.json", re.IGNORECASE), "/openapi.json"),
    (re.compile(r"/docs\b", re.IGNORECASE), "/docs"),
    (re.compile(r"/health\b", re.IGNORECASE), "/health"),
    (re.compile(r"/healthz\b", re.IGNORECASE), "/healthz"),
    (re.compile(r"/api/v1/chat\b", re.IGNORECASE), "/api/v1/chat"),
    (re.compile(r"/chat\b", re.IGNORECASE), "/chat"),
    (re.compile(r"/search\b", re.IGNORECASE), "/search"),
    (re.compile(r"/query\b", re.IGNORECASE), "/query"),
)
_INTEGRATION_ROUTE_HINTS: dict[str, tuple[tuple[re.Pattern[str], str], ...]] = {
    "slack": (
        (re.compile(r"/slack/events\b", re.IGNORECASE), "/slack/events"),
        (re.compile(r"/api/slack/events\b", re.IGNORECASE), "/api/slack/events"),
        (re.compile(r"/webhooks/slack\b", re.IGNORECASE), "/webhooks/slack"),
        (re.compile(r"/slack/commands?\b", re.IGNORECASE), "/slack/commands"),
        (re.compile(r"/slack/interactivity\b", re.IGNORECASE), "/slack/interactivity"),
    ),
    "shopify": (
        (re.compile(r"/shopify/webhooks\b", re.IGNORECASE), "/shopify/webhooks"),
        (re.compile(r"/api/shopify/webhooks\b", re.IGNORECASE), "/api/shopify/webhooks"),
        (re.compile(r"/webhooks/shopify\b", re.IGNORECASE), "/webhooks/shopify"),
        (re.compile(r"/shopify/orders\b", re.IGNORECASE), "/shopify/orders"),
    ),
}


@dataclass
class SubmissionSupportAssessment:
    supported: bool = True
    status: str = "supported"
    reason: str = ""
    detail: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class GeneratedRuntimeProfile:
    build_strategy: str = "dockerfile"
    dockerfile_path: str = ""
    entrypoint: str = ""
    http_supported: bool = False
    port_candidates: list[int] = field(default_factory=list)
    probe_paths: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    runtime_env_keys: list[str] = field(default_factory=list)
    integrations: list[str] = field(default_factory=list)
    unsupported_integrations: list[str] = field(default_factory=list)
    issued_integrations: list[str] = field(default_factory=list)
    integration_sandboxes: list[dict[str, object]] = field(default_factory=list)
    integration_routes: dict[str, list[str]] = field(default_factory=dict)
    allow_domains: list[str] = field(default_factory=list)
    issued_runtime_env: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def build_submission_profile(
    *,
    source_dir: Path | None,
    manifest: dict | None,
    dependencies: list[DependencySpec],
    runtime_env: dict[str, str],
    enforce_production_contract: bool = True,
) -> tuple[SubmissionSupportAssessment, GeneratedRuntimeProfile]:
    profile = GeneratedRuntimeProfile(
        dependencies=[dependency.service for dependency in dependencies],
        runtime_env_keys=sorted(runtime_env),
    )
    assessment = SubmissionSupportAssessment()

    if source_dir is None or not source_dir.exists():
        if enforce_production_contract:
            assessment.supported = False
            assessment.status = "unsupported_build"
            assessment.reason = "source_missing"
            assessment.detail = "Production source submission scans require a source directory."
        else:
            assessment.status = "best_effort_source"
            assessment.detail = "No source directory was provided for source profiling."
        return assessment, profile

    dockerfile = source_dir / "Dockerfile"
    docker_text = ""
    if not dockerfile.exists():
        if enforce_production_contract:
            assessment.supported = False
            assessment.status = "unsupported_build"
            assessment.reason = "dockerfile_missing"
            assessment.detail = "Production source submission scans require a Dockerfile."
            return assessment, profile
        assessment.status = "best_effort_source"
        assessment.notes.append("Dockerfile not found; build/deploy validation was skipped.")
    else:
        profile.dockerfile_path = str(dockerfile)
        docker_text = _safe_read_text(dockerfile)

    profile.entrypoint = _infer_entrypoint(docker_text, manifest)
    profile.port_candidates = _infer_ports(source_dir, docker_text)
    profile.probe_paths = _infer_probe_paths(source_dir, docker_text, manifest)
    profile.http_supported = _infer_http_supported(source_dir, docker_text, manifest)
    if not profile.http_supported and enforce_production_contract:
        assessment.supported = False
        assessment.status = "unsupported_runtime_shape"
        assessment.reason = "http_not_detected"
        assessment.detail = "v1 only supports HTTP agents that expose a reachable API."
    elif not profile.http_supported:
        assessment.notes.append("HTTP service shape was not confidently inferred from source.")

    integrations, unsupported_integrations, integration_notes = infer_platform_integrations(
        source_dir=source_dir,
        manifest=manifest,
    )
    profile.integrations = integrations
    profile.unsupported_integrations = unsupported_integrations
    profile.notes.extend(integration_notes)
    profile.integration_routes = _infer_integration_routes(
        source_dir=source_dir,
        docker_text=docker_text,
        manifest=manifest,
        integrations=integrations,
    )

    if unsupported_integrations and assessment.supported and enforce_production_contract:
        assessment.supported = False
        assessment.status = "unsupported_integration"
        assessment.reason = "unsupported_integration"
        assessment.detail = "Unsupported external integrations: " + ", ".join(
            sorted(unsupported_integrations)
        )
    elif unsupported_integrations:
        assessment.notes.append(
            "Unsupported external integrations were inferred: "
            + ", ".join(sorted(unsupported_integrations))
        )

    issued_env, issued_integrations, missing_integrations = issue_platform_credentials(integrations)
    profile.issued_runtime_env = issued_env
    profile.issued_integrations = issued_integrations
    profile.integration_sandboxes = [
        {
            "name": status.name,
            "sandbox_kind": status.sandbox_kind,
            "ready": status.ready,
            "target": status.target,
            "injected_env_keys": list(status.injected_env_keys),
            "allow_domains": list(status.allow_domains),
            "capabilities": list(status.capabilities),
            "notes": list(status.notes),
        }
        for status in resolve_platform_sandboxes(integrations)
    ]
    profile.allow_domains = sorted(platform_allow_domains(issued_integrations, issued_env))

    if missing_integrations and assessment.supported and enforce_production_contract:
        assessment.supported = False
        assessment.status = "unsupported_integration"
        assessment.reason = "platform_credentials_unavailable"
        assessment.detail = "Platform-issued credentials are unavailable for: " + ", ".join(
            sorted(missing_integrations)
        )
    elif missing_integrations:
        assessment.notes.append(
            "Platform-issued credentials were unavailable for: "
            + ", ".join(sorted(missing_integrations))
        )

    profile.notes.append(
        "Generated runtime profile from source, Dockerfile, inferred dependencies, and platform integration catalog."
    )
    return assessment, profile


def _infer_entrypoint(docker_text: str, manifest: dict | None) -> str:
    if isinstance(manifest, dict):
        entrypoint = manifest.get("entrypoint")
        if isinstance(entrypoint, str) and entrypoint.strip():
            return entrypoint.strip()
    for token in ("CMD", "ENTRYPOINT"):
        match = re.search(rf"^{token}\s+(.+)$", docker_text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _infer_ports(source_dir: Path, docker_text: str) -> list[int]:
    found: list[int] = []
    for pattern in _PORT_PATTERNS:
        for text in (
            docker_text,
            *(
                _safe_read_text(path)
                for path in source_dir.rglob("*")
                if path.is_file()
                and path.name
                in {
                    "Dockerfile",
                    "docker-compose.yml",
                    "docker-compose.yaml",
                    "compose.yml",
                    "compose.yaml",
                }
            ),
        ):
            if not text:
                continue
            for match in pattern.findall(text):
                try:
                    port = int(match)
                except ValueError:
                    continue
                if port not in found:
                    found.append(port)
    if not found:
        found.extend([8000, 8080, 3000])
    return found[:5]


def _infer_probe_paths(source_dir: Path, docker_text: str, manifest: dict | None) -> list[str]:
    paths: list[str] = ["/", "/docs", "/openapi.json"]
    if isinstance(manifest, dict):
        declared = manifest.get("runtime_entrypoints")
        if isinstance(declared, list):
            for item in declared:
                if isinstance(item, str) and item.startswith("/") and item not in paths:
                    paths.append(item)
    for text in [docker_text] + [
        _safe_read_text(path) for path in source_dir.rglob("*") if path.is_file()
    ]:
        if not text:
            continue
        for pattern, value in _PROBE_HINTS:
            if pattern.search(text) and value not in paths:
                paths.append(value)
    return paths[:8]


def _infer_http_supported(source_dir: Path, docker_text: str, manifest: dict | None) -> bool:
    if isinstance(manifest, dict):
        entrypoint = str(manifest.get("entrypoint") or "").lower()
        if entrypoint.endswith(".py") or "uvicorn" in entrypoint or "gunicorn" in entrypoint:
            return True
    texts = [docker_text] + [
        _safe_read_text(path) for path in source_dir.rglob("*") if path.is_file()
    ]
    return any(pattern.search(text) for text in texts if text for pattern in _HTTP_HINTS)


def _infer_integration_routes(
    *,
    source_dir: Path,
    docker_text: str,
    manifest: dict | None,
    integrations: list[str],
) -> dict[str, list[str]]:
    inferred: dict[str, list[str]] = {}

    declared_routes = {}
    if isinstance(manifest, dict):
        for key in ("integration_routes", "sandbox_routes"):
            value = manifest.get(key)
            if isinstance(value, dict):
                declared_routes.update(value)

    texts = [docker_text] + [
        _safe_read_text(path) for path in source_dir.rglob("*") if path.is_file()
    ]

    for integration in integrations:
        paths: list[str] = []
        declared = declared_routes.get(integration)
        if isinstance(declared, str) and declared.startswith("/"):
            paths.append(declared)
        elif isinstance(declared, list):
            for item in declared:
                if isinstance(item, str) and item.startswith("/") and item not in paths:
                    paths.append(item)
        elif isinstance(declared, dict):
            for item in declared.values():
                if isinstance(item, str) and item.startswith("/") and item not in paths:
                    paths.append(item)
                elif isinstance(item, list):
                    for route in item:
                        if isinstance(route, str) and route.startswith("/") and route not in paths:
                            paths.append(route)

        for text in texts:
            if not text:
                continue
            for pattern, route in _INTEGRATION_ROUTE_HINTS.get(integration, ()):
                if pattern.search(text) and route not in paths:
                    paths.append(route)

        if paths:
            inferred[integration] = paths[:6]

    return inferred


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""
