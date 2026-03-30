from __future__ import annotations

import hashlib
import json
import re
import secrets
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
_DEFAULT_DOCKERFILE_CANDIDATES: tuple[str, ...] = ("Dockerfile.api", "Dockerfile")
_IGNORED_DOCKERFILE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
_COMMON_DOCKERFILE_DIRS: tuple[str, ...] = (
    "api",
    "app",
    "deploy",
    "deployment",
    "docker",
    "infra",
    "ops",
    "server",
    "services",
)
_PORT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"EXPOSE\s+(\d+)", re.IGNORECASE),
    re.compile(r"\bPORT\s*=\s*[\"']?(\d+)", re.IGNORECASE),
    re.compile(r"\bport\s*[:=]\s*(\d+)", re.IGNORECASE),
)
_PORT_FLAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"--port(?:=|\s+)(\d+)", re.IGNORECASE),
    re.compile(r"localhost:(\d+)", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1:(\d+)", re.IGNORECASE),
)
_COMPOSE_PORT_MAPPING = re.compile(
    r"^\s*-\s*[\"']?(?:\d{1,3}(?:\.\d{1,3}){3}:)?(?:\d+:)?(\d+)(?:/\w+)?[\"']?\s*$",
    re.MULTILINE,
)
_PORT_SCAN_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".js",
    ".json",
    ".mjs",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
_PORT_IGNORED_PARTS = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "docs",
    "example",
    "examples",
    "fixtures",
    "node_modules",
    "sample",
    "samples",
    "test",
    "tests",
    "venv",
}
_COMPOSE_FILE_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}
_SETTINGS_FILE_HINTS = {
    ".env",
    ".env.example",
    "config.py",
    "run_service.py",
    "settings.py",
}
_PROBE_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/openapi\.json", re.IGNORECASE), "/openapi.json"),
    (re.compile(r"/docs\b", re.IGNORECASE), "/docs"),
    (re.compile(r"/health\b", re.IGNORECASE), "/health"),
    (re.compile(r"/healthz\b", re.IGNORECASE), "/healthz"),
    (re.compile(r"/invoke\b", re.IGNORECASE), "/invoke"),
    (re.compile(r"/api/v1/chat\b", re.IGNORECASE), "/api/v1/chat"),
    (re.compile(r"/chat\b", re.IGNORECASE), "/chat"),
    (re.compile(r"/search\b", re.IGNORECASE), "/search"),
    (re.compile(r"/query\b", re.IGNORECASE), "/query"),
    (re.compile(r"/run\b", re.IGNORECASE), "/run"),
    (re.compile(r"/predict\b", re.IGNORECASE), "/predict"),
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
    auth_likely: bool = False


_AUTH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Depends\s*\(\s*(?:get_current_user|verify_token|api_key|get_api_key|authenticate|auth)", re.IGNORECASE),
    re.compile(r"@(?:login_required|requires_auth|authenticated|auth_required)", re.IGNORECASE),
    re.compile(r'request\.headers\.get\s*\(\s*["\'](?:Authorization|X-API-Key)["\']', re.IGNORECASE),
    re.compile(r"(?:jwt\.decode|jwt\.verify|oauth)", re.IGNORECASE),
    re.compile(r"(?:HTTPBearer|HTTPBasic|SecurityScopes)\s*\(", re.IGNORECASE),
]


def _detect_auth_signals(source_dir: Path) -> bool:
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for pattern in _AUTH_PATTERNS:
            if pattern.search(text):
                return True
    return False


def build_submission_profile(
    *,
    source_dir: Path | None,
    manifest: dict | None,
    dependencies: list[DependencySpec],
    runtime_env: dict[str, str],
    dockerfile_path: Path | None = None,
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

    dockerfile, dockerfile_note = _resolve_dockerfile(source_dir, dockerfile_path)
    docker_text = ""
    if dockerfile is None:
        if enforce_production_contract:
            assessment.supported = False
            assessment.status = "unsupported_build"
            assessment.reason = "dockerfile_missing"
            assessment.detail = (
                dockerfile_note or "Production source submission scans require a Dockerfile."
            )
            return assessment, profile
        assessment.status = "best_effort_source"
        assessment.notes.append(
            dockerfile_note or "Dockerfile not found; build/deploy validation was skipped."
        )
    else:
        profile.dockerfile_path = str(dockerfile)
        docker_text = _safe_read_text(dockerfile)
        if dockerfile_note:
            profile.notes.append(dockerfile_note)

    profile.entrypoint = _infer_entrypoint(docker_text, manifest)
    profile.port_candidates = _infer_ports(source_dir, docker_text, dockerfile)
    profile.probe_paths = _infer_probe_paths(source_dir, docker_text, manifest)
    profile.http_supported = _infer_http_supported(source_dir, docker_text, manifest)
    profile.auth_likely = _detect_auth_signals(source_dir)
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

    # Auto-detect env vars the agent needs and generate sandbox values for any that
    # aren't already provided by platform credentials or the caller's runtime_env.
    detected_env_vars = _detect_required_env_vars(source_dir)
    already_provided = set(runtime_env) | set(issued_env)
    sandbox_env = _generate_sandbox_env(detected_env_vars, already_provided)
    if sandbox_env:
        profile.issued_runtime_env.update(sandbox_env)
        profile.notes.append(
            f"Auto-generated sandbox values for {len(sandbox_env)} detected env var(s): "
            + ", ".join(sorted(sandbox_env))
        )

    profile.notes.append(
        "Generated runtime profile from source, Dockerfile, inferred dependencies, and platform integration catalog."
    )
    return assessment, profile


def _resolve_dockerfile(
    source_dir: Path,
    dockerfile_path: Path | None,
) -> tuple[Path | None, str]:
    source_root = source_dir.resolve()
    if dockerfile_path is not None:
        requested = dockerfile_path.resolve()
        try:
            relative = requested.relative_to(source_root)
        except ValueError:
            return None, "Requested Dockerfile must live inside the repository root."
        if requested.exists():
            if relative.as_posix() == "Dockerfile":
                return requested, ""
            return requested, f"Using requested Dockerfile '{relative.as_posix()}'."
        return None, f"Requested Dockerfile was not found: {relative.as_posix()}."

    for candidate in _DEFAULT_DOCKERFILE_CANDIDATES:
        candidate_path = source_root / candidate
        if candidate_path.exists():
            note = ""
            if candidate != "Dockerfile":
                note = f"Using fallback Dockerfile '{candidate}'."
            return candidate_path, note

    discovered = _discover_nested_dockerfile(source_root)
    if discovered is not None:
        relative = discovered.relative_to(source_root).as_posix()
        return discovered, f"Using discovered Dockerfile '{relative}'."

    supported = ", ".join(_DEFAULT_DOCKERFILE_CANDIDATES)
    return None, (
        "No supported Dockerfile was found. "
        f"Expected one of: {supported}, or a discoverable Dockerfile in a common subdirectory."
    )


def _infer_entrypoint(docker_text: str, manifest: dict | None) -> str:
    docker_entrypoint = _extract_docker_entrypoint(docker_text)
    if docker_entrypoint:
        return docker_entrypoint
    if isinstance(manifest, dict):
        entrypoint = manifest.get("entrypoint")
        if isinstance(entrypoint, str) and entrypoint.strip():
            return entrypoint.strip()
    return ""


def _extract_docker_entrypoint(docker_text: str) -> str:
    if not docker_text.strip():
        return ""

    collapsed = re.sub(r"\\\s*\n\s*", " ", docker_text)
    entrypoint = ""
    cmd = ""
    for raw_line in collapsed.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(ENTRYPOINT|CMD)\s+(.+)$", line, re.IGNORECASE)
        if not match:
            continue
        instruction = match.group(1).upper()
        value = _normalize_docker_instruction(match.group(2).strip())
        if instruction == "ENTRYPOINT":
            entrypoint = value
        else:
            cmd = value

    if entrypoint and cmd:
        return f"{entrypoint} {cmd}".strip()
    return entrypoint or cmd


_SERVICE_DOCKERFILE_HINTS = {"service", "api", "server", "backend", "worker"}
_CLIENT_DOCKERFILE_HINTS = {"app", "client", "ui", "frontend", "web", "streamlit"}


def _discover_nested_dockerfile(source_root: Path) -> Path | None:
    ranked: list[tuple[tuple[int, int, int, int, str], Path]] = []
    for path in source_root.rglob("Dockerfile*"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        if any(part in _IGNORED_DOCKERFILE_DIRS for part in relative.parts):
            continue
        first_dir = relative.parts[0] if len(relative.parts) > 1 else ""
        name_lower = path.name.lower()

        # Prefer service/api/server Dockerfiles over app/client/ui
        if any(hint in name_lower for hint in _SERVICE_DOCKERFILE_HINTS):
            name_preference = 0
        elif any(hint in name_lower for hint in _CLIENT_DOCKERFILE_HINTS):
            name_preference = 2
        elif path.name == "Dockerfile":
            name_preference = 1
        else:
            name_preference = 1

        rank = (
            0 if first_dir in _COMMON_DOCKERFILE_DIRS else 1,
            name_preference,
            len(relative.parts),
            0 if path.name == "Dockerfile" else 1,
            relative.as_posix(),
        )
        ranked.append((rank, path))

    if not ranked:
        return None

    ranked.sort(key=lambda item: item[0])
    return ranked[0][1]


def _normalize_docker_instruction(value: str) -> str:
    if not value:
        return ""
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        if isinstance(parsed, list):
            return " ".join(str(part) for part in parsed if str(part).strip())
    return value


def _infer_ports(
    source_dir: Path,
    docker_text: str,
    selected_dockerfile: Path | None = None,
) -> list[int]:
    scored: dict[int, int] = {}
    first_seen: dict[int, int] = {}
    sequence = 0
    preferred_compose_ports = _ports_for_selected_compose_service(source_dir, selected_dockerfile)

    def _record(port_text: str, weight: int) -> None:
        nonlocal sequence
        try:
            port = int(port_text)
        except ValueError:
            return
        if not 1 <= port <= 65535:
            return
        scored[port] = scored.get(port, 0) + weight
        first_seen.setdefault(port, sequence)
        sequence += 1

    for pattern in _PORT_PATTERNS + _PORT_FLAG_PATTERNS:
        for match in pattern.findall(docker_text):
            _record(match, 120)

    for port in preferred_compose_ports:
        _record(str(port), 220)

    for path in source_dir.rglob("*"):
        if not path.is_file() or not _should_scan_file_for_ports(path):
            continue

        text = _safe_read_text(path)
        if not text:
            continue

        base_weight = _port_source_weight(path)
        if path.name in _COMPOSE_FILE_NAMES and not preferred_compose_ports:
            for match in _COMPOSE_PORT_MAPPING.findall(text):
                _record(match, base_weight + 60)

        for pattern in _PORT_PATTERNS + _PORT_FLAG_PATTERNS:
            bonus = 0
            if path.name in _COMPOSE_FILE_NAMES and not preferred_compose_ports:
                bonus = 40
            elif path.name in _SETTINGS_FILE_HINTS:
                bonus = 20
            for match in pattern.findall(text):
                _record(match, base_weight + bonus)

    if not scored:
        return [8000, 8080, 3000]

    ranked = sorted(scored, key=lambda port: (-scored[port], first_seen[port], port))
    return ranked[:5]


def _should_scan_file_for_ports(path: Path) -> bool:
    if any(part.lower() in _PORT_IGNORED_PARTS for part in path.parts):
        return False
    return path.suffix.lower() in _PORT_SCAN_SUFFIXES or path.name in _COMPOSE_FILE_NAMES


def _port_source_weight(path: Path) -> int:
    name = path.name.lower()
    if name in _COMPOSE_FILE_NAMES:
        return 90
    if name.startswith("dockerfile"):
        return 80
    if name in _SETTINGS_FILE_HINTS:
        return 70
    if any(part.lower() in {"config", "configs", "core", "server", "services"} for part in path.parts):
        return 55
    return 35


def _ports_for_selected_compose_service(
    source_dir: Path,
    selected_dockerfile: Path | None,
) -> list[int]:
    if selected_dockerfile is None:
        return []
    try:
        selected_relative = selected_dockerfile.resolve().relative_to(source_dir.resolve()).as_posix()
    except ValueError:
        return []

    ports: list[int] = []
    for compose_name in _COMPOSE_FILE_NAMES:
        compose_path = source_dir / compose_name
        if not compose_path.exists():
            continue
        parsed = _safe_load_yaml_mapping(_safe_read_text(compose_path))
        services = parsed.get("services")
        if not isinstance(services, dict):
            continue
        for service in services.values():
            if not isinstance(service, dict):
                continue
            if not _compose_service_matches_dockerfile(
                service=service,
                compose_path=compose_path,
                source_dir=source_dir,
                selected_relative=selected_relative,
            ):
                continue
            for port in _extract_ports_from_compose_service(service):
                if port not in ports:
                    ports.append(port)
    return ports


def _safe_load_yaml_mapping(text: str) -> dict:
    if not text.strip():
        return {}
    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(text)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _compose_service_matches_dockerfile(
    *,
    service: dict,
    compose_path: Path,
    source_dir: Path,
    selected_relative: str,
) -> bool:
    build = service.get("build")
    if isinstance(build, str):
        return selected_relative == "Dockerfile"
    if not isinstance(build, dict):
        return False

    dockerfile_value = str(build.get("dockerfile") or "").strip()
    if not dockerfile_value:
        return selected_relative == "Dockerfile"

    context_value = str(build.get("context") or ".").strip() or "."
    candidate = Path(dockerfile_value)
    if not candidate.is_absolute():
        candidate = (compose_path.parent / context_value / candidate).resolve()
    try:
        relative = candidate.relative_to(source_dir.resolve()).as_posix()
    except ValueError:
        relative = candidate.name
    return relative == selected_relative or Path(relative).name == Path(selected_relative).name


def _extract_ports_from_compose_service(service: dict) -> list[int]:
    ports: list[int] = []

    def add_port(value: object) -> None:
        text = str(value).strip().strip('"').strip("'")
        if not text:
            return
        if ":" in text:
            text = text.split(":")[-1]
        if "/" in text:
            text = text.split("/", 1)[0]
        try:
            port = int(text)
        except ValueError:
            return
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)

    for key in ("ports", "expose"):
        value = service.get(key)
        if isinstance(value, list):
            for item in value:
                add_port(item)
        elif value is not None:
            add_port(value)

    environment = service.get("environment")
    if isinstance(environment, dict):
        port_value = environment.get("PORT")
        if port_value is not None:
            add_port(port_value)
    elif isinstance(environment, list):
        for item in environment:
            text = str(item).strip()
            if text.upper().startswith("PORT="):
                add_port(text.split("=", 1)[1])

    healthcheck = service.get("healthcheck")
    if isinstance(healthcheck, dict):
        healthcheck_texts: list[str] = []
        for value in healthcheck.values():
            if isinstance(value, list):
                healthcheck_texts.append(" ".join(str(part) for part in value))
            else:
                healthcheck_texts.append(str(value))
        for text in healthcheck_texts:
            for pattern in _PORT_FLAG_PATTERNS:
                for match in pattern.findall(text):
                    add_port(match)

    return ports


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


# ---------------------------------------------------------------------------
# Auto-detect env vars from source and generate sandbox values
# ---------------------------------------------------------------------------

_ENV_VAR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"""os\.environ\s*\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\]"""),
    re.compile(r"""os\.environ\.get\s*\(\s*["']([A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"""os\.getenv\s*\(\s*["']([A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"""env\s*\.\s*(?:str|bool|int|float|list)\s*\(\s*["']([A-Z][A-Z0-9_]+)["']"""),
    re.compile(r"""Field\s*\(.*?env\s*=\s*["']([A-Z][A-Z0-9_]+)["']"""),
)

# Env vars that should never be auto-generated (they come from platform
# credentials, dependencies, or Railway itself).
_SKIP_ENV_PREFIXES = (
    "AGENTGATE_",
    "RAILWAY_",
    "REDIS_",
    "DATABASE_",
    "POSTGRES_",
    "MYSQL_",
    "NEO4J_",
    "QDRANT_",
    "ELASTICSEARCH_",
    "OPENAI_",
    "ANTHROPIC_",
    "SLACK_",
    "SHOPIFY_",
    "AZURE_",
    "AWS_",
    "GCP_",
    "GOOGLE_",
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "TERM",
    "SHELL",
    "PYTHONPATH",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "PYTHONFAULTHANDLER",
    "PYTHONHASHSEED",
    "PIP_",
    "UV_",
    "APP_ENV",
    "NODE_ENV",
    "PORT",
)

_SKIP_ENV_EXACT = frozenset({
    "DEBUG",
    "TESTING",
    "CI",
    "LOG_LEVEL",
    "LOGGING_LEVEL",
    "VERBOSE",
    "WORKERS",
    "THREADS",
    "TIMEOUT",
    "HOST",
    "BIND",
})


def _detect_required_env_vars(source_dir: Path) -> set[str]:
    """Scan source code for env var references and return the set of names."""
    found: set[str] = set()
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_dir)
        if any(part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv")
               for part in relative.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for pattern in _ENV_VAR_PATTERNS:
            for match in pattern.finditer(text):
                found.add(match.group(1))
    return found


def _generate_sandbox_env(
    detected: set[str],
    already_provided: set[str],
) -> dict[str, str]:
    """Generate safe sandbox values for env vars that aren't already provided."""
    sandbox: dict[str, str] = {}
    for name in sorted(detected):
        if name in already_provided:
            continue
        if any(name.startswith(prefix) for prefix in _SKIP_ENV_PREFIXES):
            continue
        if name in _SKIP_ENV_EXACT:
            continue
        sandbox[name] = _sandbox_value_for(name)
    return sandbox


def _sandbox_value_for(name: str) -> str:
    """Generate a plausible sandbox value based on the env var name."""
    lower = name.lower()

    # Secret/key patterns → random token
    if any(hint in lower for hint in ("secret", "key", "token", "password", "passwd", "salt")):
        return f"agentgate-sandbox-{secrets.token_urlsafe(24)}"

    # URL patterns → localhost placeholder
    if any(hint in lower for hint in ("url", "endpoint", "uri", "dsn")):
        return "http://localhost:8000"

    # Email patterns
    if "email" in lower or "mail" in lower:
        return "sandbox@agentgate.local"

    # Domain/host patterns
    if "domain" in lower or "host" in lower:
        return "localhost"

    # Name patterns
    if "name" in lower or "title" in lower:
        return "agentgate-sandbox"

    # ID patterns
    if lower.endswith("_id") or lower.endswith("id"):
        return f"agentgate-{hashlib.sha256(name.encode()).hexdigest()[:12]}"

    # Version patterns
    if "version" in lower:
        return "1.0.0"

    # Boolean-ish patterns
    if any(hint in lower for hint in ("enable", "disable", "flag", "active", "allowed")):
        return "true"

    # Default: random safe string
    return f"agentgate-sandbox-{secrets.token_urlsafe(16)}"
