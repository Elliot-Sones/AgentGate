from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES
from agentgate.trust.runtime.dependency_inference import infer_runtime_dependencies
from agentgate.trust.runtime.railway_auth import railway_cli_env

_SECRET_NAME_TOKENS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
_SERVICE_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pgvector", ("pgvector",)),
    ("postgres", ("postgres", "postgresql")),
    ("neo4j", ("neo4j", "bolt")),
    ("redis", ("redis",)),
    ("qdrant", ("qdrant",)),
    ("mysql", ("mysql",)),
    ("elasticsearch", ("elasticsearch", "elastic")),
)
_DEPENDENCY_ENV_KEYS: dict[str, tuple[str, ...]] = {
    "postgres": (
        "DATABASE_URL",
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
    ),
    "pgvector": (
        "DATABASE_URL",
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
    ),
    "neo4j": (
        "NEO4J_URI",
        "NEO4J_URL",
        "NEO4J_USER",
        "NEO4J_USERNAME",
        "NEO4J_PASSWORD",
        "ENABLE_GRAPH_STORE",
    ),
    "redis": (
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_URL",
    ),
    "qdrant": (
        "QDRANT_HOST",
        "QDRANT_PORT",
        "QDRANT_URL",
    ),
    "mysql": (
        "DATABASE_URL",
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_DATABASE",
        "MYSQL_USER",
        "MYSQL_PASSWORD",
    ),
    "elasticsearch": (
        "ELASTICSEARCH_HOST",
        "ELASTICSEARCH_URL",
    ),
}
_SAFE_PASSTHROUGH_KEYS = {
    "ENABLE_GRAPH_STORE",
}


class RailwayDiscoveryError(RuntimeError):
    """Raised when Railway discovery cannot build a usable deployment view."""


@dataclass(frozen=True)
class RailwayService:
    name: str
    source_image: str = ""
    source_repo: str = ""
    latest_status: str = ""
    public_domains: tuple[str, ...] = ()
    private_domain: str = ""


@dataclass
class RailwayDiscoveryResult:
    workspace_dir: Path
    project_name: str
    project_id: str
    environment_name: str
    service_name: str
    public_domain: str = ""
    private_domain: str = ""
    dependencies: list[DependencySpec] = field(default_factory=list)
    runtime_env: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    omitted_sensitive_env: list[str] = field(default_factory=list)
    service_graph: list[RailwayService] = field(default_factory=list)


def discover_railway_runtime(
    workspace_dir: Path,
    service: str | None = None,
    environment: str | None = None,
    source_dir: Path | None = None,
    project_token: str = "",
) -> RailwayDiscoveryResult:
    workspace_dir = workspace_dir.resolve()
    status = _run_railway_json(["status", "--json"], workspace_dir, project_token=project_token)
    project_name = str(status.get("name") or "").strip()
    project_id = str(status.get("id") or "").strip()
    if not project_name or not project_id:
        raise RailwayDiscoveryError(
            "Unable to resolve Railway project metadata from 'railway status --json'."
        )

    environment_node = _select_environment_node(status, environment)
    environment_name = str(environment_node.get("name") or "").strip()
    if not environment_name:
        raise RailwayDiscoveryError("Unable to resolve the active Railway environment.")

    service_instances = _service_instances_for_environment(environment_node)
    if not service_instances:
        raise RailwayDiscoveryError("No Railway services found in the selected environment.")

    app_service = _select_target_service(service_instances, service)
    app_service_name = str(app_service.get("serviceName") or "").strip()
    if not app_service_name:
        raise RailwayDiscoveryError("Unable to resolve the target Railway service name.")

    app_vars = _run_railway_json(
        ["variable", "list", "--json", "-s", app_service_name, "-e", environment_name],
        workspace_dir,
        project_token=project_token,
    )
    if not isinstance(app_vars, dict):
        raise RailwayDiscoveryError("Expected Railway variables output to be a JSON object.")

    service_graph = [_normalize_service_node(node) for node in service_instances]
    dependencies, runtime_env, notes, omitted_sensitive_env = _discover_runtime_from_services(
        app_service_name=app_service_name,
        service_graph=service_graph,
        app_vars=app_vars,
    )

    if source_dir is not None:
        dependencies, runtime_env, source_notes = infer_runtime_dependencies(
            source_dir=source_dir,
            existing_dependencies=dependencies,
            existing_runtime_env=runtime_env,
        )
        runtime_env = _align_runtime_env_with_dependencies(app_vars, dependencies, runtime_env)
        notes.extend(source_notes)

    public_domains = _service_public_domains(app_service)
    public_domain = str(app_vars.get("RAILWAY_PUBLIC_DOMAIN") or "").strip() or next(
        iter(public_domains), ""
    )
    private_domain = str(app_vars.get("RAILWAY_PRIVATE_DOMAIN") or "").strip()

    notes.insert(
        0,
        f"Discovered Railway service '{app_service_name}' in project '{project_name}' environment '{environment_name}'.",
    )

    return RailwayDiscoveryResult(
        workspace_dir=workspace_dir,
        project_name=project_name,
        project_id=project_id,
        environment_name=environment_name,
        service_name=app_service_name,
        public_domain=public_domain,
        private_domain=private_domain,
        dependencies=dependencies,
        runtime_env=runtime_env,
        notes=notes,
        omitted_sensitive_env=omitted_sensitive_env,
        service_graph=service_graph,
    )


def build_manifest_from_railway(
    discovery: RailwayDiscoveryResult,
    existing_manifest: dict | None = None,
) -> dict[str, object]:
    base = dict(existing_manifest or {})
    manifest: dict[str, object] = dict(base)

    manifest.setdefault(
        "submission_id",
        _slug(
            f"railway-{discovery.project_name}-{discovery.service_name}-{discovery.environment_name}"
        ),
    )
    manifest.setdefault("agent_name", discovery.service_name)
    manifest.setdefault("entrypoint", "Railway deployment")
    manifest.setdefault(
        "description",
        (
            f"Auto-generated from Railway project '{discovery.project_name}' "
            f"service '{discovery.service_name}' ({discovery.environment_name})."
        ),
    )
    manifest.setdefault("declared_tools", [])
    manifest.setdefault("declared_external_domains", [])
    manifest.setdefault("permissions", [])
    manifest.setdefault("customer_data_access", "unknown")

    integrations = _merge_string_lists(
        base.get("integrations"),
        ["railway"],
    )
    if integrations:
        manifest["integrations"] = integrations

    merged_dependencies = _merge_dependencies(
        base.get("dependencies"),
        discovery.dependencies,
    )
    if merged_dependencies:
        manifest["dependencies"] = merged_dependencies

    runtime_env = {}
    if isinstance(base.get("runtime_env"), dict):
        runtime_env.update(
            {str(key): str(value) for key, value in dict(base["runtime_env"]).items()}
        )
    for key, value in discovery.runtime_env.items():
        runtime_env.setdefault(key, value)
    if runtime_env:
        manifest["runtime_env"] = runtime_env

    deployment_meta = {}
    if isinstance(base.get("deployment"), dict):
        deployment_meta.update(dict(base["deployment"]))
    deployment_meta.update(
        {
            "platform": "railway",
            "project_name": discovery.project_name,
            "project_id": discovery.project_id,
            "environment_name": discovery.environment_name,
            "service_name": discovery.service_name,
            "public_domain": discovery.public_domain,
            "private_domain": discovery.private_domain,
            "service_graph": [service.name for service in discovery.service_graph],
            "discovery_notes": list(discovery.notes),
            "omitted_sensitive_env": list(discovery.omitted_sensitive_env),
        }
    )
    manifest["deployment"] = deployment_meta
    return manifest


def dump_manifest_yaml(manifest: dict[str, object]) -> str:
    return yaml.safe_dump(manifest, sort_keys=False, allow_unicode=False)


def load_manifest_file(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None

    text = path.read_text()
    if not text.strip():
        return None

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass

    try:
        parsed = yaml.safe_load(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _run_railway_json(args: list[str], workspace_dir: Path, project_token: str = "") -> dict:
    proc = subprocess.run(
        ["railway", *args],
        cwd=str(workspace_dir),
        env=railway_cli_env(project_token),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "Railway CLI command failed."
        raise RailwayDiscoveryError(message)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RailwayDiscoveryError(
            f"Railway CLI returned invalid JSON for {' '.join(args)}."
        ) from exc
    if not isinstance(payload, dict):
        raise RailwayDiscoveryError(
            f"Railway CLI returned unexpected JSON type for {' '.join(args)}."
        )
    return payload


def _select_environment_node(status: dict, environment: str | None) -> dict:
    edges = status.get("environments", {}).get("edges", [])
    nodes = [
        edge.get("node", {})
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
    ]
    if not nodes:
        raise RailwayDiscoveryError("No Railway environments are available in this workspace.")

    if environment:
        for node in nodes:
            if str(node.get("name") or "").strip() == environment:
                return node
        raise RailwayDiscoveryError(f"Railway environment '{environment}' was not found.")

    for node in nodes:
        if node.get("canAccess") is True:
            return node
    return nodes[0]


def _service_instances_for_environment(environment_node: dict) -> list[dict]:
    edges = environment_node.get("serviceInstances", {}).get("edges", [])
    return [
        edge.get("node", {})
        for edge in edges
        if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
    ]


def _select_target_service(service_instances: list[dict], service: str | None) -> dict:
    if service:
        for node in service_instances:
            if str(node.get("serviceName") or "").strip() == service:
                return node
        raise RailwayDiscoveryError(f"Railway service '{service}' was not found.")

    public_candidates = [node for node in service_instances if _service_public_domains(node)]
    if len(public_candidates) == 1:
        return public_candidates[0]
    if public_candidates:
        return sorted(
            public_candidates,
            key=lambda item: (
                _dependency_rank(str(item.get("serviceName") or "")),
                str(item.get("serviceName") or "").lower(),
            ),
        )[0]

    app_candidates = [
        node
        for node in service_instances
        if _classify_service_name(str(node.get("serviceName") or ""), node) is None
    ]
    if len(app_candidates) == 1:
        return app_candidates[0]
    if app_candidates:
        return sorted(
            app_candidates,
            key=lambda item: str(item.get("serviceName") or "").lower(),
        )[0]
    return service_instances[0]


def _service_public_domains(service_node: dict) -> list[str]:
    domains = service_node.get("domains", {}).get("serviceDomains", [])
    results: list[str] = []
    for domain in domains:
        if not isinstance(domain, dict):
            continue
        value = str(domain.get("domain") or "").strip()
        if value:
            results.append(value)
    return results


def _normalize_service_node(node: dict) -> RailwayService:
    source = node.get("source") or {}
    latest = node.get("latestDeployment") or {}
    return RailwayService(
        name=str(node.get("serviceName") or "").strip(),
        source_image=str(source.get("image") or "").strip(),
        source_repo=str(source.get("repo") or "").strip(),
        latest_status=str(latest.get("status") or "").strip(),
        public_domains=tuple(_service_public_domains(node)),
    )


def _discover_runtime_from_services(
    app_service_name: str,
    service_graph: list[RailwayService],
    app_vars: dict[str, object],
) -> tuple[list[DependencySpec], dict[str, str], list[str], list[str]]:
    notes: list[str] = []
    omitted_sensitive_env: list[str] = []
    dependencies: list[DependencySpec] = []
    runtime_env: dict[str, str] = {}
    service_by_name = {service.name.lower(): service for service in service_graph}
    dependency_by_service: dict[str, DependencySpec] = {}

    for key, raw_value in app_vars.items():
        if not isinstance(key, str) or not isinstance(raw_value, str):
            continue
        if key.startswith("RAILWAY_"):
            continue

        if _is_sensitive_env_name(key):
            omitted_sensitive_env.append(key)
            continue

        service_ref = _extract_railway_service_reference(raw_value)
        if service_ref and service_ref.lower() != app_service_name.lower():
            service_node = service_by_name.get(service_ref.lower())
            dependency_type = _classify_service_name(service_ref, service_node)
            if dependency_type:
                dependency = dependency_by_service.get(dependency_type)
                if dependency is None:
                    dependency = DependencySpec(
                        service=dependency_type,
                        env=_build_dependency_env_overrides(dependency_type, app_vars),
                    )
                    dependency_by_service[dependency_type] = dependency
                    dependencies.append(dependency)
                    notes.append(
                        f"Mapped Railway service '{service_ref}' to dependency '{dependency_type}' from env '{key}'."
                    )
                local_value = _localize_dependency_value(
                    service=dependency,
                    env_name=key,
                    observed_value=raw_value,
                )
                if local_value is not None:
                    runtime_env[key] = local_value
                continue

        if key in _SAFE_PASSTHROUGH_KEYS:
            runtime_env[key] = raw_value

    for dependency in dependencies:
        for env_name, env_value in _default_dependency_runtime_env(
            dependency.service, dependency.env
        ).items():
            if env_name in runtime_env:
                continue
            if env_name in app_vars:
                runtime_env[env_name] = env_value

    return dependencies, runtime_env, notes, sorted(set(omitted_sensitive_env))


def _build_dependency_env_overrides(
    dependency_type: str,
    app_vars: dict[str, object],
) -> dict[str, str]:
    overrides: dict[str, str] = {}
    if dependency_type in {"postgres", "pgvector"}:
        db_name = str(app_vars.get("POSTGRES_DB") or "").strip()
        user_name = str(app_vars.get("POSTGRES_USER") or "").strip()
        if db_name:
            overrides["POSTGRES_DB"] = db_name
        if user_name:
            overrides["POSTGRES_USER"] = user_name
    return overrides


def _default_dependency_runtime_env(
    dependency_type: str,
    overrides: dict[str, str],
) -> dict[str, str]:
    if dependency_type in {"postgres", "pgvector"}:
        service_host = dependency_type
        defaults = ALLOWED_SERVICES[dependency_type].default_env
        user = overrides.get("POSTGRES_USER", defaults.get("POSTGRES_USER", "postgres"))
        password = defaults.get("POSTGRES_PASSWORD", "postgres")
        db_name = overrides.get("POSTGRES_DB", defaults.get("POSTGRES_DB", "postgres"))
        return {
            "DATABASE_URL": f"postgresql://{user}:{password}@{service_host}:5432/{db_name}",
            "POSTGRES_HOST": service_host,
            "POSTGRES_PORT": "5432",
            "POSTGRES_DB": db_name,
            "POSTGRES_USER": user,
            "POSTGRES_PASSWORD": password,
        }
    if dependency_type == "neo4j":
        defaults = ALLOWED_SERVICES["neo4j"].default_env
        auth = defaults.get("NEO4J_AUTH", "neo4j/mem0graph")
        username, _, password = auth.partition("/")
        return {
            "NEO4J_URI": "bolt://neo4j:7687",
            "NEO4J_URL": "bolt://neo4j:7687",
            "NEO4J_USER": username,
            "NEO4J_USERNAME": username,
            "NEO4J_PASSWORD": password,
            "ENABLE_GRAPH_STORE": "true",
        }
    if dependency_type == "redis":
        return {
            "REDIS_HOST": "redis",
            "REDIS_PORT": "6379",
            "REDIS_URL": "redis://redis:6379/0",
        }
    if dependency_type == "qdrant":
        return {
            "QDRANT_HOST": "qdrant",
            "QDRANT_PORT": "6333",
            "QDRANT_URL": "http://qdrant:6333",
        }
    if dependency_type == "mysql":
        defaults = ALLOWED_SERVICES["mysql"].default_env
        password = defaults.get("MYSQL_ROOT_PASSWORD", "agentgate_test")
        database = defaults.get("MYSQL_DATABASE", "app")
        return {
            "DATABASE_URL": f"mysql://root:{password}@mysql:3306/{database}",
            "MYSQL_HOST": "mysql",
            "MYSQL_PORT": "3306",
            "MYSQL_DATABASE": database,
            "MYSQL_USER": "root",
            "MYSQL_PASSWORD": password,
        }
    if dependency_type == "elasticsearch":
        return {
            "ELASTICSEARCH_HOST": "elasticsearch",
            "ELASTICSEARCH_URL": "http://elasticsearch:9200",
        }
    return {}


def _localize_dependency_value(
    service: DependencySpec,
    env_name: str,
    observed_value: str,
) -> str | None:
    defaults = _default_dependency_runtime_env(service.service, service.env)
    if env_name in defaults:
        return defaults[env_name]

    if service.service in {"postgres", "pgvector"} and env_name == "DATABASE_URL":
        return defaults.get("DATABASE_URL")
    return None


def _align_runtime_env_with_dependencies(
    app_vars: dict[str, object],
    dependencies: list[DependencySpec],
    runtime_env: dict[str, str],
) -> dict[str, str]:
    aligned = dict(runtime_env)
    for dependency in dependencies:
        defaults = _default_dependency_runtime_env(dependency.service, dependency.env)
        for env_name in _DEPENDENCY_ENV_KEYS.get(dependency.service, ()):
            if env_name in app_vars or env_name in aligned:
                value = defaults.get(env_name)
                if value is not None:
                    aligned[env_name] = value
    return aligned


def _is_sensitive_env_name(name: str) -> bool:
    upper = name.upper()
    if upper.startswith("RAILWAY_"):
        return False
    return any(token in upper for token in _SECRET_NAME_TOKENS)


def _extract_railway_service_reference(value: str) -> str | None:
    host = _extract_host(value)
    if not host or not host.endswith(".railway.internal"):
        return None
    service_name = host.removesuffix(".railway.internal")
    return service_name or None


def _extract_host(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None

    if "://" in text:
        parsed = urlparse(text)
        return parsed.hostname

    candidate = text
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]

    if re.fullmatch(r"[A-Za-z0-9_.-]+", candidate):
        return candidate
    return None


def _classify_service_name(service_name: str, service_node: RailwayService | None) -> str | None:
    haystacks = [service_name.lower()]
    if service_node is not None:
        haystacks.extend(
            [
                service_node.source_image.lower(),
                service_node.source_repo.lower(),
            ]
        )
    joined = " ".join(filter(None, haystacks))
    for service_type, keywords in _SERVICE_KEYWORDS:
        if any(keyword in joined for keyword in keywords):
            return service_type
    return None


def _dependency_rank(service_name: str) -> int:
    return 1 if _classify_service_name(service_name, None) is None else 2


def _merge_dependencies(
    existing_raw: object,
    discovered: list[DependencySpec],
) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    by_service: dict[str, dict[str, object]] = {}

    if isinstance(existing_raw, list):
        for item in existing_raw:
            if not isinstance(item, dict):
                continue
            service = str(item.get("service") or "").strip().lower()
            if not service:
                continue
            env = item.get("env")
            normalized = {"service": service}
            if isinstance(env, dict) and env:
                normalized["env"] = {str(key): str(value) for key, value in env.items()}
            merged.append(normalized)
            by_service[service] = normalized

    for dependency in discovered:
        existing = by_service.get(dependency.service)
        if existing is None:
            payload: dict[str, object] = {"service": dependency.service}
            if dependency.env:
                payload["env"] = dict(dependency.env)
            merged.append(payload)
            by_service[dependency.service] = payload
            continue
        if dependency.env:
            current_env = existing.setdefault("env", {})
            if isinstance(current_env, dict):
                for key, value in dependency.env.items():
                    current_env.setdefault(key, value)

    return merged


def _merge_string_lists(existing_raw: object, discovered: list[str]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    if isinstance(existing_raw, list):
        for item in existing_raw:
            if not isinstance(item, str):
                continue
            if item not in seen:
                values.append(item)
                seen.add(item)
    for item in discovered:
        if item not in seen:
            values.append(item)
            seen.add(item)
    return values


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-").lower()
    return slug or "railway-submission"
