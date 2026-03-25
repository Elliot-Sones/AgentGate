from __future__ import annotations

import re
from pathlib import Path

from agentgate.trust.config import DependencySpec

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".mypy_cache",
    ".pytest_cache",
}

_TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".txt",
    ".md",
    ".ini",
    ".cfg",
}

_SERVICE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "pgvector": (
        re.compile(r"\bpgvector\b", re.IGNORECASE),
        re.compile(r"ankane/pgvector", re.IGNORECASE),
    ),
    "postgres": (
        re.compile(r"\bPOSTGRES_HOST\b"),
        re.compile(r"\bPOSTGRES_PORT\b"),
        re.compile(r"\bpostgresql://", re.IGNORECASE),
        re.compile(r"\bpsycopg\b", re.IGNORECASE),
        re.compile(r"\basyncpg\b", re.IGNORECASE),
    ),
    "neo4j": (
        re.compile(r"\bNEO4J_URI\b"),
        re.compile(r"\bneo4j\b", re.IGNORECASE),
        re.compile(r"\bbolt://", re.IGNORECASE),
    ),
    "redis": (
        re.compile(r"\bREDIS_URL\b"),
        re.compile(r"\bREDIS_HOST\b"),
        re.compile(r"\bredis://", re.IGNORECASE),
        re.compile(r"\bredis\b", re.IGNORECASE),
    ),
    "qdrant": (
        re.compile(r"\bQDRANT_(?:HOST|URL|PORT)\b"),
        re.compile(r"\bqdrant\b", re.IGNORECASE),
    ),
    "mysql": (
        re.compile(r"\bMYSQL_(?:HOST|PORT|DATABASE|USER|PASSWORD)\b"),
        re.compile(r"\bmysql://", re.IGNORECASE),
        re.compile(r"\bpymysql\b", re.IGNORECASE),
        re.compile(r"\bmysql\b", re.IGNORECASE),
    ),
    "elasticsearch": (
        re.compile(r"\bELASTICSEARCH_(?:URL|HOST)\b"),
        re.compile(r"\belasticsearch\b", re.IGNORECASE),
    ),
}

_ENV_HINTS: dict[str, dict[str, str]] = {
    "pgvector": {
        "POSTGRES_HOST": "pgvector",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "postgres",
        "POSTGRES_USER": "postgres",
        "POSTGRES_PASSWORD": "postgres",
        "DATABASE_URL": "postgresql://postgres:postgres@pgvector:5432/postgres",
    },
    "postgres": {
        "POSTGRES_HOST": "postgres",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "postgres",
        "POSTGRES_USER": "postgres",
        "POSTGRES_PASSWORD": "postgres",
        "DATABASE_URL": "postgresql://postgres:postgres@postgres:5432/postgres",
    },
    "neo4j": {
        "NEO4J_URI": "bolt://neo4j:7687",
        "NEO4J_USERNAME": "neo4j",
        "NEO4J_PASSWORD": "mem0graph",
        "ENABLE_GRAPH_STORE": "true",
    },
    "redis": {
        "REDIS_HOST": "redis",
        "REDIS_PORT": "6379",
        "REDIS_URL": "redis://redis:6379/0",
    },
    "qdrant": {
        "QDRANT_HOST": "qdrant",
        "QDRANT_PORT": "6333",
        "QDRANT_URL": "http://qdrant:6333",
    },
    "mysql": {
        "MYSQL_HOST": "mysql",
        "MYSQL_PORT": "3306",
        "MYSQL_DATABASE": "app",
        "MYSQL_USER": "root",
        "MYSQL_PASSWORD": "agentgate_test",
        "DATABASE_URL": "mysql://root:agentgate_test@mysql:3306/app",
    },
    "elasticsearch": {
        "ELASTICSEARCH_HOST": "elasticsearch",
        "ELASTICSEARCH_URL": "http://elasticsearch:9200",
    },
}


def infer_runtime_dependencies(
    source_dir: Path | None,
    existing_dependencies: list[DependencySpec] | None = None,
    existing_runtime_env: dict[str, str] | None = None,
) -> tuple[list[DependencySpec], dict[str, str], list[str]]:
    if source_dir is None or not source_dir.exists():
        return existing_dependencies or [], existing_runtime_env or {}, []

    files = list(_iter_candidate_files(source_dir))
    if not files:
        return existing_dependencies or [], existing_runtime_env or {}, []

    existing_dependency_map = {
        dep.service: dep for dep in (existing_dependencies or [])
    }
    runtime_env = dict(existing_runtime_env or {})
    notes: list[str] = []

    matches: dict[str, list[str]] = {}
    seen_env_names: set[str] = set()

    for path in files:
        text = _safe_read_text(path)
        if not text:
            continue
        relative_path = str(path.relative_to(source_dir))
        for service, patterns in _SERVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(text):
                    matches.setdefault(service, []).append(relative_path)
                    break
        for env_name in _collect_env_mentions(text):
            seen_env_names.add(env_name)

    if "pgvector" in matches:
        matches.pop("postgres", None)

    dependency_order = [
        "pgvector",
        "postgres",
        "neo4j",
        "redis",
        "qdrant",
        "mysql",
        "elasticsearch",
    ]
    dependencies = list(existing_dependency_map.values())
    seen_services = set(existing_dependency_map)

    if "pgvector" in matches and "postgres" in existing_dependency_map and "pgvector" not in seen_services:
        upgraded: list[DependencySpec] = []
        for dependency in dependencies:
            if dependency.service == "postgres":
                upgraded.append(DependencySpec(service="pgvector", env=dict(dependency.env)))
            else:
                upgraded.append(dependency)
        dependencies = upgraded
        seen_services.discard("postgres")
        seen_services.add("pgvector")
        evidence = ", ".join(sorted(set(matches["pgvector"]))[:3])
        notes.append(f"Inferred dependency 'pgvector' from {evidence}.")

    for service in dependency_order:
        if service not in matches or service in seen_services:
            continue
        if service == "postgres" and "pgvector" in seen_services:
            continue
        dependencies.append(DependencySpec(service=service))
        evidence = ", ".join(sorted(set(matches[service]))[:3])
        notes.append(f"Inferred dependency '{service}' from {evidence}.")
        seen_services.add(service)

    for dependency in dependencies:
        service_hints = _ENV_HINTS.get(dependency.service, {})
        for env_name, env_value in service_hints.items():
            if env_name in runtime_env:
                continue
            if env_name in seen_env_names:
                runtime_env[env_name] = env_value

    return dependencies, runtime_env, notes


def _iter_candidate_files(source_dir: Path):
    count = 0
    for path in source_dir.rglob("*"):
        if count >= 250:
            break
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name == "trust_manifest.yaml":
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name not in {
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "requirements.txt",
            "pyproject.toml",
        }:
            continue
        count += 1
        yield path


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def _collect_env_mentions(text: str) -> set[str]:
    env_names: set[str] = set()
    for env_map in _ENV_HINTS.values():
        for env_name in env_map:
            if re.search(rf"\b{re.escape(env_name)}\b", text):
                env_names.add(env_name)
    return env_names
