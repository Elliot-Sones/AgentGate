from __future__ import annotations

from collections.abc import Mapping

from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES


def railway_internal_host(service_name: str) -> str:
    return f"{service_name}.railway.internal"


def build_dependency_runtime_env(
    dependency_type: str,
    *,
    service_name: str | None = None,
    overrides: Mapping[str, str] | None = None,
    railway_internal: bool = False,
) -> dict[str, str]:
    normalized = dependency_type.strip().lower()
    service_host = (service_name or normalized).strip().lower() or normalized
    if railway_internal:
        service_host = railway_internal_host(service_host)

    merged_overrides = dict(ALLOWED_SERVICES[normalized].default_env)
    if overrides:
        merged_overrides.update({str(key): str(value) for key, value in overrides.items()})

    if normalized in {"postgres", "pgvector"}:
        user = merged_overrides.get("POSTGRES_USER", "postgres")
        password = merged_overrides.get("POSTGRES_PASSWORD", "postgres")
        db_name = merged_overrides.get("POSTGRES_DB", "postgres")
        return {
            "DATABASE_URL": f"postgresql://{user}:{password}@{service_host}:5432/{db_name}",
            "POSTGRES_HOST": service_host,
            "POSTGRES_PORT": "5432",
            "POSTGRES_DB": db_name,
            "POSTGRES_USER": user,
            "POSTGRES_PASSWORD": password,
        }

    if normalized == "neo4j":
        auth = merged_overrides.get("NEO4J_AUTH", "neo4j/mem0graph")
        auth_user, _, auth_password = auth.partition("/")
        username = (
            merged_overrides.get("NEO4J_USER")
            or merged_overrides.get("NEO4J_USERNAME")
            or auth_user
            or "neo4j"
        )
        password = merged_overrides.get("NEO4J_PASSWORD") or auth_password or "mem0graph"
        return {
            "NEO4J_URI": f"bolt://{service_host}:7687",
            "NEO4J_URL": f"bolt://{service_host}:7687",
            "NEO4J_USER": username,
            "NEO4J_USERNAME": username,
            "NEO4J_PASSWORD": password,
            "ENABLE_GRAPH_STORE": merged_overrides.get("ENABLE_GRAPH_STORE", "true"),
        }

    if normalized == "redis":
        return {
            "REDIS_HOST": service_host,
            "REDIS_PORT": "6379",
            "REDIS_URL": f"redis://{service_host}:6379/0",
        }

    if normalized == "qdrant":
        return {
            "QDRANT_HOST": service_host,
            "QDRANT_PORT": "6333",
            "QDRANT_URL": f"http://{service_host}:6333",
        }

    if normalized == "mysql":
        user = merged_overrides.get("MYSQL_USER", "root")
        password = merged_overrides.get("MYSQL_PASSWORD") or merged_overrides.get(
            "MYSQL_ROOT_PASSWORD", "agentgate_test"
        )
        database = merged_overrides.get("MYSQL_DATABASE", "app")
        return {
            "DATABASE_URL": f"mysql://{user}:{password}@{service_host}:3306/{database}",
            "MYSQL_HOST": service_host,
            "MYSQL_PORT": "3306",
            "MYSQL_DATABASE": database,
            "MYSQL_USER": user,
            "MYSQL_PASSWORD": password,
        }

    if normalized == "elasticsearch":
        return {
            "ELASTICSEARCH_HOST": service_host,
            "ELASTICSEARCH_URL": f"http://{service_host}:9200",
        }

    return {}
