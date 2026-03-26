from __future__ import annotations

from agentgate.trust.runtime.dependency_runtime_env import build_dependency_runtime_env


def test_build_dependency_runtime_env_for_railway_pgvector() -> None:
    env = build_dependency_runtime_env(
        "pgvector",
        service_name="pgvector",
        overrides={"POSTGRES_DB": "mem0"},
        railway_internal=True,
    )

    assert env["POSTGRES_HOST"] == "pgvector.railway.internal"
    assert (
        env["DATABASE_URL"] == "postgresql://postgres:postgres@pgvector.railway.internal:5432/mem0"
    )
    assert env["POSTGRES_DB"] == "mem0"


def test_build_dependency_runtime_env_for_railway_neo4j() -> None:
    env = build_dependency_runtime_env(
        "neo4j",
        service_name="neo4j",
        overrides={"NEO4J_AUTH": "neo4j/custompass"},
        railway_internal=True,
    )

    assert env["NEO4J_URI"] == "bolt://neo4j.railway.internal:7687"
    assert env["NEO4J_USERNAME"] == "neo4j"
    assert env["NEO4J_PASSWORD"] == "custompass"
