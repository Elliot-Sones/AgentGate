from __future__ import annotations

from pathlib import Path

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.dependency_inference import infer_runtime_dependencies


def test_infer_mem0_like_dependencies_and_runtime_env(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "\n".join(
            [
                'POSTGRES_HOST = os.environ.get("POSTGRES_HOST")',
                'POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD")',
                'NEO4J_URI = os.environ.get("NEO4J_URI")',
                'ENABLE_GRAPH_STORE = os.environ.get("ENABLE_GRAPH_STORE")',
                'DEFAULT_CONFIG = {"vector_store": {"provider": "pgvector"}}',
            ]
        )
    )
    (tmp_path / "docker-compose.yaml").write_text(
        "\n".join(
            [
                "services:",
                "  postgres:",
                "    image: ankane/pgvector:v0.5.1",
                "  neo4j:",
                "    image: neo4j:5.26.4",
            ]
        )
    )

    dependencies, runtime_env, notes = infer_runtime_dependencies(tmp_path)

    assert [dep.service for dep in dependencies] == ["pgvector", "neo4j"]
    assert runtime_env["POSTGRES_HOST"] == "pgvector"
    assert runtime_env["POSTGRES_PASSWORD"] == "postgres"
    assert runtime_env["NEO4J_URI"] == "bolt://neo4j:7687"
    assert runtime_env["ENABLE_GRAPH_STORE"] == "true"
    assert len(notes) == 2


def test_infer_redis_dependency_and_runtime_env(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "\n".join(
            [
                "import redis",
                'REDIS_URL = os.environ.get("REDIS_URL")',
            ]
        )
    )

    dependencies, runtime_env, notes = infer_runtime_dependencies(tmp_path)

    assert dependencies == [DependencySpec(service="redis")]
    assert runtime_env == {"REDIS_URL": "redis://redis:6379/0"}
    assert notes == ["Inferred dependency 'redis' from agent.py."]


def test_inference_does_not_override_explicit_dependency_config(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('POSTGRES_HOST = os.environ.get("POSTGRES_HOST")')

    dependencies, runtime_env, notes = infer_runtime_dependencies(
        tmp_path,
        existing_dependencies=[DependencySpec(service="postgres")],
        existing_runtime_env={"POSTGRES_HOST": "custom-db"},
    )

    assert dependencies == [DependencySpec(service="postgres")]
    assert runtime_env == {"POSTGRES_HOST": "custom-db"}
    assert notes == []


def test_inference_upgrades_postgres_to_pgvector_when_source_requires_it(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                'POSTGRES_HOST = os.environ.get("POSTGRES_HOST")',
                'VECTOR_STORE_PROVIDER = "pgvector"',
            ]
        )
    )

    dependencies, runtime_env, notes = infer_runtime_dependencies(
        tmp_path,
        existing_dependencies=[DependencySpec(service="postgres")],
        existing_runtime_env={"POSTGRES_HOST": "postgres"},
    )

    assert dependencies == [DependencySpec(service="pgvector")]
    assert runtime_env == {"POSTGRES_HOST": "postgres"}
    assert notes == ["Inferred dependency 'pgvector' from app.py."]


def test_inference_does_not_add_postgres_when_pgvector_is_already_declared(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                'DATABASE_URL = os.environ.get("DATABASE_URL")',
                'NEO4J_URI = os.environ.get("NEO4J_URI")',
            ]
        )
    )

    dependencies, runtime_env, notes = infer_runtime_dependencies(
        tmp_path,
        existing_dependencies=[DependencySpec(service="pgvector"), DependencySpec(service="neo4j")],
        existing_runtime_env={},
    )

    assert [dep.service for dep in dependencies] == ["pgvector", "neo4j"]
    assert runtime_env["DATABASE_URL"] == "postgresql://postgres:postgres@pgvector:5432/postgres"
    assert runtime_env["NEO4J_URI"] == "bolt://neo4j:7687"
    assert notes == []
