from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from agentgate.trust.runtime.railway_discovery import (
    RailwayDiscoveryResult,
    build_manifest_from_railway,
    discover_railway_runtime,
)


def test_discover_railway_runtime_maps_internal_services_and_redacts_secrets(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text(
        'VECTOR_PROVIDER = "pgvector"\nENABLE_GRAPH_STORE = os.environ.get("ENABLE_GRAPH_STORE")\n'
    )

    status_payload = {
        "id": "proj-123",
        "name": "mem0-agentgate-demo",
        "environments": {
            "edges": [
                {
                    "node": {
                        "name": "production",
                        "canAccess": True,
                        "serviceInstances": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceName": "Postgres",
                                        "source": {"image": "ghcr.io/railwayapp-templates/postgres-ssl:18"},
                                        "latestDeployment": {"status": "SUCCESS"},
                                        "domains": {"serviceDomains": []},
                                    }
                                },
                                {
                                    "node": {
                                        "serviceName": "gb-neo4j-railway-template",
                                        "source": {"repo": "GBVAI/gb-neo4j-railway-template"},
                                        "latestDeployment": {"status": "FAILED"},
                                        "domains": {"serviceDomains": []},
                                    }
                                },
                                {
                                    "node": {
                                        "serviceName": "mem0-agentgate-demo",
                                        "source": {},
                                        "latestDeployment": {"status": "SUCCESS"},
                                        "domains": {
                                            "serviceDomains": [
                                                {"domain": "mem0-agentgate-demo-production.up.railway.app"}
                                            ]
                                        },
                                    }
                                },
                            ]
                        },
                    }
                }
            ]
        },
    }
    vars_payload = {
        "DATABASE_URL": "postgresql://postgres:secret@postgres.railway.internal:5432/railway",
        "POSTGRES_HOST": "postgres.railway.internal",
        "POSTGRES_PORT": "5432",
        "POSTGRES_DB": "railway",
        "POSTGRES_USER": "postgres",
        "POSTGRES_PASSWORD": "secret",
        "NEO4J_URI": "bolt://gb-neo4j-railway-template.railway.internal:7687",
        "NEO4J_USERNAME": "neo4j",
        "NEO4J_PASSWORD": "super-secret",
        "OPENAI_API_KEY": "sk-test",
        "RAILWAY_PRIVATE_DOMAIN": "mem0-agentgate-demo.railway.internal",
        "RAILWAY_PUBLIC_DOMAIN": "mem0-agentgate-demo-production.up.railway.app",
    }

    calls: list[list[str]] = []

    def _run(cmd: list[str], cwd: str, capture_output: bool, text: bool, check: bool):
        calls.append(cmd)
        if cmd[1:] == ["status", "--json"]:
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(status_payload), stderr="")
        if cmd[1:] == [
            "variable",
            "list",
            "--json",
            "-s",
            "mem0-agentgate-demo",
            "-e",
            "production",
        ]:
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(vars_payload), stderr="")
        raise AssertionError(f"Unexpected Railway CLI call: {cmd}")

    with patch("agentgate.trust.runtime.railway_discovery.subprocess.run", side_effect=_run):
        result = discover_railway_runtime(
            workspace_dir=tmp_path,
            source_dir=tmp_path,
        )

    assert [dependency.service for dependency in result.dependencies] == ["pgvector", "neo4j"]
    assert result.runtime_env["DATABASE_URL"] == "postgresql://postgres:postgres@pgvector:5432/railway"
    assert result.runtime_env["POSTGRES_HOST"] == "pgvector"
    assert result.runtime_env["POSTGRES_PASSWORD"] == "postgres"
    assert result.runtime_env["NEO4J_URI"] == "bolt://neo4j:7687"
    assert result.runtime_env["NEO4J_PASSWORD"] == "mem0graph"
    assert result.runtime_env["ENABLE_GRAPH_STORE"] == "true"
    assert result.omitted_sensitive_env == [
        "NEO4J_PASSWORD",
        "OPENAI_API_KEY",
        "POSTGRES_PASSWORD",
    ]
    assert result.public_domain == "mem0-agentgate-demo-production.up.railway.app"
    assert len(calls) == 2


def test_build_manifest_from_railway_merges_existing_fields() -> None:
    discovery = RailwayDiscoveryResult(
        workspace_dir=Path("."),
        project_name="demo-project",
        project_id="proj-123",
        environment_name="production",
        service_name="demo-agent",
        public_domain="demo-agent-production.up.railway.app",
        dependencies=[],
        runtime_env={"POSTGRES_HOST": "postgres", "ENABLE_GRAPH_STORE": "true"},
        notes=["Discovered Railway service graph."],
        omitted_sensitive_env=["OPENAI_API_KEY"],
    )

    manifest = build_manifest_from_railway(
        discovery,
        existing_manifest={
            "submission_id": "custom-submission",
            "runtime_env": {"POSTGRES_HOST": "custom-db"},
            "integrations": ["slack"],
        },
    )

    assert manifest["submission_id"] == "custom-submission"
    assert manifest["agent_name"] == "demo-agent"
    assert manifest["runtime_env"] == {
        "POSTGRES_HOST": "custom-db",
        "ENABLE_GRAPH_STORE": "true",
    }
    assert manifest["integrations"] == ["slack", "railway"]
    assert manifest["deployment"]["platform"] == "railway"
