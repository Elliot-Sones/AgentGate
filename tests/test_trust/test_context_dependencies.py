from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext


def _config(tmp_path: Path, manifest_path: Path) -> TrustScanConfig:
    return TrustScanConfig(
        source_dir=tmp_path,
        image_ref="example:latest",
        manifest_path=manifest_path,
        output_dir=tmp_path / "out",
    )


def test_load_manifest_parses_dependencies_and_runtime_env(tmp_path: Path) -> None:
    manifest = tmp_path / "trust_manifest.yaml"
    manifest.write_text(
        "\n".join(
            [
                "submission_id: sub-123",
                "agent_name: mem-agent",
                "entrypoint: server.py",
                "dependencies:",
                "  - service: pgvector",
                "    env:",
                "      POSTGRES_DB: memories",
                "  - service: neo4j",
                "runtime_env:",
                "  POSTGRES_HOST: pgvector",
                "  ENABLE_GRAPH_STORE: true",
            ]
        )
    )

    ctx = TrustScanContext(config=_config(tmp_path, manifest))
    ctx.load_manifest()

    assert ctx.manifest is not None
    assert ctx.config.dependency_validation_errors == []
    assert [dep.service for dep in ctx.config.dependencies] == ["pgvector", "neo4j"]
    assert ctx.config.dependencies[0].env == {"POSTGRES_DB": "memories"}
    assert ctx.config.runtime_env == {
        "POSTGRES_HOST": "pgvector",
        "ENABLE_GRAPH_STORE": "True",
    }


def test_load_manifest_records_invalid_dependency_service(tmp_path: Path) -> None:
    manifest = tmp_path / "trust_manifest.yaml"
    manifest.write_text(
        "\n".join(
            [
                "submission_id: sub-456",
                "agent_name: broken-agent",
                "entrypoint: app.py",
                "dependencies:",
                "  - service: mem0db",
            ]
        )
    )

    ctx = TrustScanContext(config=_config(tmp_path, manifest))
    ctx.load_manifest()

    assert ctx.manifest is not None
    assert ctx.config.dependencies == []
    assert ctx.config.dependency_validation_errors == [
        "Dependency service 'mem0db' is not in the allowed service catalog."
    ]


def test_source_inference_runs_once_per_context(tmp_path: Path) -> None:
    manifest = tmp_path / "trust_manifest.yaml"
    manifest.write_text(
        "\n".join(
            [
                "submission_id: sub-789",
                "agent_name: once-only-agent",
                "entrypoint: app.py",
            ]
        )
    )

    ctx = TrustScanContext(config=_config(tmp_path, manifest))

    with patch(
        "agentgate.trust.context.infer_runtime_dependencies",
        return_value=([], {}, ["Inferred once."]),
    ) as infer_mock:
        ctx.load_manifest()
        ctx.infer_runtime_config_from_source()

    assert infer_mock.call_count == 1
    assert ctx.config.dependency_inference_notes == ["Inferred once."]
