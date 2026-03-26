from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.submission_profile import build_submission_profile


def test_submission_profile_requires_dockerfile_in_production_mode(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is False
    assert assessment.status == "unsupported_build"
    assert assessment.reason == "dockerfile_missing"
    assert profile.dockerfile_path == ""


def test_submission_profile_best_effort_mode_does_not_block_without_dockerfile(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=False,
    )

    assert assessment.supported is True
    assert assessment.status == "best_effort_source"
    assert profile.http_supported is True
    assert "/docs" in profile.probe_paths


def test_submission_profile_issues_platform_credentials_when_available(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "import openai",
                "from fastapi import FastAPI",
                'OPENAI_API_KEY = ""',
                "app = FastAPI()",
            ]
        )
    )

    with patch.dict(
        "os.environ",
        {"AGENTGATE_PLATFORM_OPENAI_API_KEY": "test-openai-key"},
        clear=False,
    ):
        assessment, profile = build_submission_profile(
            source_dir=tmp_path,
            manifest=None,
            dependencies=[DependencySpec(service="postgres")],
            runtime_env={"PORT": "8000"},
            enforce_production_contract=True,
        )

    assert assessment.supported is True
    assert profile.integrations == ["openai"]
    assert profile.issued_integrations == ["openai"]
    assert "api.openai.com" in profile.allow_domains
    assert profile.runtime_env_keys == ["PORT"]


def test_submission_profile_ignores_dependency_names_in_manifest_integrations(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest={"integrations": ["pgvector", "neo4j", "railway"]},
        dependencies=[DependencySpec(service="pgvector"), DependencySpec(service="neo4j")],
        runtime_env={"PORT": "8000"},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.integrations == []
    assert profile.unsupported_integrations == []
