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


def test_submission_profile_falls_back_to_dockerfile_api(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile.api").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.http_supported is True
    assert profile.dockerfile_path.endswith("Dockerfile.api")


def test_submission_profile_prefers_api_dockerfile_over_root_ui_dockerfile(
    tmp_path: Path,
) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8501\nCMD ["streamlit", "run", "ui.py"]\n'
    )
    (tmp_path / "Dockerfile.api").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (tmp_path / "ui.py").write_text("print('ui')\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.dockerfile_path.endswith("Dockerfile.api")
    assert profile.entrypoint == "uvicorn app:app"
    assert profile.port_candidates[0] == 8000


def test_submission_profile_discovers_nested_dockerfile(tmp_path: Path) -> None:
    deploy_dir = tmp_path / "deploy"
    deploy_dir.mkdir()
    (deploy_dir / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8080\nCMD ["uvicorn", "app:app", "--port", "8080"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.dockerfile_path.endswith("deploy/Dockerfile")
    assert profile.entrypoint == "uvicorn app:app --port 8080"


def test_submission_profile_prefers_compose_and_runtime_port_over_stray_source_mentions(
    tmp_path: Path,
) -> None:
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "Dockerfile.service").write_text(
        'FROM python:3.11\nWORKDIR /app\nCMD ["python", "run_service.py"]\n'
    )
    (tmp_path / "compose.yaml").write_text(
        "\n".join(
            [
                "services:",
                "  agent_service:",
                "    build:",
                "      context: .",
                "      dockerfile: docker/Dockerfile.service",
                "    ports:",
                '      - "8080:8080"',
                "    healthcheck:",
                '      test: ["CMD-SHELL", "curl -f http://localhost:8080/info || exit 1"]',
            ]
        )
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "core").mkdir()
    (src_dir / "core" / "settings.py").write_text(
        "from pydantic import BaseModel\n\nclass Settings(BaseModel):\n    PORT: int = 8080\n"
    )
    (tmp_path / "run_service.py").write_text("print('service')\n")
    (tmp_path / "README.md").write_text("Example docs sometimes mention port 8000.\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.dockerfile_path.endswith("docker/Dockerfile.service")
    assert profile.port_candidates[0] == 8080


def test_submission_profile_prefers_ports_for_the_selected_service_in_multi_service_compose(
    tmp_path: Path,
) -> None:
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "Dockerfile.service").write_text(
        'FROM python:3.11\nWORKDIR /app\nCMD ["python", "run_service.py"]\n'
    )
    (docker_dir / "Dockerfile.app").write_text(
        'FROM python:3.11\nWORKDIR /app\nCMD ["streamlit", "run", "streamlit_app.py"]\n'
    )
    (tmp_path / "compose.yaml").write_text(
        "\n".join(
            [
                "services:",
                "  postgres:",
                '    image: postgres:16',
                '    ports: ["5432:5432"]',
                "  agent_service:",
                "    build:",
                "      context: .",
                "      dockerfile: docker/Dockerfile.service",
                '    ports: ["8080:8080"]',
                "    healthcheck:",
                '      test: ["CMD-SHELL", "curl -f http://localhost:8080/info || exit 1"]',
                "  streamlit_app:",
                "    build:",
                "      context: .",
                "      dockerfile: docker/Dockerfile.app",
                '    ports: ["8501:8501"]',
                "    healthcheck:",
                '      test: ["CMD-SHELL", "curl -f http://localhost:8501/ || exit 1"]',
            ]
        )
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "core").mkdir()
    (src_dir / "core" / "settings.py").write_text(
        "from pydantic import BaseModel\n\nclass Settings(BaseModel):\n    PORT: int = 8080\n"
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "test.yml").write_text(
        "\n".join(
            [
                "jobs:",
                "  test-ui:",
                "    steps:",
                "      - run: curl -f http://localhost:8501/",
            ]
        )
    )
    (tmp_path / "run_service.py").write_text("print('service')\n")
    (tmp_path / "streamlit_app.py").write_text("print('ui')\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.dockerfile_path.endswith("docker/Dockerfile.service")
    assert profile.port_candidates[0] == 8080


def test_submission_profile_uses_requested_dockerfile_path(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile.worker").write_text("FROM python:3.11\n")
    (tmp_path / "Dockerfile.api").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n'
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest=None,
        dependencies=[],
        runtime_env={},
        dockerfile_path=tmp_path / "Dockerfile.api",
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.dockerfile_path.endswith("Dockerfile.api")


def test_submission_profile_prefers_dockerfile_entrypoint_over_manifest(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM python:3.11",
                "ENTRYPOINT [\"uvicorn\"]",
                "CMD [\"app:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]",
            ]
        )
    )
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    assessment, profile = build_submission_profile(
        source_dir=tmp_path,
        manifest={"entrypoint": "python wrong.py"},
        dependencies=[],
        runtime_env={},
        enforce_production_contract=True,
    )

    assert assessment.supported is True
    assert profile.entrypoint == "uvicorn app:app --host 0.0.0.0 --port 8000"


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


def test_submission_profile_records_slack_and_shopify_sandbox_status(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nEXPOSE 8000\nCMD ["python", "app.py"]\n'
    )
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "from fastapi import FastAPI",
                "import slack_sdk",
                'SLACK_BOT_TOKEN = ""',
                'SHOPIFY_STORE_DOMAIN = ""',
                '@app.post("/slack/events")',
                "def slack_events():\n    return {}",
                '@app.post("/shopify/webhooks")',
                "def shopify_webhooks():\n    return {}",
                "app = FastAPI()",
            ]
        )
    )

    with patch.dict(
        "os.environ",
        {
            "AGENTGATE_PLATFORM_SLACK_BOT_TOKEN": "xoxb-test",
            "AGENTGATE_PLATFORM_SLACK_TEAM_ID": "T123456",
            "AGENTGATE_PLATFORM_SLACK_CHANNEL_ID": "C123456",
            "AGENTGATE_PLATFORM_SHOPIFY_ACCESS_TOKEN": "shpat_test",
            "AGENTGATE_PLATFORM_SHOPIFY_STORE_DOMAIN": "agentgate-dev.myshopify.com",
        },
        clear=False,
    ):
        assessment, profile = build_submission_profile(
            source_dir=tmp_path,
            manifest={"integrations": ["slack", "shopify"]},
            dependencies=[],
            runtime_env={"PORT": "8000"},
            enforce_production_contract=True,
        )

    assert assessment.supported is True
    assert profile.issued_integrations == ["slack", "shopify"]
    sandboxes = {item["name"]: item for item in profile.integration_sandboxes}
    assert sandboxes["slack"]["ready"] is True
    assert sandboxes["slack"]["target"] == "T123456"
    assert "message_event_replay" in sandboxes["slack"]["capabilities"]
    assert sandboxes["shopify"]["ready"] is True
    assert sandboxes["shopify"]["target"] == "agentgate-dev.myshopify.com"
    assert "generated_test_data" in sandboxes["shopify"]["capabilities"]
    assert profile.integration_routes["slack"] == ["/slack/events"]
    assert profile.integration_routes["shopify"] == ["/shopify/webhooks"]


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


def test_auth_likely_true_for_fastapi_depends_auth(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n')
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "def get_current_user(): pass\n"
        "@app.get('/data')\n"
        "def read_data(user=Depends(get_current_user)): pass\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path, manifest=None, dependencies=[], runtime_env={}, enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_true_for_login_required_decorator(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n')
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/data')\n@login_required\ndef read_data(): pass\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path, manifest=None, dependencies=[], runtime_env={}, enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_true_for_authorization_header(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n')
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/data')\n"
        'def read_data(request: Request):\n    token = request.headers.get("Authorization")\n'
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path, manifest=None, dependencies=[], runtime_env={}, enforce_production_contract=True,
    )
    assert profile.auth_likely is True


def test_auth_likely_false_for_plain_fastapi_app(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text('FROM python:3.11\nEXPOSE 8000\nCMD ["uvicorn", "app:app"]\n')
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health(): return {'status': 'ok'}\n"
    )
    assessment, profile = build_submission_profile(
        source_dir=tmp_path, manifest=None, dependencies=[], runtime_env={}, enforce_production_contract=True,
    )
    assert profile.auth_likely is False
