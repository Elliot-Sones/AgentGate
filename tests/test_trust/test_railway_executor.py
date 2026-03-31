from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.railway_executor import RailwayExecutionError, RailwayExecutor


class _Completed:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_railway_executor_deploy_submission_happy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "submission"
    source_dir.mkdir()
    (source_dir / "Dockerfile").write_text("FROM python:3.11\n")

    calls: list[list[str]] = []

    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        calls.append(list(cmd))
        action = cmd[1:]
        if action[:2] == ["init", "--name"]:
            return _Completed(stdout=json.dumps({"id": "proj-123", "name": "agentgate-scan-demo"}))
        if action[:3] == ["add", "--service", "submission-agent"]:
            return _Completed(stdout=json.dumps({"service": "submission-agent"}))
        if action[:5] == ["add", "--service", "neo4j", "--image", "neo4j:5.26.4"]:
            return _Completed(stdout=json.dumps({"database": "postgres"}))
        if action[:2] == ["variable", "set"]:
            return _Completed(stdout=json.dumps({"updated": True}))
        if action[:2] == ["domain", "--service"]:
            return _Completed(
                stdout=json.dumps({"domain": "https://submission-agent.up.railway.app"})
            )
        if action[:1] == ["up"]:
            return _Completed(stdout="deploying")
        if action[:2] == ["status", "--json"]:
            return _Completed(
                stdout=json.dumps(
                    {
                        "environments": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceInstances": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "serviceName": "neo4j",
                                                        "latestDeployment": {"status": "SUCCESS"},
                                                        "domains": {"serviceDomains": []},
                                                    }
                                                },
                                                {
                                                    "node": {
                                                        "serviceName": "submission-agent",
                                                        "latestDeployment": {"status": "SUCCESS"},
                                                        "domains": {
                                                            "serviceDomains": [
                                                                {
                                                                    "domain": "submission-agent.up.railway.app"
                                                                }
                                                            ]
                                                        },
                                                    }
                                                },
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                )
            )
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    result = RailwayExecutor().deploy_submission(
        source_dir=source_dir,
        dockerfile_path=source_dir / "Dockerfile",
        dependencies=[DependencySpec(service="neo4j")],
        runtime_env={"PORT": "8000"},
        issued_integrations=["openai"],
    )

    assert result.project_id == "proj-123"
    assert result.service_name == "submission-agent"
    assert result.public_url == "https://submission-agent.up.railway.app"
    assert result.dependency_services == ["neo4j"]
    assert any(cmd[:2] == ["railway", "up"] for cmd in calls)
    variable_cmd = next(cmd for cmd in calls if cmd[1:3] == ["variable", "set"])
    assert "NEO4J_URI=bolt://neo4j.railway.internal:7687" in variable_cmd
    assert "NEO4J_PASSWORD=mem0graph" in variable_cmd
    assert "PORT=8000" in variable_cmd


def test_railway_executor_fails_fast_on_unprovisionable_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "submission"
    source_dir.mkdir()
    (source_dir / "Dockerfile").write_text("FROM python:3.11\n")

    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        action = cmd[1:]
        if action[:2] == ["init", "--name"]:
            return _Completed(stdout=json.dumps({"id": "proj-123", "name": "agentgate-scan-demo"}))
        if action[:3] == ["add", "--service", "submission-agent"]:
            return _Completed(stdout=json.dumps({"service": "submission-agent"}))
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    executor = RailwayExecutor()

    with pytest.raises(RailwayExecutionError):
        executor.deploy_submission(
            source_dir=source_dir,
            dockerfile_path=source_dir / "Dockerfile",
            dependencies=[DependencySpec(service="unknown-db")],
            runtime_env={},
            issued_integrations=[],
        )


def test_ensure_domain_accepts_domains_array(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        action = cmd[1:]
        if action[:2] == ["status", "--json"]:
            return _Completed(
                stdout=json.dumps(
                    {
                        "environments": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceInstances": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "serviceName": "submission-agent",
                                                        "latestDeployment": {"status": "SUCCESS"},
                                                        "domains": {"serviceDomains": []},
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                )
            )
        if action[:2] == ["domain", "--service"]:
            return _Completed(
                stdout=json.dumps({"domains": ["https://submission-agent-production.up.railway.app"]})
            )
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    executor = RailwayExecutor()
    public_url = executor._ensure_domain(
        tmp_path,
        "submission-agent",
        runtime_env={"PORT": "8000"},
    )

    assert public_url == "https://submission-agent-production.up.railway.app"


def test_ensure_domain_retargets_existing_domain_to_requested_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        calls.append(list(cmd))
        action = cmd[1:]
        if action[:2] == ["status", "--json"]:
            return _Completed(
                stdout=json.dumps(
                    {
                        "environments": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceInstances": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "serviceName": "submission-agent",
                                                        "latestDeployment": {"status": "SUCCESS"},
                                                        "domains": {
                                                            "serviceDomains": [
                                                                {
                                                                    "domain": "submission-agent-production.up.railway.app"
                                                                }
                                                            ]
                                                        },
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                )
            )
        if action[:2] == ["domain", "--service"]:
            return _Completed(
                stdout=json.dumps({"domains": ["https://submission-agent-production.up.railway.app"]})
            )
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    executor = RailwayExecutor()
    public_url = executor._ensure_domain(
        tmp_path,
        "submission-agent",
        runtime_env={"PORT": "8080"},
    )

    assert public_url == "https://submission-agent-production.up.railway.app"
    assert any(
        cmd[:7] == [
            "railway",
            "domain",
            "--service",
            "submission-agent",
            "--port",
            "8080",
            "--json",
        ]
        for cmd in calls
    )


def test_prepare_deploy_source_stages_non_root_dockerfile(tmp_path: Path) -> None:
    source_dir = tmp_path / "submission"
    source_dir.mkdir()
    (source_dir / "Dockerfile.api").write_text("FROM python:3.11\nCMD [\"python\", \"app.py\"]\n")
    (source_dir / "app.py").write_text("print('ok')\n")

    executor = RailwayExecutor()
    staged_source, cleanup_dir = executor._prepare_deploy_source(
        source_dir=source_dir,
        dockerfile_path=source_dir / "Dockerfile.api",
    )

    try:
        assert staged_source != source_dir
        assert (staged_source / "Dockerfile").read_text() == (
            source_dir / "Dockerfile.api"
        ).read_text()
        assert (staged_source / "Dockerfile.api").exists()
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def test_railway_executor_reuses_pool_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "submission"
    source_dir.mkdir()
    (source_dir / "Dockerfile").write_text("FROM python:3.11\n")

    calls: list[list[str]] = []
    status_payload = {
        "id": "proj-pool",
        "name": "agentgate-pool",
        "environments": {
            "edges": [
                {
                    "node": {
                        "name": "agentgate-pool",
                        "serviceInstances": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceName": "submission-agent",
                                        "latestDeployment": {"status": "SUCCESS"},
                                        "domains": {
                                            "serviceDomains": [
                                                {"domain": "submission-agent.up.railway.app"}
                                            ]
                                        },
                                    }
                                },
                                {
                                    "node": {
                                        "serviceName": "neo4j",
                                        "latestDeployment": {"status": "SUCCESS"},
                                        "domains": {"serviceDomains": []},
                                    }
                                },
                            ]
                        },
                    }
                }
            ]
        },
    }

    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        calls.append(list(cmd))
        action = cmd[1:]
        if action[:2] == ["status", "--json"]:
            return _Completed(stdout=json.dumps(status_payload))
        if action[:5] == ["add", "--service", "pgvector", "--image", "ankane/pgvector:v0.5.1"]:
            status_payload["environments"]["edges"][0]["node"]["serviceInstances"]["edges"].append(
                {
                    "node": {
                        "serviceName": "pgvector",
                        "latestDeployment": {"status": "SUCCESS"},
                        "domains": {"serviceDomains": []},
                    }
                }
            )
            return _Completed(stdout=json.dumps({"service": "pgvector"}))
        if action[:2] == ["variable", "set"]:
            return _Completed(stdout=json.dumps({"updated": True}))
        if action[:1] == ["up"]:
            return _Completed(stdout="deploying")
        if action[:2] == ["domain", "--service"]:
            return _Completed(
                stdout=json.dumps({"domains": ["https://submission-agent.up.railway.app"]})
            )
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    result = RailwayExecutor(
        pool_workspace_dir=tmp_path,
        pool_environment="agentgate-pool",
        pool_service_name="submission-agent",
    ).deploy_submission(
        source_dir=source_dir,
        dockerfile_path=source_dir / "Dockerfile",
        dependencies=[DependencySpec(service="neo4j"), DependencySpec(service="pgvector")],
        runtime_env={"PORT": "8000"},
        issued_integrations=["anthropic"],
    )

    assert result.project_id == "proj-pool"
    assert result.project_name == "agentgate-pool"
    assert result.public_url == "https://submission-agent.up.railway.app"
    assert result.reused_pool is True
    assert result.cleanup_project is False
    assert result.cleanup_workspace_dir is False
    assert result.dependency_services == ["neo4j", "pgvector"]
    assert any("Reused a warm Railway pool" in note for note in result.notes)
    assert not any(cmd[:2] == ["railway", "init"] for cmd in calls)
    assert not any(
        cmd[:3] == ["railway", "add", "--service"] and "submission-agent" in cmd for cmd in calls
    )
    assert any(
        cmd[:7]
        == [
            "railway",
            "domain",
            "--service",
            "submission-agent",
            "--port",
            "8000",
            "--json",
        ]
        for cmd in calls
    )
    assert any(cmd[:3] == ["railway", "add", "--service"] and "pgvector" in cmd for cmd in calls)


def test_railway_executor_uses_project_token_for_cli_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "submission"
    source_dir.mkdir()
    (source_dir / "Dockerfile").write_text("FROM python:3.11\n")

    seen_tokens: list[str] = []

    def _fake_run(
        cmd, cwd=None, env=None, capture_output=None, text=None, timeout=None, check=None
    ):
        seen_tokens.append((env or {}).get("RAILWAY_TOKEN", ""))
        action = cmd[1:]
        if action[:2] == ["init", "--name"]:
            return _Completed(stdout=json.dumps({"id": "proj-123", "name": "agentgate-scan-demo"}))
        if action[:3] == ["add", "--service", "submission-agent"]:
            return _Completed(stdout=json.dumps({"service": "submission-agent"}))
        if action[:2] == ["variable", "set"]:
            return _Completed(stdout=json.dumps({"updated": True}))
        if action[:1] == ["up"]:
            return _Completed(stdout="deploying")
        if action[:2] == ["domain", "--service"]:
            return _Completed(
                stdout=json.dumps({"domain": "https://submission-agent.up.railway.app"})
            )
        if action[:2] == ["status", "--json"]:
            return _Completed(
                stdout=json.dumps(
                    {
                        "environments": {
                            "edges": [
                                {
                                    "node": {
                                        "serviceInstances": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "serviceName": "submission-agent",
                                                        "latestDeployment": {"status": "SUCCESS"},
                                                        "domains": {
                                                            "serviceDomains": [
                                                                {
                                                                    "domain": "submission-agent.up.railway.app"
                                                                }
                                                            ]
                                                        },
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                )
            )
        raise AssertionError(f"Unexpected railway command: {cmd}")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    RailwayExecutor(project_token="project-token-123").deploy_submission(
        source_dir=source_dir,
        dockerfile_path=source_dir / "Dockerfile",
        dependencies=[],
        runtime_env={"PORT": "8000"},
        issued_integrations=[],
    )

    assert seen_tokens
    assert set(seen_tokens) == {"project-token-123"}
