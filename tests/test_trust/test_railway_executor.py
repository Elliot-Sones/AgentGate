from __future__ import annotations

import json
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

    def _fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None, check=None):
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
            return _Completed(stdout=json.dumps({"domain": "https://submission-agent.up.railway.app"}))
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
                                                                {"domain": "submission-agent.up.railway.app"}
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

    result = RailwayExecutor().deploy_submission(
        source_dir=source_dir,
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

    def _fake_run(cmd, cwd=None, capture_output=None, text=None, timeout=None, check=None):
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
            dependencies=[DependencySpec(service="unknown-db")],
            runtime_env={},
            issued_integrations=[],
        )
