import base64
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agentgate.trust.runtime.railway_auth import (
    ensure_linked_railway_workspace,
    materialize_railway_cli_config,
)
from agentgate.worker import settings as worker_settings


def test_materialize_railway_cli_config_from_base64(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    payload = json.dumps({"user": {"token": "test-token"}})
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")

    path = materialize_railway_cli_config(config_b64=encoded)

    assert path == tmp_path / ".railway" / "config.json"
    assert path.read_text() == payload


def test_materialize_railway_cli_config_rejects_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    encoded = base64.b64encode(b"not-json").decode("ascii")

    with pytest.raises(json.JSONDecodeError):
        materialize_railway_cli_config(config_b64=encoded)


def test_ensure_linked_railway_workspace_links_project(tmp_path, monkeypatch):
    calls = []

    def _fake_run(
        cmd,
        cwd=None,
        env=None,
        capture_output=None,
        text=None,
        timeout=None,
        check=None,
    ):
        calls.append((list(cmd), cwd, env))
        return MagicMock(returncode=0, stdout='{"project":"proj-123"}', stderr="")

    monkeypatch.setattr("agentgate.trust.runtime.railway_auth.subprocess.run", _fake_run)

    path = ensure_linked_railway_workspace(
        workspace_dir=tmp_path / "pool",
        project_id="proj-123",
        environment="agentgate-pool",
        project_token="railway-token",
    )

    assert path == (tmp_path / "pool").resolve()
    assert calls[0][0] == [
        "railway",
        "link",
        "--project",
        "proj-123",
        "--json",
        "--environment",
        "agentgate-pool",
    ]
    assert calls[0][2]["RAILWAY_TOKEN"] == "railway-token"


def test_prepare_pool_workspace_creates_default_linked_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(worker_settings, "RAILWAY_POOL_DIR", "")
    monkeypatch.setattr(worker_settings, "RAILWAY_POOL_PROJECT_ID", "proj-123")
    monkeypatch.setattr(worker_settings, "RAILWAY_POOL_ENV", "agentgate-pool")
    monkeypatch.setattr(worker_settings, "WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(worker_settings, "POOL_MODE_REQUESTED", True)

    captured = {}

    def _fake_ensure(*, workspace_dir: Path, project_id: str, environment: str, project_token: str):
        captured["workspace_dir"] = workspace_dir
        captured["project_id"] = project_id
        captured["environment"] = environment
        captured["project_token"] = project_token
        return workspace_dir.resolve()

    monkeypatch.setattr(worker_settings, "ensure_linked_railway_workspace", _fake_ensure)

    path = worker_settings.prepare_pool_workspace(project_token="railway-token")

    assert path == (tmp_path / "work" / "railway-pool").resolve()
    assert captured == {
        "workspace_dir": tmp_path / "work" / "railway-pool",
        "project_id": "proj-123",
        "environment": "agentgate-pool",
        "project_token": "railway-token",
    }
