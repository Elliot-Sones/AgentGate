from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path


def railway_cli_env(project_token: str = "") -> dict[str, str]:
    env = dict(os.environ)
    token = project_token.strip()
    if token:
        env["RAILWAY_TOKEN"] = token
    return env


def materialize_railway_cli_config(
    *,
    config_b64: str = "",
    config_json: str = "",
) -> Path | None:
    raw_b64 = config_b64.strip()
    raw_json = config_json.strip()
    if not raw_b64 and not raw_json:
        return None

    if raw_b64:
        content = base64.b64decode(raw_b64).decode("utf-8")
    else:
        content = raw_json

    # Fail fast on malformed auth payloads instead of producing a broken worker runtime.
    json.loads(content)

    config_dir = Path.home() / ".railway"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"
    config_path.write_text(content)
    os.chmod(config_path, 0o600)
    return config_path


def ensure_linked_railway_workspace(
    *,
    workspace_dir: Path,
    project_id: str = "",
    environment: str = "",
    project_token: str = "",
) -> Path:
    target_dir = workspace_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    normalized_project_id = project_id.strip()
    if not normalized_project_id:
        if _looks_like_linked_workspace(target_dir):
            return target_dir
        raise RuntimeError(
            "Railway pool mode requires AGENTGATE_RAILWAY_POOL_PROJECT_ID "
            "(or RAILWAY_PROJECT_ID) unless AGENTGATE_RAILWAY_POOL_DIR already "
            "points at a linked Railway workspace."
        )

    args = ["railway", "link", "--project", normalized_project_id, "--json"]
    normalized_environment = environment.strip()
    if normalized_environment:
        args.extend(["--environment", normalized_environment])

    proc = subprocess.run(
        args,
        cwd=str(target_dir),
        env=railway_cli_env(project_token),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        message = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        raise RuntimeError(message or "Unable to link Railway pool workspace.")

    return target_dir


def _looks_like_linked_workspace(workspace_dir: Path) -> bool:
    return any(
        (workspace_dir / marker).exists()
        for marker in (".railway", "railway.toml", "railway.json")
    )
