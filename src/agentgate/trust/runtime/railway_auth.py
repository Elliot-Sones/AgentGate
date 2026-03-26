from __future__ import annotations

import os


def railway_cli_env(project_token: str = "") -> dict[str, str]:
    env = dict(os.environ)
    token = project_token.strip()
    if token:
        env["RAILWAY_TOKEN"] = token
    return env
