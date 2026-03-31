from __future__ import annotations

from pathlib import Path

from agentgate.trust.reachability import (
    build_reachability,
    parse_entrypoint_module,
    walk_imports,
)


def test_parse_uvicorn() -> None:
    assert parse_entrypoint_module("uvicorn app.main:app --host 0.0.0.0") == ["app.main"]


def test_parse_gunicorn() -> None:
    assert parse_entrypoint_module("gunicorn pkg.app:app") == ["pkg.app"]


def test_parse_python_module() -> None:
    assert parse_entrypoint_module("python -m pkg.module") == ["pkg.module"]


def test_parse_python_script() -> None:
    assert parse_entrypoint_module("python app.py") == ["app"]


def test_parse_versioned_python_module() -> None:
    assert parse_entrypoint_module("python3.11 -m pkg.module") == ["pkg.module"]


def test_parse_multiple_commands() -> None:
    modules = parse_entrypoint_module("python migrate.py && uvicorn app.main:app")
    assert "app.main" in modules
    assert "migrate" in modules


def test_walk_imports(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "main.py").write_text(
        "from app.routes import router\nimport app.utils\n"
    )
    (tmp_path / "app" / "routes.py").write_text("from app.db import get_conn\n")
    (tmp_path / "app" / "utils.py").write_text("import os\n")
    (tmp_path / "app" / "db.py").write_text("import asyncpg\n")
    (tmp_path / "app" / "unused.py").write_text("print('never imported')\n")

    reached = walk_imports(tmp_path, ["app.main"])
    assert "app.main" in reached
    assert "app.routes" in reached
    assert "app.db" in reached
    assert "app.utils" in reached
    assert "app.unused" not in reached


def test_build_reachability(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "main.py").write_text("from app.core import run\n")
    (tmp_path / "app" / "core.py").write_text("import os\n")
    (tmp_path / "app" / "plugins.py").write_text(
        "import importlib\nmod = importlib.import_module('app.hidden')\n"
    )
    (tmp_path / "app" / "unused.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text("import app.main\n")

    graph = build_reachability(tmp_path, "uvicorn app.main:app")
    assert graph[Path("app/main.py")] == "on_execution_path"
    assert graph[Path("app/core.py")] == "on_execution_path"
    assert graph[Path("app/unused.py")] == "not_reached"
    assert graph[Path("tests/test_main.py")] == "not_reached"
    assert graph[Path("app/plugins.py")] == "unknown"


def test_dynamic_import_stays_unknown(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import importlib\nmod = importlib.import_module('plugins.x')\n"
    )
    graph = build_reachability(tmp_path, "python app.py")
    assert graph[Path("app.py")] == "on_execution_path"
