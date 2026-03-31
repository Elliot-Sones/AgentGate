from __future__ import annotations

from pathlib import Path

from agentgate.trust.file_classifier import classify_file, classify_repo


def test_test_directory() -> None:
    assert classify_file(Path("tests/test_security.py")) == "test"
    assert classify_file(Path("test/test_agent.py")) == "test"
    assert classify_file(Path("specs/test_agent.py")) == "test"


def test_test_file_pattern() -> None:
    assert classify_file(Path("src/agent/test_core.py")) == "test"
    assert classify_file(Path("src/agent/core_test.py")) == "test"


def test_fixture() -> None:
    assert classify_file(Path("tests/conftest.py")) == "fixture"
    assert classify_file(Path("tests/fixtures/data.py")) == "fixture"


def test_example() -> None:
    assert classify_file(Path("examples/demo_bot.py")) == "example"
    assert classify_file(Path("demo/run.py")) == "example"


def test_docs() -> None:
    assert classify_file(Path("docs/conf.py")) == "docs"
    assert classify_file(Path("README.md")) == "docs"


def test_tooling() -> None:
    assert classify_file(Path("setup.py")) == "tooling"
    assert classify_file(Path("noxfile.py")) == "tooling"
    assert classify_file(Path("tasks.py")) == "tooling"


def test_vendored() -> None:
    assert classify_file(Path("vendor/lib/util.py")) == "vendored"
    assert classify_file(Path("third_party/pkg/mod.py")) == "vendored"


def test_generated() -> None:
    assert classify_file(Path("src/proto/message_pb2.py")) == "generated"
    assert classify_file(Path("generated/client.py")) == "generated"


def test_runtime_code() -> None:
    assert classify_file(Path("src/agent/core.py")) == "runtime_code"
    assert classify_file(Path("app/main.py")) == "runtime_code"
    assert classify_file(Path("main.py")) == "runtime_code"


def test_classify_repo(tmp_path: Path) -> None:
    (tmp_path / "src" / "agent").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "agent" / "core.py").write_text("import os")
    (tmp_path / "tests" / "test_core.py").write_text("import pytest")
    (tmp_path / "setup.py").write_text("from setuptools import setup")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "skip.py").write_text("ignored = True")

    result = classify_repo(tmp_path)
    assert result[Path("src/agent/core.py")] == "runtime_code"
    assert result[Path("tests/test_core.py")] == "test"
    assert result[Path("setup.py")] == "tooling"
    assert Path(".venv/skip.py") not in result
