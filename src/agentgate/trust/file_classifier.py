from __future__ import annotations

from pathlib import Path

_TEST_DIRS = {"test", "tests", "spec", "specs"}
_FIXTURE_NAMES = {"conftest.py"}
_FIXTURE_DIRS = {"fixtures", "factories"}
_EXAMPLE_DIRS = {"example", "examples", "demo", "demos", "sample", "samples"}
_DOCS_DIRS = {"docs", "doc"}
_TOOLING_NAMES = {
    "Makefile",
    "fabfile.py",
    "justfile",
    "noxfile.py",
    "setup.cfg",
    "setup.py",
    "tasks.py",
}
_VENDORED_DIRS = {"vendor", "vendors", "third_party", "_vendor"}
_GENERATED_DIRS = {"generated"}
_GENERATED_SUFFIXES = ("_pb2.py", "_pb2_grpc.py")


def classify_file(relative_path: Path) -> str:
    """Classify a file path relative to a repository root."""

    parts = relative_path.parts
    name = relative_path.name

    if name in _TOOLING_NAMES:
        return "tooling"

    if name.endswith(_GENERATED_SUFFIXES) or any(part in _GENERATED_DIRS for part in parts):
        return "generated"

    if any(part in _VENDORED_DIRS for part in parts):
        return "vendored"

    if any(part in _DOCS_DIRS for part in parts) or name.endswith((".md", ".rst")):
        return "docs"

    if any(part in _EXAMPLE_DIRS for part in parts):
        return "example"

    in_test_dir = any(part in _TEST_DIRS for part in parts)
    if in_test_dir:
        if name in _FIXTURE_NAMES or any(part in _FIXTURE_DIRS for part in parts):
            return "fixture"
        return "test"

    if name.startswith("test_") and name.endswith(".py"):
        return "test"
    if name.endswith("_test.py"):
        return "test"

    return "runtime_code"


def classify_repo(source_dir: Path) -> dict[Path, str]:
    """Classify all Python files in a repo, keyed by relative path."""

    classification: dict[Path, str] = {}
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_dir)
        if any(part.startswith(".") for part in relative.parts):
            continue
        classification[relative] = classify_file(relative)
    return classification
