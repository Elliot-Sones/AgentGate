# Finding Interpretation & Confidence-Aware Verdicts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace AgentGate's single-step check→verdict pipeline with a three-stage observation→context→assessment pipeline that eliminates false BLOCKs on safe agents.

**Architecture:** Checks emit raw `TrustSignal` observations. A normalizer enriches signals with file classification, reachability, destination taxonomy, and evidence strength. Policy reads normalized `severity` on `TrustFinding` (overwritten by normalizer) plus coverage status to compute verdicts. An LLM adjudicator handles ambiguous boundary cases.

**Tech Stack:** Python 3.11, Pydantic, asyncpg, FastAPI, anthropic SDK. Phase 1 targets Python-based agents only.

**Spec:** `docs/superpowers/specs/2026-03-29-finding-interpretation-design.md`

---

## File Structure

### New files

| File | Responsibility |
|------|----------------|
| `src/agentgate/trust/signals.py` | `TrustSignal` and `SignalContext` dataclasses |
| `src/agentgate/trust/normalizer.py` | Normalizer: enriches signals with context, overwrites severity |
| `src/agentgate/trust/file_classifier.py` | File classification (test/fixture/runtime_code/etc.) by path heuristics |
| `src/agentgate/trust/reachability.py` | Lightweight Python import graph walker from Docker entrypoint |
| `src/agentgate/trust/destination_taxonomy.py` | Destination classification + telemetry registry |
| `src/agentgate/trust/adjudicator.py` | LLM trust adjudicator for boundary cases |
| `tests/test_trust/test_signals.py` | Signal model tests |
| `tests/test_trust/test_normalizer.py` | Normalizer tests |
| `tests/test_trust/test_file_classifier.py` | File classifier tests |
| `tests/test_trust/test_reachability.py` | Reachability walker tests |
| `tests/test_trust/test_destination_taxonomy.py` | Destination taxonomy tests |
| `tests/test_trust/test_adjudicator.py` | Adjudicator tests |

### Modified files

| File | What changes |
|------|-------------|
| `src/agentgate/trust/models.py` | Add `context`, `base_severity`, `legacy_interpretation` fields to `TrustFinding`. Add `coverage_recommendation` to `CoverageSummary`. |
| `src/agentgate/trust/checks/static_code_signals.py` | Rewrite to emit `TrustSignal` with `source_location`, `detection_method`, `raw_evidence` |
| `src/agentgate/trust/checks/runtime_egress.py` | Rewrite to emit `TrustSignal` with destination metadata, timing, evidence provenance |
| `src/agentgate/trust/policy.py` | Rewrite `verdict_for_findings` to use evidence-strength buckets, corroboration rule, diversity-aware accumulation |
| `src/agentgate/trust/scanner.py` | Wire normalizer between checks and policy. Build file classifier + reachability once per scan on context. |
| `src/agentgate/trust/context.py` | Add `file_classification_map`, `reachability_graph`, `destination_taxonomy` fields |
| `src/agentgate/trust/runtime/adaptive/orchestrator.py` | Add health gate, specialist preconditions, `SpecialistDispatchResult` skip reporting |
| `src/agentgate/server/models.py` | Add `coverage_status`, `coverage_recommendation` to `ScanResponse` and `WebhookPayload` |
| `src/agentgate/server/webhook.py` | Include `coverage_status` and `coverage_recommendation` in webhook payload |
| `src/agentgate/server/routes/scans.py` | Map new coverage fields into response |
| `tests/test_trust/test_policy.py` | New tests for confidence-aware policy |
| `tests/test_trust/test_scanner.py` | Tests for normalizer wiring |

---

## Task 1: TrustSignal and SignalContext Models

**Files:**
- Create: `src/agentgate/trust/signals.py`
- Modify: `src/agentgate/trust/models.py:58-72`
- Test: `tests/test_trust/test_signals.py`

- [ ] **Step 1: Write tests for TrustSignal and SignalContext**

```python
# tests/test_trust/test_signals.py
from agentgate.trust.models import TrustCategory, TrustSeverity
from agentgate.trust.signals import SignalContext, TrustSignal


def test_trust_signal_construction():
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Dynamic exec detected",
        summary="exec() call found in source",
        raw_evidence="exec(user_input)",
        detection_method="heuristic",
        source_location="src/agent/core.py:42",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
        recommendation="Remove dynamic exec calls.",
    )
    assert signal.check_id == "static_code_signals"
    assert signal.base_severity == TrustSeverity.HIGH
    assert signal.detection_method == "heuristic"


def test_signal_context_defaults():
    ctx = SignalContext()
    assert ctx.file_class == "unknown"
    assert ctx.reachability == "unknown"
    assert ctx.destination_class == ""
    assert ctx.evidence_strength == "heuristic"
    assert ctx.runtime_attribution == "unknown"
    assert ctx.attribution_confidence == "low"


def test_signal_context_with_values():
    ctx = SignalContext(
        file_class="test",
        reachability="not_reached",
        evidence_strength="procfs_confirmed",
        attribution_confidence="high",
    )
    assert ctx.file_class == "test"
    assert ctx.reachability == "not_reached"


def test_trust_finding_new_fields_default_none():
    from agentgate.trust.models import TrustFinding

    finding = TrustFinding(
        check_id="test",
        title="Test",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=TrustSeverity.HIGH,
        passed=False,
        summary="test",
    )
    assert finding.context is None
    assert finding.base_severity is None
    assert finding.legacy_interpretation is False


def test_trust_finding_with_context():
    from agentgate.trust.models import TrustFinding

    ctx = SignalContext(file_class="test", reachability="not_reached")
    finding = TrustFinding(
        check_id="test",
        title="Test",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=TrustSeverity.INFO,
        passed=True,
        summary="test",
        context=ctx,
        base_severity=TrustSeverity.HIGH,
    )
    assert finding.context.file_class == "test"
    assert finding.base_severity == TrustSeverity.HIGH
    assert finding.severity == TrustSeverity.INFO
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_signals.py -v`
Expected: ImportError — `signals` module doesn't exist yet.

- [ ] **Step 3: Create TrustSignal and SignalContext**

```python
# src/agentgate/trust/signals.py
from __future__ import annotations

from dataclasses import dataclass, field

from agentgate.trust.models import TrustCategory, TrustSeverity


@dataclass
class SignalContext:
    """Context annotations added by the normalizer. Pure context — no severity."""

    file_class: str = "unknown"
    # runtime_code, test, fixture, example, docs, tooling, vendored, generated, unknown

    reachability: str = "unknown"
    # on_execution_path, not_reached, unknown

    destination_class: str = ""
    # platform_internal_verified, private_unattributed, declared_business,
    # framework_telemetry, dependency_service, undeclared_known, unknown_external

    evidence_strength: str = "heuristic"
    # procfs_confirmed, dns_only, log_only, llm_inferred, heuristic, inconclusive

    runtime_attribution: str = "unknown"
    # startup, request_time, background, unknown

    attribution_confidence: str = "low"
    # high, medium, low


# Canonical evidence strength values
EVIDENCE_STRENGTH_VALUES = frozenset({
    "procfs_confirmed",
    "dns_only",
    "log_only",
    "llm_inferred",
    "heuristic",
    "inconclusive",
})


def is_strong_evidence(ctx: SignalContext) -> bool:
    """Map evidence_strength to the 'strong' policy bucket.

    Strong = procfs_confirmed, or heuristic on a reachable path with high confidence.
    Everything else is weak.
    """
    if ctx.evidence_strength == "procfs_confirmed":
        return True
    if (
        ctx.evidence_strength == "heuristic"
        and ctx.reachability == "on_execution_path"
        and ctx.attribution_confidence == "high"
    ):
        return True
    return False


@dataclass
class TrustSignal:
    """Raw observation emitted by a check, before normalization."""

    check_id: str
    signal_type: str
    title: str
    summary: str
    raw_evidence: str
    detection_method: str
    source_location: str
    base_severity: TrustSeverity
    category: TrustCategory
    recommendation: str = ""
```

- [ ] **Step 4: Add context, base_severity, legacy_interpretation to TrustFinding**

In `src/agentgate/trust/models.py`, add these optional fields to the `TrustFinding` dataclass after the existing fields (after line 72):

```python
    # --- Normalization fields (added by finding interpretation pipeline) ---
    context: object | None = None  # SignalContext, kept as object to avoid circular import
    base_severity: TrustSeverity | None = None  # check's pre-normalization assessment, diagnostic only
    legacy_interpretation: bool = False  # True for checks not yet emitting TrustSignal
```

Note: Use `object | None` for `context` to avoid circular import between `models.py` and `signals.py`. The normalizer sets this to a `SignalContext` instance. Pydantic serialization handles it via `model_dump(mode="json")` since `SignalContext` is a dataclass.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_signals.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/trust/signals.py src/agentgate/trust/models.py tests/test_trust/test_signals.py
git commit -m "feat: add TrustSignal, SignalContext models and TrustFinding normalization fields"
```

---

## Task 2: File Classifier

**Files:**
- Create: `src/agentgate/trust/file_classifier.py`
- Test: `tests/test_trust/test_file_classifier.py`

- [ ] **Step 1: Write tests for file classification**

```python
# tests/test_trust/test_file_classifier.py
from pathlib import Path

from agentgate.trust.file_classifier import classify_file, classify_repo


def test_test_directory():
    assert classify_file(Path("tests/test_security.py")) == "test"
    assert classify_file(Path("test/test_agent.py")) == "test"


def test_test_file_pattern():
    assert classify_file(Path("src/agent/test_core.py")) == "test"
    assert classify_file(Path("src/agent/core_test.py")) == "test"


def test_fixture():
    assert classify_file(Path("tests/conftest.py")) == "fixture"
    assert classify_file(Path("tests/fixtures/data.py")) == "fixture"


def test_example():
    assert classify_file(Path("examples/demo_bot.py")) == "example"
    assert classify_file(Path("demo/run.py")) == "example"


def test_docs():
    assert classify_file(Path("docs/conf.py")) == "docs"


def test_tooling():
    assert classify_file(Path("setup.py")) == "tooling"
    assert classify_file(Path("noxfile.py")) == "tooling"
    assert classify_file(Path("tasks.py")) == "tooling"


def test_vendored():
    assert classify_file(Path("vendor/lib/util.py")) == "vendored"
    assert classify_file(Path("third_party/pkg/mod.py")) == "vendored"


def test_generated():
    assert classify_file(Path("src/proto/message_pb2.py")) == "generated"
    assert classify_file(Path("generated/client.py")) == "generated"


def test_runtime_code():
    assert classify_file(Path("src/agent/core.py")) == "runtime_code"
    assert classify_file(Path("app/main.py")) == "runtime_code"
    assert classify_file(Path("main.py")) == "runtime_code"


def test_classify_repo(tmp_path):
    (tmp_path / "src" / "agent").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "agent" / "core.py").write_text("import os")
    (tmp_path / "tests" / "test_core.py").write_text("import pytest")
    (tmp_path / "setup.py").write_text("from setuptools import setup")

    result = classify_repo(tmp_path)
    assert result[Path("src/agent/core.py")] == "runtime_code"
    assert result[Path("tests/test_core.py")] == "test"
    assert result[Path("setup.py")] == "tooling"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_file_classifier.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement file classifier**

```python
# src/agentgate/trust/file_classifier.py
from __future__ import annotations

from pathlib import Path

_TEST_DIRS = {"test", "tests", "spec", "specs"}
_FIXTURE_NAMES = {"conftest.py"}
_FIXTURE_DIRS = {"fixtures", "factories"}
_EXAMPLE_DIRS = {"example", "examples", "demo", "demos", "sample", "samples"}
_DOCS_DIRS = {"docs", "doc"}
_TOOLING_NAMES = {
    "setup.py", "setup.cfg", "noxfile.py", "fabfile.py",
    "tasks.py", "Makefile", "justfile",
}
_VENDORED_DIRS = {"vendor", "vendors", "third_party", "_vendor"}
_GENERATED_DIRS = {"generated"}
_GENERATED_SUFFIXES = {"_pb2.py", "_pb2_grpc.py"}


def classify_file(relative_path: Path) -> str:
    """Classify a single file by its path relative to the repo root."""
    parts = relative_path.parts
    name = relative_path.name

    # Tooling — specific filenames at any depth
    if name in _TOOLING_NAMES:
        return "tooling"

    # Generated — suffixes or directory
    if any(name.endswith(suffix) for suffix in _GENERATED_SUFFIXES):
        return "generated"
    if any(part in _GENERATED_DIRS for part in parts):
        return "generated"

    # Vendored
    if any(part in _VENDORED_DIRS for part in parts):
        return "vendored"

    # Docs
    if any(part in _DOCS_DIRS for part in parts):
        return "docs"

    # Example
    if any(part in _EXAMPLE_DIRS for part in parts):
        return "example"

    # Test directory or test file patterns
    in_test_dir = any(part in _TEST_DIRS for part in parts)

    if in_test_dir:
        # Fixture detection within test directories
        if name in _FIXTURE_NAMES or any(part in _FIXTURE_DIRS for part in parts):
            return "fixture"
        return "test"

    # Test file naming patterns outside test directories
    if name.startswith("test_") and name.endswith(".py"):
        return "test"
    if name.endswith("_test.py"):
        return "test"

    return "runtime_code"


def classify_repo(source_dir: Path) -> dict[Path, str]:
    """Classify all .py files in a repo. Returns {relative_path: file_class}."""
    result: dict[Path, str] = {}
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        if any(part.startswith(".") for part in path.relative_to(source_dir).parts):
            continue
        relative = path.relative_to(source_dir)
        result[relative] = classify_file(relative)
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_file_classifier.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/file_classifier.py tests/test_trust/test_file_classifier.py
git commit -m "feat: add file classifier for test/fixture/runtime_code/etc"
```

---

## Task 3: Reachability Walker

**Files:**
- Create: `src/agentgate/trust/reachability.py`
- Test: `tests/test_trust/test_reachability.py`

- [ ] **Step 1: Write tests for entrypoint parsing and import walking**

```python
# tests/test_trust/test_reachability.py
from pathlib import Path

from agentgate.trust.reachability import (
    parse_entrypoint_module,
    walk_imports,
    build_reachability,
)


def test_parse_uvicorn():
    assert parse_entrypoint_module("uvicorn app.main:app --host 0.0.0.0") == ["app.main"]


def test_parse_gunicorn():
    assert parse_entrypoint_module("gunicorn pkg.app:app") == ["pkg.app"]


def test_parse_python_module():
    assert parse_entrypoint_module("python -m pkg.module") == ["pkg.module"]


def test_parse_python_script():
    assert parse_entrypoint_module("python app.py") == ["app"]


def test_parse_multiple_commands():
    # Dockerfile with && chaining
    assert "app.main" in parse_entrypoint_module(
        "python migrate.py && uvicorn app.main:app"
    )


def test_walk_imports(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "main.py").write_text(
        "from app.routes import router\nimport app.utils\n"
    )
    (tmp_path / "app" / "routes.py").write_text(
        "from app.db import get_conn\n"
    )
    (tmp_path / "app" / "utils.py").write_text("import os\n")
    (tmp_path / "app" / "db.py").write_text("import asyncpg\n")
    (tmp_path / "app" / "unused.py").write_text("print('never imported')\n")

    reached = walk_imports(tmp_path, ["app.main"])
    assert "app.main" in reached
    assert "app.routes" in reached
    assert "app.db" in reached
    assert "app.utils" in reached
    assert "app.unused" not in reached


def test_build_reachability(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "main.py").write_text("from app.core import run\n")
    (tmp_path / "app" / "core.py").write_text("import os\n")
    (tmp_path / "app" / "unused.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text("import app.main\n")

    graph = build_reachability(tmp_path, "uvicorn app.main:app")
    assert graph[Path("app/main.py")] == "on_execution_path"
    assert graph[Path("app/core.py")] == "on_execution_path"
    assert graph[Path("app/unused.py")] == "not_reached"
    # Test files are not walked from entrypoint, so not_reached
    assert graph[Path("tests/test_main.py")] == "not_reached"


def test_dynamic_import_stays_unknown(tmp_path):
    (tmp_path / "app.py").write_text(
        "import importlib\nmod = importlib.import_module('plugins.x')\n"
    )
    graph = build_reachability(tmp_path, "python app.py")
    assert graph[Path("app.py")] == "on_execution_path"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_reachability.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement reachability walker**

```python
# src/agentgate/trust/reachability.py
from __future__ import annotations

import re
from pathlib import Path

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.MULTILINE
)

_ENTRYPOINT_PATTERNS: list[tuple[re.Pattern[str], int]] = [
    # uvicorn app.main:app
    (re.compile(r"uvicorn\s+([\w.]+):"), 1),
    # gunicorn pkg.app:app
    (re.compile(r"gunicorn\s+([\w.]+):"), 1),
    # python -m pkg.module
    (re.compile(r"python3?\s+-m\s+([\w.]+)"), 1),
    # python app.py
    (re.compile(r"python3?\s+([\w/]+\.py)"), 1),
]


def parse_entrypoint_module(entrypoint: str) -> list[str]:
    """Extract Python module names from a Docker CMD/ENTRYPOINT string."""
    modules: list[str] = []
    for pattern, group in _ENTRYPOINT_PATTERNS:
        for match in pattern.finditer(entrypoint):
            raw = match.group(group).strip()
            # Convert file paths to module names: app.py -> app, src/app.py -> src.app
            if raw.endswith(".py"):
                raw = raw[:-3].replace("/", ".")
            if raw and raw not in modules:
                modules.append(raw)
    return modules


def walk_imports(source_dir: Path, entry_modules: list[str]) -> set[str]:
    """Walk import statements from entry modules. Returns set of reached module names."""
    source_root = source_dir.resolve()
    reached: set[str] = set()
    queue: list[str] = list(entry_modules)

    while queue:
        module_name = queue.pop()
        if module_name in reached:
            continue
        reached.add(module_name)

        module_path = _resolve_module_path(source_root, module_name)
        if module_path is None:
            continue

        try:
            source_text = module_path.read_text(errors="replace")
        except OSError:
            continue

        for match in _IMPORT_RE.finditer(source_text):
            imported = match.group(1) or match.group(2)
            if not imported:
                continue
            # Only follow imports that could be local modules
            top_level = imported.split(".")[0]
            if _could_be_local_module(source_root, top_level) and imported not in reached:
                queue.append(imported)

    return reached


def build_reachability(source_dir: Path, entrypoint: str) -> dict[Path, str]:
    """Build reachability map: {relative_path: on_execution_path|not_reached|unknown}.

    not_reached is only assigned when positively established. Modules with
    dynamic imports (importlib, __import__, entry_points) get unknown.
    """
    source_root = source_dir.resolve()
    entry_modules = parse_entrypoint_module(entrypoint)
    if not entry_modules:
        # Can't determine entrypoint — everything is unknown
        result: dict[Path, str] = {}
        for path in source_root.rglob("*.py"):
            if path.is_file() and not any(p.startswith(".") for p in path.relative_to(source_root).parts):
                result[path.relative_to(source_root)] = "unknown"
        return result

    reached_modules = walk_imports(source_root, entry_modules)

    # Check which modules use dynamic imports
    dynamic_import_modules = _find_dynamic_import_modules(source_root)

    # Build the map
    result = {}
    for path in source_root.rglob("*.py"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        if any(part.startswith(".") for part in relative.parts):
            continue

        module_name = _path_to_module(relative)
        if module_name in reached_modules:
            result[relative] = "on_execution_path"
        elif module_name in dynamic_import_modules:
            result[relative] = "unknown"
        else:
            result[relative] = "not_reached"

    # If any reached module uses dynamic imports, mark all not_reached as unknown
    # because the dynamic loader could pull in anything
    if reached_modules & dynamic_import_modules:
        for path, status in result.items():
            if status == "not_reached":
                result[path] = "unknown"

    return result


def _resolve_module_path(source_root: Path, module_name: str) -> Path | None:
    """Resolve a dotted module name to a file path."""
    parts = module_name.split(".")
    # Try as package: a/b/__init__.py
    package_path = source_root / Path(*parts) / "__init__.py"
    if package_path.exists():
        return package_path
    # Try as module: a/b.py
    module_path = source_root / Path(*parts[:-1]) / f"{parts[-1]}.py" if len(parts) > 1 else source_root / f"{parts[0]}.py"
    if module_path.exists():
        return module_path
    return None


def _could_be_local_module(source_root: Path, top_level: str) -> bool:
    """Check if a top-level name could be a local module (not stdlib/third-party)."""
    return (source_root / top_level).is_dir() or (source_root / f"{top_level}.py").is_file()


def _path_to_module(relative_path: Path) -> str:
    """Convert a relative file path to a dotted module name."""
    parts = list(relative_path.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return ".".join(parts)


_DYNAMIC_IMPORT_RE = re.compile(
    r"(?:importlib\.import_module|__import__|entry_points|load_module)\s*\(",
    re.MULTILINE,
)


def _find_dynamic_import_modules(source_root: Path) -> set[str]:
    """Find modules that use dynamic imports."""
    dynamic: set[str] = set()
    for path in source_root.rglob("*.py"):
        if not path.is_file():
            continue
        relative = path.relative_to(source_root)
        if any(part.startswith(".") for part in relative.parts):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if _DYNAMIC_IMPORT_RE.search(text):
            dynamic.add(_path_to_module(relative))
    return dynamic
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_reachability.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/reachability.py tests/test_trust/test_reachability.py
git commit -m "feat: add Python import reachability walker"
```

---

## Task 4: Destination Taxonomy + Telemetry Registry

**Files:**
- Create: `src/agentgate/trust/destination_taxonomy.py`
- Test: `tests/test_trust/test_destination_taxonomy.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_trust/test_destination_taxonomy.py
from agentgate.trust.destination_taxonomy import (
    classify_destination,
    build_telemetry_registry,
    DestinationContext,
)


def test_platform_internal_verified():
    result = classify_destination(
        "10.165.167.93",
        verified_internal_ips={"10.165.167.93"},
    )
    assert result.destination_class == "platform_internal_verified"


def test_private_unattributed():
    result = classify_destination("10.0.0.55", verified_internal_ips=set())
    assert result.destination_class == "private_unattributed"


def test_declared_business():
    result = classify_destination(
        "api.openai.com",
        declared_domains={"api.openai.com"},
    )
    assert result.destination_class == "declared_business"


def test_framework_telemetry():
    registry = build_telemetry_registry(["streamlit"])
    result = classify_destination(
        "browser.gatherusagestats",
        telemetry_registry=registry,
    )
    assert result.destination_class == "framework_telemetry"


def test_dependency_service():
    registry = build_telemetry_registry(["langchain", "langsmith"])
    result = classify_destination(
        "api.langsmith.com",
        telemetry_registry=registry,
    )
    assert result.destination_class == "dependency_service"


def test_unknown_external():
    result = classify_destination("sketchy-server.xyz")
    assert result.destination_class == "unknown_external"


def test_railway_internal_domain():
    result = classify_destination(
        "postgres-r0d2.railway.internal",
        verified_internal_domains={"*.railway.internal"},
    )
    assert result.destination_class == "platform_internal_verified"


def test_build_registry_from_packages():
    registry = build_telemetry_registry(["sentry-sdk", "wandb", "streamlit"])
    assert "*.ingest.sentry.io" in registry
    assert "api.wandb.ai" in registry
    assert "browser.gatherusagestats" in registry
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_destination_taxonomy.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement destination taxonomy**

```python
# src/agentgate/trust/destination_taxonomy.py
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from fnmatch import fnmatch

# Package -> expected outbound domains
_PACKAGE_TELEMETRY_MAP: dict[str, list[str]] = {
    "streamlit": ["browser.gatherusagestats", "*.streamlit.io"],
    "langchain": ["api.langsmith.com", "api.smith.langchain.com"],
    "langchain-core": ["api.langsmith.com", "api.smith.langchain.com"],
    "langsmith": ["api.langsmith.com", "api.smith.langchain.com"],
    "langgraph": ["api.langsmith.com"],
    "sentry-sdk": ["*.ingest.sentry.io"],
    "sentry_sdk": ["*.ingest.sentry.io"],
    "opentelemetry-sdk": ["*.otel.collector"],
    "opentelemetry-api": ["*.otel.collector"],
    "wandb": ["api.wandb.ai"],
    "datadog": ["*.datadoghq.com"],
    "dd-trace": ["*.datadoghq.com"],
    "newrelic": ["*.newrelic.com"],
    "bugsnag": ["*.bugsnag.com"],
    "segment-analytics-python": ["api.segment.io"],
    "mixpanel": ["api.mixpanel.com"],
    "posthog": ["*.posthog.com"],
}

_RFC1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

_RFC4193_NETWORK = ipaddress.IPv6Network("fc00::/7")


@dataclass
class DestinationContext:
    destination_class: str
    matched_rule: str = ""


def build_telemetry_registry(packages: list[str]) -> dict[str, str]:
    """Build {domain_pattern: package_name} from installed packages."""
    registry: dict[str, str] = {}
    for pkg in packages:
        normalized = pkg.strip().lower().replace("-", "_").replace("_", "-")
        for variant in (pkg.strip().lower(), normalized):
            domains = _PACKAGE_TELEMETRY_MAP.get(variant, [])
            for domain in domains:
                registry[domain.lower()] = variant
    return registry


def classify_destination(
    destination: str,
    *,
    verified_internal_ips: set[str] | None = None,
    verified_internal_domains: set[str] | None = None,
    declared_domains: set[str] | None = None,
    telemetry_registry: dict[str, str] | None = None,
) -> DestinationContext:
    """Classify a network destination. Evaluated in taxonomy order, first match wins."""
    dest = destination.strip().lower()

    # 1. Platform internal verified (exact IP match)
    if verified_internal_ips and dest in verified_internal_ips:
        return DestinationContext("platform_internal_verified", f"verified IP: {dest}")

    # 2. Platform internal verified (domain pattern match, e.g. *.railway.internal)
    if verified_internal_domains:
        for pattern in verified_internal_domains:
            if fnmatch(dest, pattern.lower()):
                return DestinationContext("platform_internal_verified", f"matched: {pattern}")

    # 3. Private IP range (RFC1918/RFC4193) but not verified
    if _is_private_ip(dest):
        return DestinationContext("private_unattributed", f"private IP: {dest}")

    # 4. Declared business domain
    if declared_domains:
        for declared in declared_domains:
            if dest == declared.lower() or dest.endswith(f".{declared.lower()}"):
                return DestinationContext("declared_business", f"declared: {declared}")

    # 5. Framework telemetry / dependency service
    if telemetry_registry:
        for pattern, pkg in telemetry_registry.items():
            if fnmatch(dest, pattern) or dest == pattern:
                # Telemetry packages vs dependency services
                if pkg in _PACKAGE_TELEMETRY_MAP:
                    return DestinationContext(
                        "framework_telemetry" if _is_telemetry_package(pkg) else "dependency_service",
                        f"package: {pkg}",
                    )

    # 6. Unknown external
    return DestinationContext("unknown_external", "")


def _is_private_ip(dest: str) -> bool:
    try:
        addr = ipaddress.ip_address(dest)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in network for network in _RFC1918_NETWORKS)
    return addr in _RFC4193_NETWORK


def _is_telemetry_package(pkg: str) -> bool:
    """Distinguish telemetry/analytics packages from functional dependencies."""
    telemetry_indicators = {
        "sentry", "opentelemetry", "datadog", "dd-trace", "newrelic",
        "bugsnag", "segment", "mixpanel", "posthog", "wandb", "streamlit",
    }
    normalized = pkg.lower().replace("-", "").replace("_", "")
    return any(indicator.replace("-", "") in normalized for indicator in telemetry_indicators)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_destination_taxonomy.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/destination_taxonomy.py tests/test_trust/test_destination_taxonomy.py
git commit -m "feat: add destination taxonomy and telemetry registry"
```

---

## Task 5: Normalizer

**Files:**
- Create: `src/agentgate/trust/normalizer.py`
- Modify: `src/agentgate/trust/context.py` (add classification/reachability fields)
- Test: `tests/test_trust/test_normalizer.py`

- [ ] **Step 1: Write normalizer tests**

```python
# tests/test_trust/test_normalizer.py
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.normalizer import normalize_finding
from agentgate.trust.signals import SignalContext, TrustSignal


def test_test_file_not_reached_caps_to_info():
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Dynamic exec detected",
        summary="exec() call in test file",
        raw_evidence="exec(payload)",
        detection_method="heuristic",
        source_location="tests/test_security.py:10",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
    )
    file_map = {"tests/test_security.py": "test"}
    reach_map = {"tests/test_security.py": "not_reached"}

    finding = normalize_finding(signal, file_map=file_map, reachability_map=reach_map)
    assert finding.severity == TrustSeverity.INFO
    assert finding.base_severity == TrustSeverity.HIGH
    assert finding.context.file_class == "test"
    assert finding.context.reachability == "not_reached"


def test_runtime_code_on_path_preserves_severity():
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Dynamic exec detected",
        summary="exec() call in runtime code",
        raw_evidence="exec(payload)",
        detection_method="heuristic",
        source_location="src/agent/core.py:42",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
    )
    file_map = {"src/agent/core.py": "runtime_code"}
    reach_map = {"src/agent/core.py": "on_execution_path"}

    finding = normalize_finding(signal, file_map=file_map, reachability_map=reach_map)
    assert finding.severity == TrustSeverity.HIGH
    assert finding.context.file_class == "runtime_code"
    assert finding.context.reachability == "on_execution_path"


def test_not_reached_alone_lowers_by_one_band():
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Suspicious pattern",
        summary="Found in unreachable runtime code",
        raw_evidence="os.system(cmd)",
        detection_method="heuristic",
        source_location="src/unused_module.py:5",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
    )
    file_map = {"src/unused_module.py": "runtime_code"}
    reach_map = {"src/unused_module.py": "not_reached"}

    finding = normalize_finding(signal, file_map=file_map, reachability_map=reach_map)
    # runtime_code + not_reached: lower by one band, HIGH -> MEDIUM
    assert finding.severity == TrustSeverity.MEDIUM


def test_unknown_reachability_no_downgrade():
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Suspicious pattern",
        summary="Found in dynamically loaded module",
        raw_evidence="exec(x)",
        detection_method="heuristic",
        source_location="src/plugins/loader.py:5",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
    )
    file_map = {"src/plugins/loader.py": "runtime_code"}
    reach_map = {"src/plugins/loader.py": "unknown"}

    finding = normalize_finding(signal, file_map=file_map, reachability_map=reach_map)
    assert finding.severity == TrustSeverity.HIGH  # no downgrade


def test_platform_internal_verified_defaults_to_info():
    signal = TrustSignal(
        check_id="runtime_egress",
        signal_type="outbound_connection",
        title="Outbound connection",
        summary="Connection to internal IP",
        raw_evidence="10.165.167.93",
        detection_method="procfs_socket",
        source_location="runtime:startup",
        base_severity=TrustSeverity.CRITICAL,
        category=TrustCategory.EGRESS,
    )
    finding = normalize_finding(
        signal,
        destination_class="platform_internal_verified",
        evidence_strength="procfs_confirmed",
        runtime_attribution="startup",
    )
    assert finding.severity == TrustSeverity.INFO
    assert finding.context.destination_class == "platform_internal_verified"


def test_unknown_external_preserves_severity():
    signal = TrustSignal(
        check_id="runtime_egress",
        signal_type="outbound_connection",
        title="Unknown destination",
        summary="Connection to unknown host",
        raw_evidence="sketchy-server.xyz",
        detection_method="procfs_socket",
        source_location="runtime:request_time",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.EGRESS,
    )
    finding = normalize_finding(
        signal,
        destination_class="unknown_external",
        evidence_strength="procfs_confirmed",
        runtime_attribution="request_time",
        attribution_confidence="high",
    )
    assert finding.severity == TrustSeverity.HIGH


def test_legacy_finding_tagged():
    legacy = TrustFinding(
        check_id="static_manifest",
        title="Manifest missing",
        category=TrustCategory.DECLARATION,
        severity=TrustSeverity.INFO,
        passed=True,
        summary="No manifest",
    )
    from agentgate.trust.normalizer import tag_legacy_finding

    tagged = tag_legacy_finding(legacy)
    assert tagged.legacy_interpretation is True
    assert tagged.base_severity == TrustSeverity.INFO
    assert tagged.context is not None
    assert tagged.context.attribution_confidence == "low"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_normalizer.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement normalizer**

```python
# src/agentgate/trust/normalizer.py
from __future__ import annotations

from pathlib import Path

from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.signals import SignalContext, TrustSignal

_SEVERITY_LADDER = [
    TrustSeverity.INFO,
    TrustSeverity.LOW,
    TrustSeverity.MEDIUM,
    TrustSeverity.HIGH,
    TrustSeverity.CRITICAL,
]

_SEVERITY_RANK = {sev: i for i, sev in enumerate(_SEVERITY_LADDER)}

_NON_RUNTIME_FILE_CLASSES = frozenset({
    "test", "fixture", "example", "docs", "tooling", "vendored", "generated",
})

_DESTINATION_DEFAULT_SEVERITY: dict[str, TrustSeverity] = {
    "platform_internal_verified": TrustSeverity.INFO,
    "declared_business": TrustSeverity.INFO,
    "framework_telemetry": TrustSeverity.INFO,
    "dependency_service": TrustSeverity.INFO,
    "undeclared_known": TrustSeverity.MEDIUM,
    "private_unattributed": TrustSeverity.MEDIUM,
    "unknown_external": TrustSeverity.HIGH,
}


def _lower_severity(severity: TrustSeverity, bands: int = 1) -> TrustSeverity:
    """Lower severity by N bands, with a floor at INFO."""
    rank = _SEVERITY_RANK.get(severity, 0)
    new_rank = max(rank - bands, 0)
    return _SEVERITY_LADDER[new_rank]


def _cap_severity(severity: TrustSeverity, cap: TrustSeverity) -> TrustSeverity:
    """Cap severity at a maximum level."""
    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(cap, 0):
        return cap
    return severity


def normalize_finding(
    signal: TrustSignal,
    *,
    file_map: dict[str, str] | None = None,
    reachability_map: dict[str, str] | None = None,
    destination_class: str = "",
    evidence_strength: str = "",
    runtime_attribution: str = "unknown",
    attribution_confidence: str = "low",
) -> TrustFinding:
    """Normalize a TrustSignal into a TrustFinding with context-adjusted severity."""
    # Extract file path from source_location ("path/to/file.py:42" -> "path/to/file.py")
    source_path = signal.source_location.split(":")[0] if ":" in signal.source_location else signal.source_location

    file_class = (file_map or {}).get(source_path, "unknown")
    reachability = (reachability_map or {}).get(source_path, "unknown")

    ctx = SignalContext(
        file_class=file_class,
        reachability=reachability,
        destination_class=destination_class,
        evidence_strength=evidence_strength or signal.detection_method,
        runtime_attribution=runtime_attribution,
        attribution_confidence=attribution_confidence,
    )

    severity = signal.base_severity

    # --- File class + reachability rules ---

    if file_class in _NON_RUNTIME_FILE_CLASSES and reachability == "not_reached":
        severity = _cap_severity(severity, TrustSeverity.INFO)
    elif file_class in _NON_RUNTIME_FILE_CLASSES and reachability == "unknown":
        severity = _lower_severity(severity, bands=1)
        severity = max(severity, TrustSeverity.LOW, key=lambda s: _SEVERITY_RANK.get(s, 0))
    elif file_class == "test" and reachability == "on_execution_path":
        severity = _cap_severity(severity, TrustSeverity.MEDIUM)
    elif file_class in ("runtime_code", "unknown") and reachability == "not_reached":
        severity = _lower_severity(severity, bands=1)
        severity = max(severity, TrustSeverity.LOW, key=lambda s: _SEVERITY_RANK.get(s, 0))
    # reachability == "unknown" with runtime_code: no downgrade

    # --- Destination class rules ---
    if destination_class and destination_class in _DESTINATION_DEFAULT_SEVERITY:
        dest_default = _DESTINATION_DEFAULT_SEVERITY[destination_class]
        severity = _cap_severity(severity, dest_default)

    # --- Evidence strength rules ---
    if ctx.evidence_strength == "llm_inferred" and ctx.attribution_confidence == "low":
        severity = _cap_severity(severity, TrustSeverity.MEDIUM)

    return TrustFinding(
        check_id=signal.check_id,
        title=signal.title,
        category=signal.category,
        severity=severity,
        passed=severity in (TrustSeverity.INFO, TrustSeverity.LOW),
        summary=signal.summary,
        recommendation=signal.recommendation,
        location_path=source_path if source_path != signal.source_location else "",
        location_line=_extract_line(signal.source_location),
        context=ctx,
        base_severity=signal.base_severity,
    )


def tag_legacy_finding(finding: TrustFinding) -> TrustFinding:
    """Tag an existing TrustFinding from a legacy check that hasn't been migrated."""
    finding.legacy_interpretation = True
    finding.base_severity = finding.severity
    finding.context = SignalContext(attribution_confidence="low")
    return finding


def _extract_line(source_location: str) -> int:
    """Extract line number from 'path:42' format."""
    if ":" not in source_location:
        return 0
    parts = source_location.rsplit(":", 1)
    try:
        return int(parts[1])
    except (ValueError, IndexError):
        return 0
```

- [ ] **Step 4: Add context fields to TrustScanContext**

In `src/agentgate/trust/context.py`, add after the existing fields (around line 30):

```python
    # Normalization context (built once per scan by scanner)
    file_classification: dict[str, str] = field(default_factory=dict)
    reachability_graph: dict[str, str] = field(default_factory=dict)
```

These use `str` keys (relative file paths as strings) to avoid Path serialization issues.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_normalizer.py -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/trust/normalizer.py src/agentgate/trust/context.py tests/test_trust/test_normalizer.py
git commit -m "feat: add finding normalizer with severity override rules"
```

---

## Task 6: Confidence-Aware Policy

**Files:**
- Modify: `src/agentgate/trust/policy.py`
- Create: `tests/test_trust/test_policy_confidence.py`

- [ ] **Step 1: Write tests for new policy behavior**

```python
# tests/test_trust/test_policy_confidence.py
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity, TrustVerdict
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.signals import SignalContext


def _finding(severity, *, evidence="heuristic", confidence="high", reachability="on_execution_path", legacy=False):
    ctx = SignalContext(
        evidence_strength=evidence,
        attribution_confidence=confidence,
        reachability=reachability,
    )
    return TrustFinding(
        check_id="test_check",
        title="Test",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=severity,
        passed=False,
        summary="test",
        context=ctx,
        legacy_interpretation=legacy,
    )


def test_critical_strong_evidence_blocks():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="procfs_confirmed")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_critical_weak_evidence_manual_review():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="log_only", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_critical_heuristic_on_path_high_confidence_blocks():
    policy = TrustPolicy()
    findings = [_finding(
        TrustSeverity.CRITICAL,
        evidence="heuristic",
        confidence="high",
        reachability="on_execution_path",
    )]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_critical_heuristic_low_confidence_manual_review():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, evidence="heuristic", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_high_strong_manual_review():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.HIGH, evidence="procfs_confirmed")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_high_weak_allow_with_warnings():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.HIGH, evidence="log_only", confidence="low")]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_WITH_WARNINGS


def test_medium_allow_with_warnings():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.MEDIUM)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_WITH_WARNINGS


def test_info_only_allow_clean():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.INFO)]
    assert policy.verdict_for_findings(findings) == TrustVerdict.ALLOW_CLEAN


def test_legacy_single_critical_cannot_block():
    policy = TrustPolicy()
    findings = [_finding(TrustSeverity.CRITICAL, legacy=True)]
    # Single legacy finding cannot block — needs corroboration
    assert policy.verdict_for_findings(findings) == TrustVerdict.MANUAL_REVIEW


def test_legacy_critical_with_corroboration_blocks():
    policy = TrustPolicy()
    legacy = _finding(TrustSeverity.CRITICAL, legacy=True)
    legacy.check_id = "static_manifest"
    corroborating = _finding(TrustSeverity.HIGH, evidence="procfs_confirmed")
    corroborating.check_id = "runtime_egress"
    findings = [legacy, corroborating]
    assert policy.verdict_for_findings(findings) == TrustVerdict.BLOCK


def test_passed_findings_ignored():
    policy = TrustPolicy()
    passed = TrustFinding(
        check_id="test",
        title="OK",
        category=TrustCategory.HIDDEN_BEHAVIOR,
        severity=TrustSeverity.CRITICAL,
        passed=True,
        summary="all good",
    )
    assert policy.verdict_for_findings([passed]) == TrustVerdict.ALLOW_CLEAN


def test_no_findings_allow_clean():
    policy = TrustPolicy()
    assert policy.verdict_for_findings([]) == TrustVerdict.ALLOW_CLEAN
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_trust/test_policy_confidence.py -v`
Expected: Some tests FAIL (current policy doesn't check evidence strength).

- [ ] **Step 3: Rewrite policy.py**

Replace the `verdict_for_findings` method in `src/agentgate/trust/policy.py`:

```python
from __future__ import annotations

from dataclasses import dataclass

from agentgate.trust.models import TrustFinding, TrustSeverity, TrustVerdict, severity_counts
from agentgate.trust.signals import SignalContext, is_strong_evidence


@dataclass
class TrustPolicy:
    version: str = "trust-policy-v2"

    def verdict_for_findings(self, findings: list[TrustFinding]) -> TrustVerdict:
        failed = [f for f in findings if not f.passed]
        if not failed:
            return TrustVerdict.ALLOW_CLEAN

        has_block_evidence = False
        has_manual_review_evidence = False
        has_warnings = False

        # Check families that have strong high+ findings (for corroboration)
        strong_high_families: set[str] = set()

        for finding in failed:
            ctx = finding.context if isinstance(finding.context, SignalContext) else SignalContext()
            strong = is_strong_evidence(ctx)
            family = _check_family(finding.check_id)

            if finding.severity == TrustSeverity.CRITICAL:
                if finding.legacy_interpretation:
                    # Legacy critical needs corroboration — track but don't block yet
                    has_manual_review_evidence = True
                elif strong:
                    has_block_evidence = True
                else:
                    has_manual_review_evidence = True
            elif finding.severity == TrustSeverity.HIGH:
                if strong:
                    has_manual_review_evidence = True
                    strong_high_families.add(family)
                else:
                    has_warnings = True
            elif finding.severity == TrustSeverity.MEDIUM:
                has_warnings = True
            elif finding.severity == TrustSeverity.LOW:
                has_warnings = True

        # Legacy corroboration: a legacy critical can block if corroborated
        # by a strong high+ finding from a different check family
        if not has_block_evidence:
            legacy_criticals = [
                f for f in failed
                if f.severity == TrustSeverity.CRITICAL and f.legacy_interpretation
            ]
            for legacy in legacy_criticals:
                legacy_family = _check_family(legacy.check_id)
                if strong_high_families - {legacy_family}:
                    has_block_evidence = True
                    break

        if has_block_evidence:
            return TrustVerdict.BLOCK
        if has_manual_review_evidence:
            return TrustVerdict.MANUAL_REVIEW
        if has_warnings:
            return TrustVerdict.ALLOW_WITH_WARNINGS
        return TrustVerdict.ALLOW_CLEAN

    def should_fail(self, verdict: TrustVerdict, fail_on: str) -> bool:
        threshold = _parse_fail_on(fail_on)
        return verdict_rank(verdict) >= verdict_rank(threshold)

    def summary_counts(self, findings: list[TrustFinding]) -> dict[str, int]:
        return severity_counts(findings)


def _check_family(check_id: str) -> str:
    """Group check IDs into families for diversity-aware accumulation."""
    if check_id.startswith("static_"):
        return f"static_{check_id}"
    if check_id.startswith("runtime_"):
        return f"runtime_{check_id}"
    return check_id


def verdict_rank(verdict: TrustVerdict) -> int:
    return {
        TrustVerdict.ALLOW_CLEAN: 0,
        TrustVerdict.ALLOW_WITH_WARNINGS: 1,
        TrustVerdict.MANUAL_REVIEW: 2,
        TrustVerdict.BLOCK: 3,
    }.get(verdict, 0)


FAIL_ON_VALUES = {
    "allow_with_warnings": TrustVerdict.ALLOW_WITH_WARNINGS,
    "manual_review": TrustVerdict.MANUAL_REVIEW,
    "block": TrustVerdict.BLOCK,
}


def _parse_fail_on(value: str) -> TrustVerdict:
    return FAIL_ON_VALUES.get(value.strip().lower(), TrustVerdict.MANUAL_REVIEW)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_trust/test_policy_confidence.py -v`
Expected: All PASS.

- [ ] **Step 5: Run existing policy tests to check for regressions**

Run: `python -m pytest tests/test_trust/ -v -k policy`
Expected: All PASS (or update existing tests that assumed the old severity-only logic).

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/trust/policy.py tests/test_trust/test_policy_confidence.py
git commit -m "feat: rewrite policy with evidence-strength buckets and corroboration rule"
```

---

## Task 7: Rewrite static_code_signals to Emit TrustSignal

**Files:**
- Modify: `src/agentgate/trust/checks/static_code_signals.py`
- Modify: `tests/test_trust/test_checks_static_code_signals.py`

- [ ] **Step 1: Write test for signal-based output**

```python
# Add to tests/test_trust/test_checks_static_code_signals.py

async def test_emits_trust_signals(tmp_path):
    """Static code signals check should emit TrustSignal objects."""
    source = tmp_path / "src" / "agent"
    source.mkdir(parents=True)
    (source / "core.py").write_text("result = exec(user_input)\n")

    from agentgate.trust.checks.static_code_signals import StaticCodeSignalsCheck
    from agentgate.trust.config import TrustScanConfig

    config = TrustScanConfig(
        source_dir=tmp_path, image_ref="", manifest_path=None,
        output_dir=tmp_path / "out",
    )
    from agentgate.trust.context import TrustScanContext
    ctx = TrustScanContext(config=config)

    check = StaticCodeSignalsCheck()
    signals = check.scan_signals(ctx)
    assert len(signals) >= 1
    signal = signals[0]
    assert signal.signal_type == "pattern_match"
    assert signal.detection_method == "heuristic"
    assert "src/agent/core.py" in signal.source_location
    assert "exec" in signal.raw_evidence
```

- [ ] **Step 2: Add `scan_signals` method to StaticCodeSignalsCheck**

Modify `src/agentgate/trust/checks/static_code_signals.py` to add a `scan_signals` method that returns `list[TrustSignal]`, while keeping the existing `run` method working for backwards compatibility. The `run` method should call `scan_signals` internally and convert to `TrustFinding` via the normalizer.

```python
from agentgate.trust.signals import TrustSignal

class StaticCodeSignalsCheck(BaseTrustCheck):
    check_id = "static_code_signals"
    description = "Scans source code for obfuscation, anti-analysis, and suspicious patterns."

    def scan_signals(self, ctx: TrustScanContext) -> list[TrustSignal]:
        """Emit raw TrustSignal observations without severity interpretation."""
        signals: list[TrustSignal] = []
        source = ctx.source_dir
        if source is None or not source.exists():
            return signals

        for path in source.rglob("*.py"):
            if not path.is_file():
                continue
            relative = path.relative_to(source)
            if any(part.startswith(".") for part in relative.parts):
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue
            for label, severity, pattern in PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    # Extract the matched line for raw_evidence
                    lines = content.splitlines()
                    matched_line = lines[line_num - 1].strip() if line_num <= len(lines) else match.group()
                    signals.append(TrustSignal(
                        check_id=self.check_id,
                        signal_type="pattern_match",
                        title=f"Suspicious code signal ({label})",
                        summary=f"Matched pattern '{label}' in {relative.as_posix()}:{line_num}.",
                        raw_evidence=matched_line[:200],
                        detection_method="heuristic",
                        source_location=f"{relative.as_posix()}:{line_num}",
                        base_severity=severity,
                        category=TrustCategory.HIDDEN_BEHAVIOR,
                        recommendation="Review the flagged code for security implications.",
                    ))
        return signals

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        source = ctx.source_dir
        if source is None or not source.exists():
            return [self.finding(
                title="Source code not available",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="No source directory provided for code signal analysis.",
            )]

        signals = self.scan_signals(ctx)
        if not signals:
            file_count = sum(1 for _ in source.rglob("*.py") if _.is_file())
            return [self.finding(
                title="No suspicious code signals detected",
                category=TrustCategory.HIDDEN_BEHAVIOR,
                severity=TrustSeverity.INFO,
                passed=True,
                summary=f"Scanned {file_count} Python files with no risky pattern matches.",
            )]

        # Convert signals to findings — normalizer will adjust severity later
        from agentgate.trust.normalizer import normalize_finding
        file_map = {str(k): v for k, v in ctx.file_classification.items()} if ctx.file_classification else {}
        reach_map = {str(k): v for k, v in ctx.reachability_graph.items()} if ctx.reachability_graph else {}

        findings: list[TrustFinding] = []
        for signal in signals:
            findings.append(normalize_finding(signal, file_map=file_map, reachability_map=reach_map))
        return findings
```

- [ ] **Step 3: Run tests**

Run: `python -m pytest tests/test_trust/test_checks_static_code_signals.py -v`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add src/agentgate/trust/checks/static_code_signals.py tests/test_trust/test_checks_static_code_signals.py
git commit -m "feat: rewrite static_code_signals to emit TrustSignal with source context"
```

---

## Task 8: Rewrite runtime_egress to Emit TrustSignal

**Files:**
- Modify: `src/agentgate/trust/checks/runtime_egress.py`
- Test: existing egress tests + new signal tests

- [ ] **Step 1: Write test for destination-classified egress signals**

```python
# Add to tests or create tests/test_trust/test_egress_signals.py

async def test_railway_internal_ip_classified():
    """Internal Railway IPs should be classified as platform_internal_verified."""
    # Setup: create a mock context with runtime traces showing 10.x.x.x connections
    # and deployment_result with known internal IPs
    # Assert: the finding severity is INFO, not CRITICAL
    # Assert: context.destination_class == "platform_internal_verified"
    pass  # Implement with actual context setup
```

- [ ] **Step 2: Modify RuntimeEgressCheck to use destination taxonomy**

Add a `scan_signals` method similar to Task 7. The key change: instead of immediately creating CRITICAL findings for undeclared destinations, emit `TrustSignal` with destination metadata. Let the normalizer handle severity via `destination_taxonomy.classify_destination()`.

Key integration points:
- Build `verified_internal_ips` from `ctx.deployment_result` and `ctx.hosted_runtime_context`
- Build `telemetry_registry` from the repo's dependencies (read from `ctx.config.dependencies` or parse requirements files)
- Build `declared_domains` from manifest + config allowlist
- Set `runtime_attribution` based on timing (startup vs request_time)
- Set `evidence_strength` based on source (procfs_confirmed vs log_only vs dns_only)

- [ ] **Step 3: Run all egress tests**

Run: `python -m pytest tests/ -v -k egress`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add src/agentgate/trust/checks/runtime_egress.py tests/
git commit -m "feat: rewrite runtime_egress with destination taxonomy and evidence provenance"
```

---

## Task 9: Wire Normalizer into Scanner

**Files:**
- Modify: `src/agentgate/trust/scanner.py`
- Modify: `tests/test_trust/test_scanner.py`

- [ ] **Step 1: Write test for normalizer wiring**

```python
# Add to tests/test_trust/test_scanner.py

async def test_scanner_builds_file_classification():
    """Scanner should build file classification and reachability on context."""
    # Setup a TrustScanConfig with a source_dir containing test files and runtime files
    # Assert ctx.file_classification is populated after _prepare_context
    pass

async def test_scanner_normalizes_legacy_checks():
    """Legacy checks should be tagged with legacy_interpretation=True."""
    # Run scanner with legacy checks
    # Assert findings from legacy checks have legacy_interpretation=True
    pass
```

- [ ] **Step 2: Modify scanner.py to build classification + reachability in _prepare_context**

In `TrustScanner._prepare_context()`, after `ctx.infer_runtime_config_from_source()`, add:

```python
from agentgate.trust.file_classifier import classify_repo
from agentgate.trust.reachability import build_reachability

file_map = classify_repo(ctx.source_dir)
ctx.file_classification = {str(k): v for k, v in file_map.items()}

entrypoint = ""
if ctx.generated_runtime_profile is not None:
    entrypoint = ctx.generated_runtime_profile.entrypoint
if entrypoint:
    reach_map = build_reachability(ctx.source_dir, entrypoint)
    ctx.reachability_graph = {str(k): v for k, v in reach_map.items()}
```

- [ ] **Step 3: Tag legacy check findings in the check loop**

In `TrustScanner.run()`, after a check produces findings and before they're added to the findings list, tag findings from checks that don't emit signals natively:

```python
SIGNAL_NATIVE_CHECKS = {"static_code_signals", "runtime_egress"}

for check_finding in check_findings:
    if check.check_id not in SIGNAL_NATIVE_CHECKS:
        from agentgate.trust.normalizer import tag_legacy_finding
        tag_legacy_finding(check_finding)
```

- [ ] **Step 4: Run scanner tests**

Run: `python -m pytest tests/test_trust/test_scanner.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/scanner.py src/agentgate/trust/context.py tests/test_trust/test_scanner.py
git commit -m "feat: wire normalizer into scanner — build classification and tag legacy findings"
```

---

## Task 10: API + Webhook Coverage Fields

**Files:**
- Modify: `src/agentgate/server/models.py`
- Modify: `src/agentgate/server/webhook.py`
- Modify: `src/agentgate/server/routes/scans.py`
- Test: `tests/test_server/test_models.py`, `tests/test_server/test_routes.py`

- [ ] **Step 1: Add coverage fields to ScanResponse**

In `src/agentgate/server/models.py`, add to `ScanResponse`:

```python
    coverage_status: str | None = None          # full, partial, limited
    coverage_recommendation: str | None = None  # manual_review when limited + non-block
```

- [ ] **Step 2: Add coverage fields to WebhookPayload**

In `src/agentgate/server/models.py`, add to `WebhookPayload`:

```python
    coverage_status: str | None = None
    coverage_recommendation: str | None = None
```

- [ ] **Step 3: Update webhook delivery to include coverage fields**

In `src/agentgate/server/webhook.py`, update `deliver_webhook` signature and payload construction to accept and include `coverage_status` and `coverage_recommendation`.

- [ ] **Step 4: Update scan response builder in routes/scans.py**

In the `_scan_row_to_response` function, map coverage fields from the scan row/report into the response.

- [ ] **Step 5: Run server tests**

Run: `python -m pytest tests/test_server/ -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/server/models.py src/agentgate/server/webhook.py src/agentgate/server/routes/scans.py tests/test_server/
git commit -m "feat: add coverage_status and coverage_recommendation to API and webhooks"
```

---

## Task 11: Specialist Dispatch Gating

**Files:**
- Modify: `src/agentgate/trust/runtime/adaptive/orchestrator.py`
- Modify: `src/agentgate/trust/runtime/adaptive/models.py`
- Test: `tests/test_trust/test_orchestrator.py`

- [ ] **Step 1: Add SpecialistDispatchResult to models**

In `src/agentgate/trust/runtime/adaptive/models.py`:

```python
@dataclass
class SpecialistDispatchResult:
    specialist: str
    status: str        # executed, skipped, failed
    skip_reason: str = ""
    precondition: str = ""
```

- [ ] **Step 2: Add health gate to orchestrator**

In `AdaptiveProbeOrchestrator`, add a `_run_health_gate` method that sends 2-3 probes to discovered routes and returns whether the agent is responsive. Distinguish application responses (any status from the agent process) from infrastructure proxy errors (Railway 502 "Application failed to respond").

- [ ] **Step 3: Add precondition checks per specialist**

Before running each specialist, check its precondition. If unmet, record a `SpecialistDispatchResult` with `status="skipped"` and continue. Return dispatch results alongside specialist reports.

- [ ] **Step 4: Run orchestrator tests**

Run: `python -m pytest tests/test_trust/test_orchestrator.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/runtime/adaptive/orchestrator.py src/agentgate/trust/runtime/adaptive/models.py tests/test_trust/test_orchestrator.py
git commit -m "feat: add health gate and specialist preconditions to orchestrator"
```

---

## Task 12: LLM Trust Adjudicator (Phase 2)

**Files:**
- Create: `src/agentgate/trust/adjudicator.py`
- Test: `tests/test_trust/test_adjudicator.py`

- [ ] **Step 1: Write tests for adjudicator**

Test that the adjudicator:
- Returns an `AdjudicatorResult` with adjusted severity and rationale
- Respects budget cap (returns None after N calls)
- Handles LLM errors gracefully (returns None, keeps heuristic classification)

- [ ] **Step 2: Implement TrustAdjudicator**

Separate from `LLMJudge`. Uses narrow, structured prompts for specific adjudication questions:
- "Is this pattern in a test fixture or a live code path?"
- "Is this domain framework telemetry or unknown external?"

Budget-capped at N calls per scan (configurable, default 5). Returns `AdjudicatorResult` or `None` if budget exhausted.

- [ ] **Step 3: Wire into normalizer for irreversible-downgrade cases**

In `normalizer.py`, before applying a 2+ band downgrade with `attribution_confidence` != high, call the adjudicator.

- [ ] **Step 4: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/adjudicator.py tests/test_trust/test_adjudicator.py src/agentgate/trust/normalizer.py
git commit -m "feat: add LLM trust adjudicator for boundary-case findings"
```

---

## Task 13: Integration Test — Full Pipeline

- [ ] **Step 1: Write end-to-end test**

Create a test that:
1. Sets up a source dir with a test file containing `exec()` and a runtime file with `os.system()`
2. Runs the full `TrustScanner.run()` pipeline
3. Asserts the test-file finding has `severity=INFO` and the runtime-file finding keeps `severity=HIGH`
4. Asserts the verdict accounts for evidence strength

- [ ] **Step 2: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: add integration test for full finding interpretation pipeline"
```

- [ ] **Step 4: Deploy to Railway and test with agent-service-toolkit**

Redeploy the API and worker, then re-scan `agent-service-toolkit`. Verify:
- The prompt injection pattern (in test file) is now INFO, not HIGH
- Railway internal IPs are INFO, not CRITICAL
- Streamlit telemetry is INFO, not CRITICAL
- The verdict is NOT `block`
