from __future__ import annotations

import json

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeResult,
)
from agentgate.trust.runtime.adaptive.specialists.tool_exerciser import ToolExerciser


def _make_context(**kwargs) -> ContextBundle:
    defaults = dict(
        source_files={"agent.py": "def handle(q): pass"},
        manifest=None,
        static_findings=[],
        live_url="http://localhost:8000",
        canary_tokens={"CANARY_KEY": "canary-val-xyz"},
        declared_tools=["search_knowledge_base", "send_email"],
        declared_domains=["example.com"],
        customer_data_access=["user_profile", "order_history"],
        permissions=["read:orders"],
    )
    defaults.update(kwargs)
    return ContextBundle(**defaults)


def test_build_generation_prompt_includes_tools() -> None:
    specialist = ToolExerciser()
    ctx = _make_context()
    prompt = specialist.build_generation_prompt(ctx)
    assert "search_knowledge_base" in prompt
    assert "send_email" in prompt
    assert "user_profile" in prompt


def test_parse_probe_requests_from_json() -> None:
    specialist = ToolExerciser()
    llm_response = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "Search for account info"},
                    "rationale": "Exercises search_knowledge_base tool",
                },
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "What is the weather today?"},
                    "rationale": "Should NOT trigger any tool",
                },
            ]
        }
    )
    probes = specialist.parse_probe_requests(llm_response)
    assert len(probes) == 2
    assert probes[0].method == "POST"
    assert probes[0].path == "/api/v1/chat"
    assert probes[0].body == {"question": "Search for account info"}
    assert "search_knowledge_base" in probes[0].rationale
    assert probes[0].specialist == "tool_exerciser"


def test_parse_probe_requests_handles_bad_json() -> None:
    specialist = ToolExerciser()
    assert specialist.parse_probe_requests("not valid json at all") == []
    assert specialist.parse_probe_requests("{}") == []
    assert specialist.parse_probe_requests('{"probes": "wrong type"}') == []


def test_build_analysis_prompt_includes_results() -> None:
    specialist = ToolExerciser()
    ctx = _make_context()
    results = [
        ProbeResult(
            specialist="tool_exerciser",
            method="POST",
            path="/api/v1/chat",
            request_body={"question": "Search for account info"},
            status_code=200,
            response_body='{"answer": "Here is what I found..."}',
            content_type="application/json",
        )
    ]
    prompt = specialist.build_analysis_prompt(ctx, results)
    assert "Search for account info" in prompt
    assert "Here is what I found" in prompt


def test_parse_analysis_extracts_findings() -> None:
    specialist = ToolExerciser()
    llm_response = json.dumps(
        {
            "findings": ["Tool invoked with unexpected data", "Possible over-triggering"],
            "evidence": ["Response contained PII", "Tool called 3 times"],
            "severity": "medium",
        }
    )
    report = specialist.parse_analysis(llm_response)
    assert report.specialist == "tool_exerciser"
    assert len(report.findings) == 2
    assert "Tool invoked with unexpected data" in report.findings
    assert report.severity == "medium"
    assert len(report.evidence) == 2


def test_parse_analysis_handles_bad_json() -> None:
    specialist = ToolExerciser()
    report = specialist.parse_analysis("not json")
    assert report.specialist == "tool_exerciser"
    assert report.findings == []
    assert report.evidence == []
    assert report.severity == "info"
