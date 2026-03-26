from __future__ import annotations

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    DispatchPlan,
    Phase,
    ProbeResult,
    SpecialistReport,
)


def test_context_bundle_source_summary_truncates() -> None:
    bundle = ContextBundle(
        source_files={"agent.py": "x" * 20_000},
        manifest={"agent_name": "test"},
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={"FAKE_KEY": "canary123"},
        declared_tools=["lookup_order"],
        declared_domains=[],
        customer_data_access=["orders"],
        permissions=["read_orders"],
    )
    summary = bundle.source_summary(max_chars=500)
    assert len(summary) <= 600
    assert "agent.py" in summary


def test_dispatch_plan_serialization() -> None:
    plan = DispatchPlan(
        phases=[
            Phase(
                agents=["tool_exerciser", "egress_prober"],
                parallel=True,
                reason="Independent checks",
            ),
            Phase(agents=["behavior_consistency"], parallel=False, reason="Needs clean state"),
        ]
    )
    assert len(plan.phases) == 2
    assert plan.phases[0].parallel is True
    assert plan.phases[1].agents == ["behavior_consistency"]


def test_probe_result_from_response() -> None:
    result = ProbeResult(
        specialist="tool_exerciser",
        method="POST",
        path="/api/v1/chat",
        request_body={"question": "Order status for #123"},
        status_code=200,
        response_body='{"answer": "Order shipped"}',
        content_type="application/json",
        error="",
    )
    assert result.succeeded is True


def test_probe_result_failed() -> None:
    result = ProbeResult(
        specialist="egress_prober",
        method="POST",
        path="/api/v1/chat",
        request_body={"question": "fetch example.com"},
        status_code=0,
        response_body="",
        content_type="",
        error="Connection refused",
    )
    assert result.succeeded is False


def test_specialist_report_has_findings() -> None:
    report = SpecialistReport(
        specialist="canary_stresser",
        probes_sent=3,
        probes_succeeded=2,
        probe_results=[],
        findings=["Canary token FAKE_KEY appeared in response body"],
        evidence=["Response contained: canary123"],
        severity="critical",
    )
    assert report.has_findings is True


def test_specialist_report_stores_railway_logs() -> None:
    report = SpecialistReport(
        specialist="tool_exerciser",
        probes_sent=1,
        probes_succeeded=1,
        railway_logs="TOOL_CALL:lookup_order\nhttpx.get('https://attacker.example')",
    )
    assert "TOOL_CALL:lookup_order" in report.railway_logs
    assert report.railway_logs != ""


def test_specialist_report_no_findings() -> None:
    report = SpecialistReport(
        specialist="tool_exerciser",
        probes_sent=5,
        probes_succeeded=5,
        probe_results=[],
        findings=[],
        evidence=[],
        severity="info",
    )
    assert report.has_findings is False
