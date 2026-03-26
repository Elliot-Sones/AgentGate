from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeResult,
    SpecialistReport,
)
from agentgate.trust.runtime.adaptive.orchestrator import AdaptiveProbeOrchestrator


def _make_bundle() -> ContextBundle:
    return ContextBundle(
        source_files={
            "agent.py": "def lookup_order(oid): return {'status': 'shipped'}\n",
            "server.py": "@app.post('/api/v1/chat')\nasync def chat(req): pass\n",
        },
        manifest={"agent_name": "TestAgent", "declared_tools": ["lookup_order"]},
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={"FAKE_KEY": "canary123"},
        declared_tools=["lookup_order"],
        declared_domains=[],
        customer_data_access=["orders"],
        permissions=["read_orders"],
    )


def _mock_anthropic_client(responses: list[str]) -> MagicMock:
    client = MagicMock()
    call_count = 0

    def create_message(**kwargs):
        nonlocal call_count
        msg = MagicMock()
        text = responses[min(call_count, len(responses) - 1)]
        msg.content = [MagicMock(text=text)]
        call_count += 1
        return msg

    client.messages.create = MagicMock(side_effect=create_message)
    return client


def test_orchestrator_parse_dispatch_plan() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    plan_json = json.dumps(
        {
            "phases": [
                {
                    "agents": ["tool_exerciser", "egress_prober"],
                    "parallel": True,
                    "reason": "Independent",
                },
                {"agents": ["canary_stresser"], "parallel": False, "reason": "Needs warmup"},
            ]
        }
    )

    plan = orchestrator._parse_dispatch_plan(plan_json)
    assert len(plan.phases) == 2
    assert plan.phases[0].parallel is True
    assert "canary_stresser" in plan.phases[1].agents


def test_orchestrator_parse_dispatch_plan_bad_json() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    plan = orchestrator._parse_dispatch_plan("not json")
    assert len(plan.phases) >= 1


def test_orchestrator_build_profile_prompt() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = _make_bundle()
    prompt = orchestrator._build_profile_prompt(bundle)

    assert "lookup_order" in prompt
    assert "orders" in prompt
    assert "agent.py" in prompt


def test_orchestrator_all_probe_results_collected() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")

    reports = [
        SpecialistReport(
            specialist="tool_exerciser",
            probes_sent=3,
            probes_succeeded=3,
            probe_results=[
                ProbeResult(
                    specialist="tool_exerciser",
                    method="POST",
                    path="/api/v1/chat",
                    request_body={"question": "test"},
                    status_code=200,
                    response_body="ok",
                    content_type="application/json",
                )
            ],
            findings=[],
            severity="info",
        ),
        SpecialistReport(
            specialist="egress_prober",
            probes_sent=2,
            probes_succeeded=1,
            probe_results=[
                ProbeResult(
                    specialist="egress_prober",
                    method="POST",
                    path="/api/v1/chat",
                    request_body={"question": "fetch"},
                    status_code=200,
                    response_body="nope",
                    content_type="application/json",
                )
            ],
            findings=["Undeclared egress detected"],
            severity="critical",
        ),
    ]

    all_results = orchestrator._collect_probe_responses(reports)
    assert len(all_results) == 2
    assert all_results[0]["specialist"] == "tool_exerciser"
    assert all_results[1]["specialist"] == "egress_prober"


def test_orchestrator_run_specialist() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = _make_bundle()

    generation_response = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "Order #123?"},
                    "rationale": "test",
                }
            ]
        }
    )
    analysis_response = json.dumps(
        {
            "findings": ["Tool lookup_order fired correctly"],
            "evidence": ["TOOL_CALL:lookup_order in logs"],
            "severity": "info",
        }
    )

    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "shipped"}'
    mock_http_response.headers = {"content-type": "application/json"}

    with (
        patch.object(orchestrator, "_get_client", return_value=mock_client),
        patch("httpx.Client") as MockHTTPClient,
    ):
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.request.return_value = mock_http_response
        MockHTTPClient.return_value = mock_http

        report = orchestrator._run_specialist("tool_exerciser", bundle)

    assert report.specialist == "tool_exerciser"


def test_orchestrator_run_specialist_uses_fallback_probes_when_llm_returns_none() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = ContextBundle(
        source_files={},
        manifest={"agent_name": "Mem0Like"},
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={},
        openapi_spec={
            "openapi": "3.1.0",
            "paths": {
                "/search": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"query": {"type": "string"}},
                                        "required": ["query"],
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
    )

    generation_response = '{"probes": []}'
    analysis_response = json.dumps(
        {"findings": [], "evidence": [], "severity": "info"}
    )
    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"results": []}'
    mock_http_response.headers = {"content-type": "application/json"}

    with (
        patch.object(orchestrator, "_get_client", return_value=mock_client),
        patch("httpx.Client") as MockHTTPClient,
    ):
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.request.return_value = mock_http_response
        MockHTTPClient.return_value = mock_http

        report = orchestrator._run_specialist("egress_prober", bundle)

    assert report.specialist == "egress_prober"
    assert report.probes_sent > 0
    assert report.probe_results[0].path == "/search"


def test_orchestrator_passes_logs_to_analysis() -> None:
    orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
    bundle = _make_bundle()

    generation_response = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "Order #123?"},
                    "rationale": "test",
                }
            ]
        }
    )
    analysis_response = json.dumps(
        {
            "findings": ["Hidden tool call detected"],
            "evidence": ["TOOL_CALL:hidden_exfil in logs"],
            "severity": "critical",
        }
    )

    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "shipped"}'
    mock_http_response.headers = {"content-type": "application/json"}

    railway_logs = "TOOL_CALL:lookup_order\nTOOL_CALL:hidden_exfil\n"

    with (
        patch.object(orchestrator, "_get_client", return_value=mock_client),
        patch("httpx.Client") as MockHTTPClient,
    ):
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

    generation_response = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "test"},
                    "rationale": "test",
                }
            ]
        }
    )
    analysis_response = json.dumps(
        {"findings": [], "evidence": [], "severity": "info"}
    )

    mock_client = _mock_anthropic_client([generation_response, analysis_response])

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "ok"}'
    mock_http_response.headers = {"content-type": "application/json"}

    with (
        patch.object(orchestrator, "_get_client", return_value=mock_client),
        patch("httpx.Client") as MockHTTPClient,
    ):
        mock_http = MagicMock()
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        mock_http.request.return_value = mock_http_response
        MockHTTPClient.return_value = mock_http

        report = orchestrator._run_specialist("tool_exerciser", bundle)

    assert report.railway_logs == ""
