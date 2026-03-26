from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from agentgate.trust.runtime.adaptive.orchestrator import AdaptiveProbeOrchestrator
from agentgate.trust.runtime.adaptive.context_builder import ContextBuilder


def _make_bundle(tmp_path: Path):
    agent_py = tmp_path / "agent.py"
    agent_py.write_text(
        "import os\n"
        "class SupportAgent:\n"
        "    def process(self, question):\n"
        "        if 'order' in question:\n"
        "            print('TOOL_CALL:lookup_order')\n"
        "            return {'answer': 'Order shipped', 'data': []}\n"
        "        return {'answer': 'I can help with orders', 'data': []}\n"
    )
    server_py = tmp_path / "server.py"
    server_py.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/api/v1/chat')\n"
        "async def chat(req): pass\n"
    )

    return ContextBuilder.build(
        source_dir=tmp_path,
        manifest={
            "agent_name": "ShopFlow Support Agent",
            "declared_tools": ["lookup_order", "search_products"],
            "declared_external_domains": [],
            "customer_data_access": ["orders", "products"],
            "permissions": ["read_orders", "read_products"],
        },
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={"FAKE_KEY": "canary123"},
    )


def _mock_llm_responses():
    # 1. Orchestrator dispatch plan
    plan = json.dumps(
        {
            "phases": [
                {"agents": ["tool_exerciser"], "parallel": False, "reason": "Test tools first"},
            ]
        }
    )

    # 2. Tool exerciser probe generation
    probes = json.dumps(
        {
            "probes": [
                {
                    "method": "POST",
                    "path": "/api/v1/chat",
                    "body": {"question": "What is the status of order #ORD-1234?"},
                    "rationale": "Trigger lookup_order",
                }
            ]
        }
    )

    # 3. Tool exerciser analysis
    analysis = json.dumps(
        {
            "findings": [],
            "evidence": ["TOOL_CALL:lookup_order observed in response"],
            "severity": "info",
        }
    )

    return [plan, probes, analysis]


def test_full_orchestrator_pipeline(tmp_path: Path) -> None:
    bundle = _make_bundle(tmp_path)
    responses = _mock_llm_responses()

    call_idx = 0

    def mock_create(**kwargs):
        nonlocal call_idx
        msg = MagicMock()
        msg.content = [MagicMock(text=responses[min(call_idx, len(responses) - 1)])]
        call_idx += 1
        return msg

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.text = '{"answer": "Order shipped", "data": []}'
    mock_http_response.headers = {"content-type": "application/json"}

    with patch("agentgate.trust.runtime.adaptive.orchestrator.anthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_client.messages.create = MagicMock(side_effect=mock_create)
        mock_anthropic.Anthropic.return_value = mock_client

        with patch("httpx.Client") as MockHTTPClient:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.request.return_value = mock_http_response
            MockHTTPClient.return_value = mock_http

            orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
            probe_responses, reports = orchestrator.run(bundle)

    # Verify we got probe responses
    assert len(probe_responses) >= 1
    assert probe_responses[0]["status_code"] == 200

    # Verify specialist reports
    assert len(reports) == 1
    assert reports[0].specialist == "tool_exerciser"
    assert reports[0].probes_sent == 1
    assert reports[0].probes_succeeded == 1

    # Verify LLM was called 3 times: plan, generate, analyze
    assert call_idx == 3
