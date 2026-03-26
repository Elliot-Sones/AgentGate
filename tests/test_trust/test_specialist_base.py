from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeRequest,
    ProbeResult,
    SpecialistReport,
)
from agentgate.trust.runtime.adaptive.specialists.base import BaseSpecialist


class StubSpecialist(BaseSpecialist):
    name = "stub"
    description = "Stub for testing"
    system_prompt = "You are a test specialist."

    def build_generation_prompt(self, context: ContextBundle) -> str:
        return "Generate a probe for this agent."

    def parse_probe_requests(self, llm_response: str) -> list[ProbeRequest]:
        return [
            ProbeRequest(
                specialist="stub",
                method="POST",
                path="/api/v1/chat",
                body={"question": "test probe"},
                rationale="Testing",
            )
        ]

    def build_analysis_prompt(self, context: ContextBundle, results: list[ProbeResult]) -> str:
        return "Analyze these results."

    def parse_analysis(self, llm_response: str) -> SpecialistReport:
        return SpecialistReport(
            specialist="stub",
            probes_sent=1,
            probes_succeeded=1,
            findings=["Found issue"],
            evidence=["evidence"],
            severity="medium",
        )


def test_specialist_execute_probes() -> None:
    specialist = StubSpecialist()
    probes = [
        ProbeRequest(
            specialist="stub",
            method="POST",
            path="/api/v1/chat",
            body={"question": "test"},
        )
    ]

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"answer": "hello"}'
    mock_response.headers = {"content-type": "application/json"}

    with patch.object(httpx.Client, "request", return_value=mock_response):
        results = specialist.execute_probes(
            probes=probes,
            base_url="https://agent.example.com",
            timeout=5,
        )

    assert len(results) == 1
    assert results[0].succeeded is True
    assert results[0].status_code == 200


def test_specialist_execute_probes_handles_error() -> None:
    specialist = StubSpecialist()
    probes = [
        ProbeRequest(
            specialist="stub",
            method="POST",
            path="/api/v1/chat",
            body={"question": "test"},
        )
    ]

    with patch.object(httpx.Client, "request", side_effect=httpx.ConnectError("refused")):
        results = specialist.execute_probes(
            probes=probes,
            base_url="https://agent.example.com",
            timeout=5,
        )

    assert len(results) == 1
    assert results[0].succeeded is False
    assert "refused" in results[0].error


def test_specialist_call_llm() -> None:
    specialist = StubSpecialist()

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="LLM response text")]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message

    result = specialist.call_llm(
        client=mock_client,
        user_prompt="Test prompt",
        model="claude-sonnet-4-6",
    )

    assert result == "LLM response text"
    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"
    assert call_kwargs["system"] == "You are a test specialist."
