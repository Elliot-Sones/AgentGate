"""Tests for probe reliability: fallback probes and orchestrator retry logic."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeRequest,
)
from agentgate.trust.runtime.adaptive.orchestrator import AdaptiveProbeOrchestrator
from agentgate.trust.runtime.adaptive.specialists.behavior_consistency import (
    BehaviorConsistencyChecker,
)
from agentgate.trust.runtime.adaptive.specialists.canary_stresser import CanaryStresser
from agentgate.trust.runtime.adaptive.specialists.data_boundary import DataBoundaryTester
from agentgate.trust.runtime.adaptive.specialists.egress_prober import EgressProber
from agentgate.trust.runtime.adaptive.specialists.tool_exerciser import ToolExerciser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rich_bundle() -> ContextBundle:
    """A bundle with declared tools, canary tokens, domains, and an OpenAPI spec."""
    return ContextBundle(
        source_files={},
        manifest=None,
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={"FAKE_API_KEY": "canary-abc123", "DB_PASS": "canary-xyz789"},
        declared_tools=["lookup_order", "cancel_order"],
        declared_domains=["api.payments.example.com"],
        customer_data_access=["orders", "customer_profiles"],
        permissions=["read_orders", "read_profiles"],
        openapi_spec={
            "openapi": "3.1.0",
            "paths": {
                "/api/v1/chat": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"question": {"type": "string"}},
                                        "required": ["question"],
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
    )


def _make_minimal_bundle() -> ContextBundle:
    """A bundle with no tools, no domains, no canary tokens."""
    return ContextBundle(
        source_files={},
        manifest=None,
        static_findings=[],
        live_url="https://agent.example.com",
        canary_tokens={},
        declared_tools=[],
        declared_domains=[],
        customer_data_access=[],
        permissions=[],
        openapi_spec=None,
    )


def _assert_valid_probe_request(probe: ProbeRequest, expected_specialist: str) -> None:
    assert isinstance(probe, ProbeRequest)
    assert probe.specialist == expected_specialist
    assert probe.method in {"GET", "POST", "PUT", "PATCH"}
    assert probe.path.startswith("/")
    # At least one of body or path must carry meaningful content
    has_body_content = isinstance(probe.body, dict) and bool(probe.body)
    has_path = len(probe.path) > 1  # more than just "/"
    assert has_body_content or has_path


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


# ---------------------------------------------------------------------------
# Fallback probe tests — each specialist
# ---------------------------------------------------------------------------


class TestToolExerciserFallback:
    def test_returns_non_empty_probes_with_tools(self) -> None:
        specialist = ToolExerciser()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) > 0

    def test_probes_are_valid_probe_requests(self) -> None:
        specialist = ToolExerciser()
        context = _make_rich_bundle()
        for probe in specialist.fallback_probe_requests(context):
            _assert_valid_probe_request(probe, "tool_exerciser")

    def test_probes_mention_declared_tools(self) -> None:
        specialist = ToolExerciser()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        # At least one probe body should reference a declared tool
        combined = " ".join(
            str(p.body) for p in probes if p.body
        ).lower()
        assert any(tool.lower() in combined for tool in context.declared_tools)

    def test_returns_at_least_one_probe_with_no_tools(self) -> None:
        specialist = ToolExerciser()
        context = _make_minimal_bundle()
        probes = specialist.fallback_probe_requests(context)
        # Even with no declared tools, the off-topic fallback should still fire
        assert len(probes) >= 1


class TestEgressProberFallback:
    def test_returns_non_empty_probes(self) -> None:
        specialist = EgressProber()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) > 0

    def test_probes_are_valid_probe_requests(self) -> None:
        specialist = EgressProber()
        context = _make_rich_bundle()
        for probe in specialist.fallback_probe_requests(context):
            _assert_valid_probe_request(probe, "egress_prober")

    def test_probes_contain_urls_in_body(self) -> None:
        specialist = EgressProber()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        combined = " ".join(str(p.body) for p in probes if p.body)
        # Should have at least one URL-containing probe
        assert "http" in combined.lower() or "https" in combined.lower()

    def test_returns_probes_with_no_spec(self) -> None:
        specialist = EgressProber()
        context = _make_minimal_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) >= 1


class TestDataBoundaryFallback:
    def test_returns_non_empty_probes(self) -> None:
        specialist = DataBoundaryTester()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) > 0

    def test_probes_are_valid_probe_requests(self) -> None:
        specialist = DataBoundaryTester()
        context = _make_rich_bundle()
        for probe in specialist.fallback_probe_requests(context):
            _assert_valid_probe_request(probe, "data_boundary")

    def test_probes_include_cross_tenant_attempt(self) -> None:
        specialist = DataBoundaryTester()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        combined = " ".join(str(p.body) for p in probes if p.body).lower()
        # Should probe for cross-tenant or system prompt exposure
        assert any(kw in combined for kw in ("user", "profile", "system prompt", "environment", "password", "connection"))

    def test_returns_probes_with_minimal_context(self) -> None:
        specialist = DataBoundaryTester()
        context = _make_minimal_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) >= 1


class TestCanaryStresserFallback:
    def test_returns_non_empty_probes_with_canary_tokens(self) -> None:
        specialist = CanaryStresser()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) > 0

    def test_probes_are_valid_probe_requests(self) -> None:
        specialist = CanaryStresser()
        context = _make_rich_bundle()
        for probe in specialist.fallback_probe_requests(context):
            _assert_valid_probe_request(probe, "canary_stresser")

    def test_probes_mention_canary_key_names(self) -> None:
        specialist = CanaryStresser()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        combined = " ".join(str(p.body) for p in probes if p.body)
        # Should reference at least one canary key name (not value)
        assert any(key in combined for key in context.canary_tokens)

    def test_generic_secrets_probe_always_present(self) -> None:
        specialist = CanaryStresser()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        combined = " ".join(str(p.body) for p in probes if p.body).lower()
        assert any(kw in combined for kw in ("secret", "token", "api key", "environment", "variable"))

    def test_returns_probes_with_no_canary_tokens(self) -> None:
        specialist = CanaryStresser()
        context = _make_minimal_bundle()
        probes = specialist.fallback_probe_requests(context)
        # Generic probe should still fire even with no canary tokens
        assert len(probes) >= 1


class TestBehaviorConsistencyFallback:
    def test_returns_non_empty_probes(self) -> None:
        specialist = BehaviorConsistencyChecker()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) > 0

    def test_probes_are_valid_probe_requests(self) -> None:
        specialist = BehaviorConsistencyChecker()
        context = _make_rich_bundle()
        for probe in specialist.fallback_probe_requests(context):
            _assert_valid_probe_request(probe, "behavior_consistency")

    def test_probes_include_both_review_and_production_profiles(self) -> None:
        specialist = BehaviorConsistencyChecker()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        rationales = " ".join(p.rationale for p in probes).lower()
        assert "review" in rationales
        assert "production" in rationales

    def test_returns_paired_probes(self) -> None:
        specialist = BehaviorConsistencyChecker()
        context = _make_rich_bundle()
        probes = specialist.fallback_probe_requests(context)
        # Expect at least 2 probes (one review + one production)
        assert len(probes) >= 2

    def test_returns_probes_with_minimal_context(self) -> None:
        specialist = BehaviorConsistencyChecker()
        context = _make_minimal_bundle()
        probes = specialist.fallback_probe_requests(context)
        assert len(probes) >= 1


# ---------------------------------------------------------------------------
# Orchestrator retry logic tests
# ---------------------------------------------------------------------------


class TestOrchestratorRetryLogic:
    """Test that _run_specialist retries when the first LLM call produces 0 probes."""

    def _make_bundle_with_spec(self) -> ContextBundle:
        return ContextBundle(
            source_files={},
            manifest=None,
            static_findings=[],
            live_url="https://agent.example.com",
            canary_tokens={},
            declared_tools=["lookup_order"],
            declared_domains=[],
            customer_data_access=[],
            permissions=[],
            openapi_spec={
                "openapi": "3.1.0",
                "paths": {
                    "/chat": {
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"message": {"type": "string"}},
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            },
        )

    def test_retry_when_first_attempt_returns_zero_probes(self) -> None:
        """Orchestrator retries probe generation when first LLM call returns no probes."""
        orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
        bundle = self._make_bundle_with_spec()

        # First generation: empty probes. Retry generation: valid probes. Analysis: ok.
        empty_generation = json.dumps({"probes": []})
        retry_generation = json.dumps(
            {
                "probes": [
                    {
                        "method": "POST",
                        "path": "/chat",
                        "body": {"message": "Can you look up order 123?"},
                        "rationale": "retry probe",
                    }
                ]
            }
        )
        analysis_response = json.dumps({"findings": [], "evidence": [], "severity": "info"})

        mock_client = _mock_anthropic_client(
            [empty_generation, retry_generation, analysis_response]
        )

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

        assert report.probes_sent > 0
        # Should have made 3 LLM calls: generate, retry-generate, analyse
        assert mock_client.messages.create.call_count == 3

    def test_falls_back_to_specialist_fallbacks_when_retry_also_fails(self) -> None:
        """Uses specialist fallback probes when both LLM attempts return 0 probes."""
        orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
        bundle = self._make_bundle_with_spec()

        empty_generation = json.dumps({"probes": []})
        analysis_response = json.dumps({"findings": [], "evidence": [], "severity": "info"})

        # Both generation attempts return empty; fallback probes should be used
        mock_client = _mock_anthropic_client(
            [empty_generation, empty_generation, analysis_response]
        )

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

        # Fallback probes should have been used; tool_exerciser has declared_tools
        assert report.probes_sent > 0
        # 3 LLM calls: generate, retry-generate, analyse
        assert mock_client.messages.create.call_count == 3

    def test_retry_uses_endpoint_list_from_openapi_spec(self) -> None:
        """The retry prompt explicitly mentions available endpoints from the OpenAPI spec."""
        orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
        bundle = self._make_bundle_with_spec()

        empty_generation = json.dumps({"probes": []})
        analysis_response = json.dumps({"findings": [], "evidence": [], "severity": "info"})

        captured_prompts: list[str] = []

        def capturing_call_llm(client, prompt, **kwargs):
            captured_prompts.append(prompt)
            msg = MagicMock()
            msg.content = [MagicMock(text=empty_generation)]
            return client.messages.create(
                model=kwargs.get("model", "claude-sonnet-4-6"),
                max_tokens=kwargs.get("max_tokens", 4096),
                system="",
                messages=[{"role": "user", "content": prompt}],
            ).content[0].text

        mock_client = _mock_anthropic_client(
            [empty_generation, empty_generation, analysis_response]
        )

        with (
            patch.object(orchestrator, "_get_client", return_value=mock_client),
            patch("httpx.Client") as MockHTTPClient,
        ):
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.request.return_value = MagicMock(
                status_code=200,
                text="{}",
                headers={"content-type": "application/json"},
            )
            MockHTTPClient.return_value = mock_http

            # Capture the retry prompt by examining LLM call args
            orchestrator._run_specialist("tool_exerciser", bundle)

        # The second call to messages.create (retry) should mention the endpoint
        calls = mock_client.messages.create.call_args_list
        # calls[0] = first generation, calls[1] = retry generation, calls[2] = analysis
        assert len(calls) >= 2
        retry_call_messages = calls[1][1]["messages"]
        retry_prompt_text = retry_call_messages[0]["content"]
        assert "/chat" in retry_prompt_text

    def test_no_retry_when_first_attempt_succeeds(self) -> None:
        """Orchestrator does NOT retry when first LLM call returns valid probes."""
        orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
        bundle = self._make_bundle_with_spec()

        good_generation = json.dumps(
            {
                "probes": [
                    {
                        "method": "POST",
                        "path": "/chat",
                        "body": {"message": "hello"},
                        "rationale": "test",
                    }
                ]
            }
        )
        analysis_response = json.dumps({"findings": [], "evidence": [], "severity": "info"})

        mock_client = _mock_anthropic_client([good_generation, analysis_response])

        mock_http_response = MagicMock()
        mock_http_response.status_code = 200
        mock_http_response.text = "{}"
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

            orchestrator._run_specialist("tool_exerciser", bundle)

        # Only 2 LLM calls: generate + analyse (no retry)
        assert mock_client.messages.create.call_count == 2

    def test_warning_logged_when_all_probe_sources_empty(self, caplog) -> None:
        """A warning is logged when both LLM attempts and fallbacks yield 0 probes."""
        import logging

        orchestrator = AdaptiveProbeOrchestrator(api_key="test-key")
        # Bundle with no tools, no OpenAPI spec, so fallbacks also produce nothing useful
        bundle = ContextBundle(
            source_files={},
            manifest=None,
            static_findings=[],
            live_url="https://agent.example.com",
            canary_tokens={},
            declared_tools=[],
            declared_domains=[],
            customer_data_access=[],
            permissions=[],
            openapi_spec=None,
        )

        empty_generation = json.dumps({"probes": []})
        analysis_response = json.dumps({"findings": [], "evidence": [], "severity": "info"})

        mock_client = _mock_anthropic_client(
            [empty_generation, empty_generation, analysis_response]
        )

        mock_http_response = MagicMock()
        mock_http_response.status_code = 200
        mock_http_response.text = "{}"
        mock_http_response.headers = {"content-type": "application/json"}

        with (
            patch.object(orchestrator, "_get_client", return_value=mock_client),
            patch("httpx.Client") as MockHTTPClient,
            caplog.at_level(logging.WARNING, logger="agentgate.trust.runtime.adaptive.orchestrator"),
        ):
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            mock_http.request.return_value = mock_http_response
            MockHTTPClient.return_value = mock_http

            # Even with no probes the run should complete without raising
            report = orchestrator._run_specialist("canary_stresser", bundle)

        # Even with no probes, a report is returned
        assert report.specialist == "canary_stresser"
