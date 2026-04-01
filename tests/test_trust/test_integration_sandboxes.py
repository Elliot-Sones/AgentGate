from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agentgate.trust.checks.runtime_integration_sandboxes import (
    RuntimeIntegrationSandboxesCheck,
)
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.runtime.integration_sandboxes import run_integration_sandbox_exercises


@dataclass
class _Profile:
    integration_sandboxes: list[dict] = field(default_factory=list)
    integration_routes: dict[str, list[str]] = field(default_factory=dict)
    issued_runtime_env: dict[str, str] = field(default_factory=dict)


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or ""

    def json(self):
        return self._payload


class _SlackClient:
    def __init__(self, *args, **kwargs) -> None:
        self.history_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, headers=None, content=None, data=None):
        if url.endswith("/api/auth.test"):
            return _FakeResponse(200, {"ok": True, "user_id": "UBOT"})
        if url.endswith("/api/conversations.join"):
            return _FakeResponse(200, {"ok": True, "channel": {"id": "C123"}})
        if url == "https://agent.example.com/slack/events":
            return _FakeResponse(200, text="ok")
        raise AssertionError(f"Unexpected POST {url}")

    def get(self, url, headers=None, params=None):
        if url.endswith("/api/conversations.history"):
            self.history_calls += 1
            if self.history_calls == 1:
                return _FakeResponse(200, {"ok": True, "messages": [{"ts": "100.1"}]})
            return _FakeResponse(
                200,
                {
                    "ok": True,
                    "messages": [
                        {"ts": "101.1", "user": "UBOT", "text": "Sandbox ack from Slack"}
                    ],
                },
            )
        raise AssertionError(f"Unexpected GET {url}")


class _ShopifyClient:
    def __init__(self, *args, **kwargs) -> None:
        self.deleted = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method, url, headers=None, json=None):
        if url.endswith("/products.json") and method == "POST":
            return _FakeResponse(
                201,
                {"product": {"id": 42, "title": "AgentGate Sandbox Product 1234"}},
            )
        if url.endswith("/products/42.json") and method == "GET":
            return _FakeResponse(
                200,
                {"product": {"id": 42, "title": "AgentGate Sandbox Product 1234"}},
            )
        if url.endswith("/products/42.json") and method == "DELETE":
            self.deleted = True
            return _FakeResponse(200, {})
        raise AssertionError(f"Unexpected request {method} {url}")

    def post(self, url, headers=None, content=None, data=None):
        if url == "https://agent.example.com/shopify/webhooks":
            return _FakeResponse(200, text="accepted")
        raise AssertionError(f"Unexpected POST {url}")


class _SlackNotInChannelClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, headers=None, content=None, data=None):
        if url.endswith("/api/auth.test"):
            return _FakeResponse(200, {"ok": True, "user_id": "UBOT"})
        if url.endswith("/api/conversations.join"):
            return _FakeResponse(200, {"ok": False, "error": "method_not_supported_for_channel_type"})
        if url == "https://agent.example.com/slack/events":
            return _FakeResponse(200, text="ok")
        raise AssertionError(f"Unexpected POST {url}")

    def get(self, url, headers=None, params=None):
        if url.endswith("/api/conversations.history"):
            return _FakeResponse(200, {"ok": False, "error": "not_in_channel"})
        raise AssertionError(f"Unexpected GET {url}")


class _SlackCallbackFailureClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, headers=None, content=None, data=None):
        if url.endswith("/api/auth.test"):
            return _FakeResponse(200, {"ok": True, "user_id": "UBOT"})
        if url.endswith("/api/conversations.join"):
            return _FakeResponse(200, {"ok": True, "channel": {"id": "C123"}})
        if url == "https://agent.example.com/slack/events":
            return _FakeResponse(500, text="boom")
        raise AssertionError(f"Unexpected POST {url}")

    def get(self, url, headers=None, params=None):
        if url.endswith("/api/conversations.history"):
            return _FakeResponse(200, {"ok": True, "messages": [{"ts": "100.1"}]})
        raise AssertionError(f"Unexpected GET {url}")


def _config(tmp_path: Path, **overrides) -> TrustScanConfig:
    defaults = dict(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
        hosted_url="https://agent.example.com",
    )
    defaults.update(overrides)
    return TrustScanConfig(**defaults)


def test_run_integration_sandbox_exercises_slack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agentgate.trust.runtime.integration_sandboxes.httpx.Client",
        _SlackClient,
    )
    monkeypatch.setattr("agentgate.trust.runtime.integration_sandboxes.time.sleep", lambda _: None)

    profile = _Profile(
        integration_sandboxes=[
            {
                "name": "slack",
                "ready": True,
                "target": "T123",
                "notes": ["Slack sandbox target: T123."],
            }
        ],
        integration_routes={"slack": ["/slack/events"]},
        issued_runtime_env={
            "SLACK_BOT_TOKEN": "xoxb-test",
            "SLACK_SIGNING_SECRET": "secret",
            "SLACK_CHANNEL_ID": "C123",
            "SLACK_TEAM_ID": "T123",
            "SLACK_APP_ID": "A123",
        },
    )

    results = run_integration_sandbox_exercises(
        hosted_url="https://agent.example.com",
        runtime_profile=profile,
        timeout_seconds=5,
    )

    assert len(results) == 1
    assert results[0].status == "passed"
    assert results[0].route == "/slack/events"
    assert results[0].verification_level == "full"
    assert results[0].reply_verification_attempted is True
    assert "Sandbox ack from Slack" in " ".join(results[0].evidence)


def test_run_integration_sandbox_exercises_slack_falls_back_to_callback_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentgate.trust.runtime.integration_sandboxes.httpx.Client",
        _SlackNotInChannelClient,
    )

    profile = _Profile(
        integration_sandboxes=[
            {
                "name": "slack",
                "ready": True,
                "target": "T123",
                "notes": ["Slack sandbox target: T123."],
            }
        ],
        integration_routes={"slack": ["/slack/events"]},
        issued_runtime_env={
            "SLACK_BOT_TOKEN": "xoxb-test",
            "SLACK_SIGNING_SECRET": "secret",
            "SLACK_CHANNEL_ID": "C123",
            "SLACK_TEAM_ID": "T123",
            "SLACK_APP_ID": "A123",
        },
    )

    results = run_integration_sandbox_exercises(
        hosted_url="https://agent.example.com",
        runtime_profile=profile,
        timeout_seconds=5,
    )

    assert len(results) == 1
    assert results[0].status == "passed"
    assert results[0].route == "/slack/events"
    assert results[0].callback_status_code == 200
    assert results[0].verification_level == "callback_only"
    assert results[0].reply_verification_attempted is False
    assert results[0].degraded_reason == "channel_verification_unavailable"
    assert "reply verification was unavailable" in results[0].summary.lower()


def test_run_integration_sandbox_exercises_slack_uses_api_prefixed_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _SlackApiRouteClient(_SlackClient):
        def post(self, url, headers=None, content=None, data=None):  # type: ignore[override]
            if url == "https://agent.example.com/api/slack/events":
                return _FakeResponse(200, text="ok")
            if url == "https://agent.example.com/slack/events":
                return _FakeResponse(404, {"ok": False})
            return super().post(url, headers=headers, content=content, data=data)

    monkeypatch.setattr(
        "agentgate.trust.runtime.integration_sandboxes.httpx.Client",
        _SlackApiRouteClient,
    )

    profile = _Profile(
        integration_sandboxes=[
            {
                "name": "slack",
                "ready": True,
                "target": "T123",
                "notes": ["Slack sandbox target: T123."],
            }
        ],
        integration_routes={"slack": ["/api/slack/events", "/slack/events"]},
        issued_runtime_env={
            "SLACK_BOT_TOKEN": "xoxb-test",
            "SLACK_SIGNING_SECRET": "secret",
            "SLACK_CHANNEL_ID": "C123",
            "SLACK_TEAM_ID": "T123",
            "SLACK_APP_ID": "A123",
        },
    )

    results = run_integration_sandbox_exercises(
        hosted_url="https://agent.example.com",
        runtime_profile=profile,
        timeout_seconds=5,
    )

    assert len(results) == 1
    assert results[0].status == "passed"
    assert results[0].route == "/api/slack/events"


def test_run_integration_sandbox_exercises_slack_callback_failure_is_hard_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentgate.trust.runtime.integration_sandboxes.httpx.Client",
        _SlackCallbackFailureClient,
    )

    profile = _Profile(
        integration_sandboxes=[
            {
                "name": "slack",
                "ready": True,
                "target": "T123",
                "notes": ["Slack sandbox target: T123."],
            }
        ],
        integration_routes={"slack": ["/slack/events"]},
        issued_runtime_env={
            "SLACK_BOT_TOKEN": "xoxb-test",
            "SLACK_SIGNING_SECRET": "secret",
            "SLACK_CHANNEL_ID": "C123",
            "SLACK_TEAM_ID": "T123",
            "SLACK_APP_ID": "A123",
        },
    )

    results = run_integration_sandbox_exercises(
        hosted_url="https://agent.example.com",
        runtime_profile=profile,
        timeout_seconds=5,
    )

    assert len(results) == 1
    assert results[0].status == "failed"
    assert results[0].callback_status_code == 500
    assert results[0].verification_level == "none"
    assert "returned http 500" in results[0].summary.lower()


def test_run_integration_sandbox_exercises_shopify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agentgate.trust.runtime.integration_sandboxes.httpx.Client",
        _ShopifyClient,
    )

    profile = _Profile(
        integration_sandboxes=[
            {
                "name": "shopify",
                "ready": True,
                "target": "agentgate-dev.myshopify.com",
                "notes": ["Shopify dev store target: agentgate-dev.myshopify.com."],
            }
        ],
        integration_routes={"shopify": ["/shopify/webhooks"]},
        issued_runtime_env={
            "SHOPIFY_ACCESS_TOKEN": "shpat-test",
            "SHOPIFY_STORE_DOMAIN": "agentgate-dev.myshopify.com",
            "SHOPIFY_API_SECRET": "secret",
        },
    )

    results = run_integration_sandbox_exercises(
        hosted_url="https://agent.example.com",
        runtime_profile=profile,
        timeout_seconds=5,
    )

    assert len(results) == 1
    assert results[0].status == "passed"
    assert results[0].route == "/shopify/webhooks"
    assert "Seeded Shopify product" in " ".join(results[0].evidence)


@pytest.mark.asyncio
async def test_runtime_integration_sandboxes_check_records_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _config(tmp_path)
    ctx = TrustScanContext(config=cfg)
    ctx.generated_runtime_profile = _Profile(
        integration_sandboxes=[
            {"name": "slack", "ready": True, "target": "T123", "notes": []}
        ],
        integration_routes={"slack": ["/slack/events"]},
        issued_runtime_env={},
    )

    monkeypatch.setattr(
        "agentgate.trust.checks.runtime_integration_sandboxes.run_integration_sandbox_exercises",
        lambda **kwargs: [],
    )

    findings = await RuntimeIntegrationSandboxesCheck().run(ctx)

    assert len(findings) == 1
    assert findings[0].passed is True
    assert ctx.hosted_runtime_context["integration_sandbox_results"] == []
