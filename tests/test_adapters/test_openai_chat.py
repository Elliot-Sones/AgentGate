"""Tests for the OpenAI Chat Completions adapter."""

from __future__ import annotations

import json

import httpx
import pytest

from agentgate.adapters.openai_chat import OpenAIChatAdapter
from agentgate.models.agent import AgentConfig


@pytest.fixture
def agent_cfg() -> AgentConfig:
    return AgentConfig(
        url="http://fakehost:9999/v1/chat/completions",
        name="Test",
        auth_header="Authorization: Bearer sk-test",
    )


def _openai_response(content: str = "Hello!") -> dict:
    """Build a minimal OpenAI-format JSON response."""
    return {
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ]
    }


# ── Payload shape ──────────────────────────────────────────────────────


async def test_send_payload_shape(agent_cfg: AgentConfig) -> None:
    """send() should POST {model, messages} to the configured URL."""
    captured: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json=_openai_response("hi"))

    transport = httpx.MockTransport(handler)

    adapter = OpenAIChatAdapter(agent_cfg, model="gpt-3.5-turbo")
    # Use _get_client's header logic by setting up the client with auth
    headers = {"Content-Type": "application/json", "Authorization": "Bearer sk-test"}
    adapter._client = httpx.AsyncClient(transport=transport, headers=headers)

    resp = await adapter.send("ping")
    assert resp.text == "hi"
    assert resp.status_code == 200

    body = captured["body"]
    assert body["model"] == "gpt-3.5-turbo"
    assert body["messages"] == [{"role": "user", "content": "ping"}]

    # Auth header should be present
    assert "bearer sk-test" in captured["headers"].get("authorization", "").lower()

    await adapter.close()


# ── Response parsing ───────────────────────────────────────────────────


async def test_extracts_content_from_choices(agent_cfg: AgentConfig) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json=_openai_response("world")))
    adapter = OpenAIChatAdapter(agent_cfg)
    adapter._client = httpx.AsyncClient(transport=transport)

    resp = await adapter.send("hello")
    assert resp.text == "world"
    await adapter.close()


async def test_fallback_on_unexpected_json(agent_cfg: AgentConfig) -> None:
    """When response JSON doesn't have choices, fall back to str(data)."""
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={"answer": "fallback"}))
    adapter = OpenAIChatAdapter(agent_cfg)
    adapter._client = httpx.AsyncClient(transport=transport)

    resp = await adapter.send("test")
    assert "answer" in resp.text  # str(dict) representation
    await adapter.close()


# ── Conversation state ─────────────────────────────────────────────────


async def test_conversation_state(agent_cfg: AgentConfig) -> None:
    """send_conversation() should accumulate user/assistant messages."""
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        body = json.loads(request.content)
        # Each subsequent call should have more messages
        msg_count = len(body["messages"])
        return httpx.Response(200, json=_openai_response(f"reply-{call_count} (msgs={msg_count})"))

    transport = httpx.MockTransport(handler)
    adapter = OpenAIChatAdapter(agent_cfg)
    adapter._client = httpx.AsyncClient(transport=transport)

    responses = await adapter.send_conversation(["first", "second", "third"])

    assert len(responses) == 3
    assert "reply-1" in responses[0].text
    assert "reply-3" in responses[2].text

    # After 3 turns, conversation should have 6 messages (3 user + 3 assistant)
    assert len(adapter._conversation) == 6
    assert adapter._conversation[0]["role"] == "user"
    assert adapter._conversation[1]["role"] == "assistant"

    await adapter.close()


# ── Reset ──────────────────────────────────────────────────────────────


async def test_reset_clears_conversation(agent_cfg: AgentConfig) -> None:
    adapter = OpenAIChatAdapter(agent_cfg)
    adapter._conversation = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    await adapter.reset()
    assert adapter._conversation == []


# ── Retry on 5xx ───────────────────────────────────────────────────────


async def test_retries_on_server_error(agent_cfg: AgentConfig) -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(500, text="Internal Server Error")
        return httpx.Response(200, json=_openai_response("recovered"))

    transport = httpx.MockTransport(handler)
    adapter = OpenAIChatAdapter(agent_cfg, max_retries=3)
    adapter._client = httpx.AsyncClient(transport=transport)

    resp = await adapter.send("test")
    assert resp.text == "recovered"
    assert attempts == 3
    await adapter.close()


# ── Connection error ───────────────────────────────────────────────────


async def test_connection_error_returns_adapter_response(agent_cfg: AgentConfig) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    transport = httpx.MockTransport(handler)
    adapter = OpenAIChatAdapter(agent_cfg)
    adapter._client = httpx.AsyncClient(transport=transport)

    resp = await adapter.send("test")
    assert resp.error is not None
    assert "Connection refused" in resp.error
    await adapter.close()
