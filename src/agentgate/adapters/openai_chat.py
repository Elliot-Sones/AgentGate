from __future__ import annotations

import time

import httpx

from agentgate.adapters.base import AdapterResponse, AgentAdapter
from agentgate.models.agent import AgentConfig


class OpenAIChatAdapter(AgentAdapter):
    """Adapter for agents that speak the OpenAI Chat Completions format.

    Sends ``{"messages": [...], "model": ...}`` and parses
    ``choices[0].message.content`` from the response.
    """

    def __init__(
        self,
        config: AgentConfig,
        model: str = "gpt-4",
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.config = config
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None
        self._conversation: list[dict[str, str]] = []

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"Content-Type": "application/json"}
            if self.config.auth_header:
                key, _, value = self.config.auth_header.partition(":")
                headers[key.strip()] = value.strip()
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client

    async def send(self, message: str) -> AdapterResponse:
        client = await self._get_client()
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": message}],
        }

        last_error: str | None = None
        for attempt in range(self.max_retries):
            start = time.monotonic()
            try:
                resp = await client.post(self.config.url, json=payload)
                elapsed_ms = (time.monotonic() - start) * 1000

                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                    import asyncio

                    await asyncio.sleep(retry_after)
                    continue

                if resp.status_code >= 500:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    if attempt < self.max_retries - 1:
                        import asyncio

                        await asyncio.sleep(2 ** (attempt + 1))
                        continue
                    return AdapterResponse(
                        text="",
                        status_code=resp.status_code,
                        response_time_ms=elapsed_ms,
                        error=last_error,
                    )

                data = resp.json()
                text = self._extract_content(data)

                return AdapterResponse(
                    text=text,
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                    raw=data if isinstance(data, dict) else None,
                )

            except httpx.ConnectError as e:
                return AdapterResponse(
                    text="",
                    status_code=0,
                    error=f"Connection refused: {e}",
                )
            except httpx.TimeoutException as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                if attempt < self.max_retries - 1:
                    self.timeout *= 2
                    continue
                return AdapterResponse(
                    text="",
                    status_code=0,
                    response_time_ms=elapsed_ms,
                    error=f"Timeout after {elapsed_ms:.0f}ms: {e}",
                )
            except Exception as e:
                return AdapterResponse(
                    text="",
                    status_code=0,
                    error=f"Unexpected error: {e}",
                )

        return AdapterResponse(text="", status_code=0, error=last_error or "Max retries exceeded")

    async def send_conversation(self, messages: list[str]) -> list[AdapterResponse]:
        """Maintain cumulative conversation state across turns."""
        client = await self._get_client()
        responses: list[AdapterResponse] = []

        for message in messages:
            self._conversation.append({"role": "user", "content": message})
            payload = {
                "model": self.model,
                "messages": list(self._conversation),
            }

            start = time.monotonic()
            try:
                resp = await client.post(self.config.url, json=payload)
                elapsed_ms = (time.monotonic() - start) * 1000

                data = resp.json()
                text = self._extract_content(data)
                self._conversation.append({"role": "assistant", "content": text})

                responses.append(
                    AdapterResponse(
                        text=text,
                        status_code=resp.status_code,
                        response_time_ms=elapsed_ms,
                        raw=data if isinstance(data, dict) else None,
                    )
                )
            except Exception as e:
                responses.append(AdapterResponse(text="", status_code=0, error=str(e)))

        return responses

    async def reset(self) -> None:
        """Clear conversation history."""
        self._conversation.clear()

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @staticmethod
    def _extract_content(data: dict) -> str:
        """Extract message content from OpenAI-format response."""
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return str(data)
