from __future__ import annotations

import time

import httpx

from agentscorer.adapters.base import AdapterResponse, AgentAdapter
from agentscorer.models.agent import AgentConfig


class HTTPAdapter(AgentAdapter):
    """Adapter that communicates with agents via HTTP POST."""

    def __init__(self, config: AgentConfig, timeout: float = 30.0, max_retries: int = 3):
        self.config = config
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

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
        payload = {self.config.request_field: message}

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

                try:
                    data = resp.json()
                    text = str(data.get(self.config.response_field, data.get("response", "")))
                except Exception:
                    text = resp.text

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

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
