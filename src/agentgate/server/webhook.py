from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time

import httpx

from agentgate.server.models import ScoreResponse, WebhookPayload

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_SECONDS = (1, 5, 25)


def compute_signature(*, body: str, timestamp: str, secret: str) -> str:
    message = body + timestamp
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def build_webhook_headers(*, body: str, secret: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    signature = compute_signature(body=body, timestamp=timestamp, secret=secret)
    return {
        "X-AgentGate-Signature": f"sha256={signature}",
        "X-AgentGate-Timestamp": timestamp,
        "Content-Type": "application/json",
    }


async def deliver_webhook(
    *,
    webhook_url: str,
    scan_id: str,
    verdict: str | None,
    score: dict | None,
    report_url: str,
    webhook_secret: str,
) -> bool:
    payload = WebhookPayload(
        scan_id=scan_id,
        verdict=verdict,
        score=ScoreResponse(**score) if score else None,
        report_url=report_url,
    )
    body = payload.model_dump_json()
    headers = build_webhook_headers(body=body, secret=webhook_secret)

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(webhook_url, content=body, headers=headers)
                if resp.status_code < 400:
                    logger.info("Webhook delivered to %s (attempt %d)", webhook_url, attempt + 1)
                    return True
                logger.warning(
                    "Webhook to %s returned %d (attempt %d)",
                    webhook_url, resp.status_code, attempt + 1,
                )
        except Exception as exc:
            logger.warning("Webhook to %s failed (attempt %d): %s", webhook_url, attempt + 1, exc)

        if attempt < _MAX_RETRIES - 1:
            await asyncio.sleep(_BACKOFF_SECONDS[attempt])

    logger.error("Webhook delivery to %s failed after %d attempts", webhook_url, _MAX_RETRIES)
    return False
