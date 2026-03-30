from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import socket
import time
from urllib.parse import urlparse

import httpx

from agentgate.server.models import ScoreResponse, WebhookPayload

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_SECONDS = (1, 5, 25)


def summarize_coverage_fields(
    report: dict | None,
    *,
    verdict: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    if not isinstance(report, dict):
        return None, None, None

    raw_status = report.get("coverage_status")
    if not isinstance(raw_status, str) or not raw_status.strip():
        coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else None
        if isinstance(coverage, dict):
            raw_status = coverage.get("level")

    status = _normalize_coverage_status(raw_status)
    detail = report.get("coverage_detail") if isinstance(report.get("coverage_detail"), str) else None
    if not detail:
        coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else None
        if isinstance(coverage, dict):
            detail = _build_coverage_detail(coverage, status=status)

    recommendation = report.get("coverage_recommendation")
    if not isinstance(recommendation, str) or not recommendation.strip():
        coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else None
        if isinstance(coverage, dict):
            recommendation = coverage.get("coverage_recommendation")
        else:
            recommendation = None
    if not isinstance(recommendation, str) or not recommendation.strip():
        if status == "limited" and verdict != "block":
            recommendation = "manual_review"
        else:
            recommendation = None

    return status, detail, recommendation


def _normalize_coverage_status(raw_status: object) -> str | None:
    if not isinstance(raw_status, str):
        return None
    status = raw_status.strip().lower()
    if not status:
        return None
    if status == "none":
        return "limited"
    if status in {"full", "partial", "limited"}:
        return status
    return status


def _build_coverage_detail(coverage: dict, *, status: str | None) -> str | None:
    notes: list[str] = []
    raw_notes = coverage.get("notes")
    if isinstance(raw_notes, list):
        for note in raw_notes:
            text = str(note).strip()
            if text:
                notes.append(text)

    exercised = coverage.get("exercised_surfaces")
    if isinstance(exercised, list) and exercised:
        items = [str(item).strip() for item in exercised if str(item).strip()]
        if items:
            notes.append("Exercised surfaces: " + ", ".join(items))

    skipped = coverage.get("skipped_surfaces")
    if isinstance(skipped, list) and skipped:
        items = [str(item).strip() for item in skipped if str(item).strip()]
        if items:
            notes.append("Skipped surfaces: " + ", ".join(items))

    if notes:
        return "; ".join(notes)
    if status:
        return f"Coverage level: {status}."
    return None


def _resolve_and_check_ip(url: str) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        results = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    for family, type_, proto, canonname, sockaddr in results:
        addr = ipaddress.ip_address(sockaddr[0])
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError(f"Webhook target {hostname} resolves to private address {addr}")


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
    coverage_status: str | None = None,
    coverage_recommendation: str | None = None,
    report_url: str,
    webhook_secret: str,
) -> bool:
    try:
        _resolve_and_check_ip(webhook_url)
    except ValueError:
        logger.warning("Webhook to %s blocked: resolves to private IP", webhook_url)
        return False

    payload = WebhookPayload(
        scan_id=scan_id,
        verdict=verdict,
        score=ScoreResponse(**score) if score else None,
        coverage_status=coverage_status,
        coverage_recommendation=coverage_recommendation,
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
