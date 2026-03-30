from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from slowapi import Limiter

from agentgate.server.auth import parse_api_key, verify_secret
from agentgate.server.db import Database
from agentgate.server.models import (
    CreateScanRequest,
    ScanEventListResponse,
    ScanEventResponse,
    ScanListResponse,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
    ScoreResponse,
)
from agentgate.server.urls import build_events_url, build_report_url
from agentgate.server.webhook import summarize_coverage_fields

router = APIRouter()


def _rate_limit_key(request: Request) -> str:
    raw_key = request.headers.get("X-API-Key", "")
    if "." in raw_key:
        return raw_key.split(".")[0]
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_rate_limit_key)


def _response_base_url(request: Request) -> str:
    return getattr(request.app.state, "public_base_url", "") or str(request.base_url)


async def get_db(request: Request) -> Database:
    return request.app.state.db


async def authenticate(
    request: Request,
    x_api_key: str | None = Header(None),
) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    try:
        key_id, secret = parse_api_key(x_api_key)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid API key format")

    db: Database = request.app.state.db
    key_row = await db.get_api_key(key_id)
    if not key_row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not verify_secret(secret, key_row["key_hash"]):
        raise HTTPException(status_code=401, detail="Invalid API key")

    return key_id


def _failure_reason_from_row(row: dict) -> str | None:
    report = row.get("report")
    if isinstance(report, dict):
        reason = report.get("failure_reason")
        if isinstance(reason, str) and reason:
            return reason
        submission_support = report.get("submission_support")
        if isinstance(submission_support, dict):
            reason = submission_support.get("reason") or submission_support.get("status")
            if isinstance(reason, str) and reason:
                return reason
        metadata = report.get("metadata")
        if isinstance(metadata, dict) and metadata.get("deployment_error"):
            return "deployment_failed"
    if row.get("status") == "failed" and row.get("error"):
        return "scan_failed"
    return None


def _scan_row_to_response(row: dict, *, base_url: str = "") -> ScanResponse:
    score = None
    if isinstance(row.get("score"), dict):
        score = ScoreResponse(**row["score"])
    report_url = None
    if row.get("report") and row.get("status") in {"completed", "failed"}:
        report_url = build_report_url(row["id"], base_url)
    report = row.get("report") if isinstance(row.get("report"), dict) else None
    coverage_status, coverage_detail, coverage_recommendation = summarize_coverage_fields(
        report,
        verdict=row.get("verdict"),
    )
    return ScanResponse(
        id=row["id"],
        status=ScanStatus(row["status"]),
        repo_url=row["repo_url"],
        git_ref=row.get("git_ref"),
        dockerfile_path=row.get("dockerfile_path"),
        created_at=row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        updated_at=row["updated_at"].isoformat() if hasattr(row["updated_at"], "isoformat") else row["updated_at"],
        phase=row.get("phase"),
        status_detail=row.get("status_detail"),
        progress_current=row.get("progress_current"),
        progress_total=row.get("progress_total"),
        verdict=ScanVerdict(row["verdict"]) if row.get("verdict") else None,
        score=score,
        coverage_status=coverage_status,
        coverage_detail=coverage_detail,
        coverage_recommendation=coverage_recommendation,
        error=row.get("error"),
        failure_reason=_failure_reason_from_row(row),
        completed_at=row["completed_at"].isoformat() if row.get("completed_at") and hasattr(row["completed_at"], "isoformat") else row.get("completed_at"),
        report_url=report_url,
        events_url=build_events_url(row["id"], base_url),
        events_stream_url=build_events_url(row["id"], base_url, stream=True),
    )


def _scan_event_to_response(row: dict) -> ScanEventResponse:
    return ScanEventResponse(
        id=int(row["id"]),
        scan_id=row["scan_id"],
        event_type=str(row.get("event_type") or "scan.progress"),
        status=ScanStatus(row["status"]),
        phase=row.get("phase"),
        detail=row.get("detail"),
        progress_current=row.get("progress_current"),
        progress_total=row.get("progress_total"),
        payload=row.get("payload") if isinstance(row.get("payload"), dict) else None,
        created_at=(
            row["created_at"].isoformat()
            if hasattr(row["created_at"], "isoformat")
            else row["created_at"]
        ),
    )


def _format_sse_event(*, event: str, data: dict, event_id: int | None = None) -> str:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    if event:
        lines.append(f"event: {event}")
    payload = json.dumps(data, separators=(",", ":"))
    for line in payload.splitlines() or ["{}"]:
        lines.append(f"data: {line}")
    return "\n".join(lines) + "\n\n"


def _parse_last_event_id(raw: str | None) -> int:
    if not raw:
        return 0
    try:
        parsed = int(str(raw).strip())
    except ValueError:
        return 0
    return max(parsed, 0)


@router.post("/v1/scans", response_model=ScanResponse, status_code=201)
@limiter.limit("10/minute")
async def create_scan(
    body: CreateScanRequest,
    request: Request,
    key_id: str = Depends(authenticate),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
):
    db: Database = request.app.state.db

    if idempotency_key:
        existing = await db.find_by_idempotency_key(
            api_key_id=key_id, idempotency_key=idempotency_key
        )
        if existing:
            return _scan_row_to_response(
                existing,
                base_url=_response_base_url(request),
            )

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    await db.create_scan(
        scan_id=scan_id,
        repo_url=body.repo_url,
        git_ref=body.git_ref,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
        dockerfile_path=body.dockerfile_path,
        webhook_url=body.webhook_url,
        api_key_id=key_id,
        idempotency_key=idempotency_key,
    )

    redis_pool = request.app.state.redis
    await redis_pool.enqueue_job(
        "run_scan_job",
        scan_id=scan_id,
        repo_url=body.repo_url,
        git_ref=body.git_ref,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
        dockerfile_path=body.dockerfile_path,
    )

    row = await db.get_scan(scan_id, api_key_id=key_id)
    return _scan_row_to_response(
        row,
        base_url=_response_base_url(request),
    )


@router.get("/v1/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    request: Request,
    key_id: str = Depends(authenticate),
):
    db: Database = request.app.state.db
    row = await db.get_scan(scan_id, api_key_id=key_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_row_to_response(
        row,
        base_url=_response_base_url(request),
    )


@router.get("/v1/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    request: Request,
    key_id: str = Depends(authenticate),
):
    db: Database = request.app.state.db
    row = await db.get_scan(scan_id, api_key_id=key_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.get("status") not in {"completed", "failed"} or not row.get("report"):
        raise HTTPException(status_code=409, detail="Scan not yet completed")
    return row.get("report", {})


@router.get("/v1/scans/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    request: Request,
    key_id: str = Depends(authenticate),
    stream: bool = Query(default=False),
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    last_event_id: str | None = Header(None, alias="Last-Event-ID"),
):
    db: Database = request.app.state.db
    row = await db.get_scan(scan_id, api_key_id=key_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not stream:
        events = await db.list_scan_events(scan_id, after_id=after, limit=limit)
        return ScanEventListResponse(
            scan_id=scan_id,
            events=[_scan_event_to_response(event) for event in events],
        )

    initial_cursor = max(after, _parse_last_event_id(last_event_id))

    async def _event_stream():
        cursor = initial_cursor
        batch_limit = min(limit, 100)
        yield "retry: 1000\n\n"
        while True:
            events = await db.list_scan_events(scan_id, after_id=cursor, limit=batch_limit)
            if events:
                for event in events:
                    payload = _scan_event_to_response(event).model_dump(mode="json")
                    cursor = max(cursor, int(event["id"]))
                    yield _format_sse_event(
                        event=str(event.get("event_type") or "scan.progress"),
                        data=payload,
                        event_id=int(event["id"]),
                    )
                latest = await db.get_scan(scan_id, api_key_id=key_id)
                if latest and latest.get("status") in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value}:
                    break
                continue

            latest = await db.get_scan(scan_id, api_key_id=key_id)
            if latest and latest.get("status") in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value}:
                break
            yield ": keep-alive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/v1/scans", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    key_id: str = Depends(authenticate),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    db: Database = request.app.state.db
    rows = await db.list_scans(api_key_id=key_id, limit=limit, offset=offset)
    return ScanListResponse(
        scans=[
            _scan_row_to_response(
                r,
                base_url=_response_base_url(request),
            )
            for r in rows
        ],
        limit=limit,
        offset=offset,
    )
