from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from agentgate.server.auth import parse_api_key, verify_secret
from agentgate.server.db import Database
from agentgate.server.models import (
    CreateScanRequest,
    ScanListResponse,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
    ScoreResponse,
)

router = APIRouter()


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


def _scan_row_to_response(row: dict) -> ScanResponse:
    score = None
    if row.get("score"):
        score = ScoreResponse(**row["score"]) if isinstance(row["score"], dict) else None
    report_url = None
    if row.get("status") == "completed":
        report_url = f"/v1/scans/{row['id']}/report"
    return ScanResponse(
        id=row["id"],
        status=ScanStatus(row["status"]),
        repo_url=row["repo_url"],
        created_at=row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"],
        updated_at=row["updated_at"].isoformat() if hasattr(row["updated_at"], "isoformat") else row["updated_at"],
        verdict=ScanVerdict(row["verdict"]) if row.get("verdict") else None,
        score=score,
        error=row.get("error"),
        completed_at=row["completed_at"].isoformat() if row.get("completed_at") and hasattr(row["completed_at"], "isoformat") else row.get("completed_at"),
        report_url=report_url,
    )


@router.post("/v1/scans", response_model=ScanResponse, status_code=201)
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
            return _scan_row_to_response(existing)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    await db.create_scan(
        scan_id=scan_id,
        repo_url=body.repo_url,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
        webhook_url=body.webhook_url,
        api_key_id=key_id,
        idempotency_key=idempotency_key,
    )

    redis_pool = request.app.state.redis
    await redis_pool.enqueue_job(
        "run_scan_job",
        scan_id=scan_id,
        repo_url=body.repo_url,
        entrypoint=body.entrypoint,
        runtime=body.runtime,
        manifest_path=body.manifest_path,
    )

    row = await db.get_scan(scan_id, api_key_id=key_id)
    return _scan_row_to_response(row)


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
    return _scan_row_to_response(row)


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
    if row.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Scan not yet completed")
    return row.get("report", {})


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
        scans=[_scan_row_to_response(r) for r in rows],
        limit=limit,
        offset=offset,
    )
