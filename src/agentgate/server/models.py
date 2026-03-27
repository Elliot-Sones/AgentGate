from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class ScanStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    DEPLOYING = "deploying"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanVerdict(str, Enum):
    ALLOW_CLEAN = "allow_clean"
    ALLOW_WITH_WARNINGS = "allow_with_warnings"
    MANUAL_REVIEW = "manual_review"
    BLOCK = "block"


class CreateScanRequest(BaseModel):
    repo_url: str
    entrypoint: str | None = "main.py"
    runtime: str = "python"
    manifest_path: str | None = None
    webhook_url: str | None = None


class ScoreResponse(BaseModel):
    checks_run: int
    checks_passed: int
    checks_failed: int


class ScanResponse(BaseModel):
    id: str
    status: ScanStatus
    repo_url: str
    created_at: str | datetime
    updated_at: str | datetime
    verdict: ScanVerdict | None = None
    score: ScoreResponse | None = None
    error: str | None = None
    completed_at: str | datetime | None = None
    report_url: str | None = None

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    limit: int
    offset: int


class WebhookPayload(BaseModel):
    event: str = "scan.completed"
    scan_id: str
    verdict: str | None
    score: ScoreResponse | None
    report_url: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.0.0"
