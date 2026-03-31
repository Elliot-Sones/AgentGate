from __future__ import annotations

import ipaddress
import os
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


def _is_private_host(hostname: str) -> bool:
    hostname = hostname.strip("[]").lower()
    if hostname in ("localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        pass
    if hostname.endswith(".local") or hostname.endswith(".internal"):
        return True
    return False


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
    git_ref: str | None = None
    entrypoint: str | None = "main.py"
    runtime: Literal["python"] = "python"
    manifest_path: str | None = None
    dockerfile_path: str | None = None
    webhook_url: str | None = None

    @field_validator("manifest_path", "dockerfile_path")
    @classmethod
    def validate_repo_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Path must stay within the repository root")
        return normalized

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        if not value:
            raise ValueError("repo_url must not be empty")
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise ValueError("repo_url must use https://")
        hostname = parsed.hostname or ""
        if _is_private_host(hostname):
            raise ValueError("repo_url must not point to a private or internal host")
        return value

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        hostname = parsed.hostname or ""
        dev_mode = os.environ.get("AGENTGATE_DEV_MODE", "") == "1"
        if dev_mode and hostname in ("localhost", "127.0.0.1", "::1"):
            return value
        if parsed.scheme != "https":
            raise ValueError("webhook_url must use https://")
        if _is_private_host(hostname):
            raise ValueError("webhook_url must not point to a private or internal host")
        return value

    @field_validator("git_ref")
    @classmethod
    def validate_git_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ScoreResponse(BaseModel):
    checks_run: int
    checks_passed: int
    checks_failed: int


class ScanResponse(BaseModel):
    id: str
    status: ScanStatus
    repo_url: str
    git_ref: str | None = None
    dockerfile_path: str | None = None
    created_at: str | datetime
    updated_at: str | datetime
    phase: str | None = None
    status_detail: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
    verdict: ScanVerdict | None = None
    score: ScoreResponse | None = None
    coverage_status: str | None = None
    coverage_detail: str | None = None
    coverage_recommendation: str | None = None
    error: str | None = None
    failure_reason: str | None = None
    failure_explanation: dict | None = None
    completed_at: str | datetime | None = None
    report_url: str | None = None
    events_url: str | None = None
    events_stream_url: str | None = None

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
    coverage_status: str | None = None
    coverage_recommendation: str | None = None
    report_url: str


class ScanEventResponse(BaseModel):
    id: int
    scan_id: str
    event_type: str
    status: ScanStatus
    phase: str | None = None
    detail: str | None = None
    progress_current: int | None = None
    progress_total: int | None = None
    payload: dict | None = None
    created_at: str | datetime


class ScanEventListResponse(BaseModel):
    scan_id: str
    events: list[ScanEventResponse]


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.0.0"
