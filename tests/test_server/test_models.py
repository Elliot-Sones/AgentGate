import pytest
from pydantic import ValidationError

from agentgate.server.models import (
    CreateScanRequest,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
)


def test_create_scan_request_valid():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        entrypoint="main.py",
        runtime="python",
    )
    assert req.repo_url == "https://github.com/test/agent"
    assert req.manifest_path is None
    assert req.webhook_url is None


def test_create_scan_request_with_optional_fields():
    req = CreateScanRequest(
        repo_url="https://github.com/test/agent",
        manifest_path="trust_manifest.yaml",
        webhook_url="https://example.com/webhook",
    )
    assert req.manifest_path == "trust_manifest.yaml"
    assert req.webhook_url == "https://example.com/webhook"


def test_create_scan_request_missing_repo_url():
    with pytest.raises(ValidationError):
        CreateScanRequest()


def test_scan_status_enum():
    assert ScanStatus.PENDING == "pending"
    assert ScanStatus.SCANNING == "scanning"
    assert ScanStatus.COMPLETED == "completed"
    assert ScanStatus.FAILED == "failed"


def test_scan_verdict_enum():
    assert ScanVerdict.ALLOW_CLEAN == "allow_clean"
    assert ScanVerdict.BLOCK == "block"


def test_scan_response_pending():
    resp = ScanResponse(
        id="scan_abc123",
        status=ScanStatus.PENDING,
        repo_url="https://github.com/test/agent",
        created_at="2026-03-26T22:00:00Z",
        updated_at="2026-03-26T22:00:00Z",
    )
    assert resp.verdict is None
    assert resp.score is None
