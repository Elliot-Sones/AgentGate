import pytest
from pydantic import ValidationError

from agentgate.server.models import (
    CreateScanRequest,
    ScanEventResponse,
    ScanResponse,
    ScanStatus,
    ScanVerdict,
    WebhookPayload,
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
        git_ref="feature/hosted-api",
        manifest_path="trust_manifest.yaml",
        dockerfile_path="Dockerfile.api",
        webhook_url="https://example.com/webhook",
    )
    assert req.git_ref == "feature/hosted-api"
    assert req.manifest_path == "trust_manifest.yaml"
    assert req.dockerfile_path == "Dockerfile.api"
    assert req.webhook_url == "https://example.com/webhook"


def test_create_scan_request_rejects_parent_traversal():
    with pytest.raises(ValidationError):
        CreateScanRequest(
            repo_url="https://github.com/test/agent",
            dockerfile_path="../Dockerfile",
        )


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
        phase="queued",
        status_detail="Scan accepted and queued for processing.",
        progress_current=0,
        progress_total=0,
    )
    assert resp.verdict is None
    assert resp.score is None
    assert resp.phase == "queued"


def test_scan_event_response_payload():
    event = ScanEventResponse(
        id=1,
        scan_id="scan_abc123",
        event_type="scan.phase",
        status=ScanStatus.CLONING,
        phase="clone_started",
        detail="Cloning the repository.",
        progress_current=0,
        progress_total=0,
        payload={"repo_url": "https://github.com/test/agent"},
        created_at="2026-03-26T22:00:00Z",
    )
    assert event.payload == {"repo_url": "https://github.com/test/agent"}


def test_scan_response_coverage_fields():
    resp = ScanResponse(
        id="scan_abc123",
        status=ScanStatus.COMPLETED,
        repo_url="https://github.com/test/agent",
        created_at="2026-03-26T22:00:00Z",
        updated_at="2026-03-26T22:00:00Z",
        coverage_status="limited",
        coverage_detail="Runtime coverage was incomplete.",
        coverage_recommendation="manual_review",
    )
    assert resp.coverage_status == "limited"
    assert resp.coverage_recommendation == "manual_review"


def test_scan_response_failed_includes_failure_reason():
    resp = ScanResponse(
        id="scan_abc123",
        status=ScanStatus.FAILED,
        repo_url="https://github.com/test/agent",
        created_at="2026-03-26T22:00:00Z",
        updated_at="2026-03-26T22:00:00Z",
        failure_reason="live_attack_unusable",
        error="Agent never became usable enough for the mandatory live attack scan.",
    )
    assert resp.status == ScanStatus.FAILED
    assert resp.failure_reason == "live_attack_unusable"
    assert resp.error == "Agent never became usable enough for the mandatory live attack scan."


def test_create_scan_request_rejects_http_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="http://github.com/test/agent")


def test_create_scan_request_rejects_localhost_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://localhost/test/agent")


def test_create_scan_request_rejects_private_ip_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://10.0.0.1/test/agent")


def test_create_scan_request_rejects_link_local_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="https://169.254.1.1/test/agent")


def test_create_scan_request_accepts_github_tree_url():
    req = CreateScanRequest(repo_url="https://github.com/test/agent/tree/feature/branch")
    assert req.repo_url == "https://github.com/test/agent/tree/feature/branch"


def test_create_scan_request_accepts_gitlab_url():
    req = CreateScanRequest(repo_url="https://gitlab.com/test/agent")
    assert req.repo_url == "https://gitlab.com/test/agent"


def test_create_scan_request_rejects_empty_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="")


def test_create_scan_request_rejects_non_url_repo_url():
    with pytest.raises(ValidationError, match="repo_url"):
        CreateScanRequest(repo_url="not-a-url")


def test_create_scan_request_rejects_http_webhook_url():
    with pytest.raises(ValidationError, match="webhook_url"):
        CreateScanRequest(repo_url="https://github.com/test/agent", webhook_url="http://example.com/hook")


def test_create_scan_request_rejects_private_webhook_url():
    with pytest.raises(ValidationError, match="webhook_url"):
        CreateScanRequest(repo_url="https://github.com/test/agent", webhook_url="https://192.168.1.1/hook")


def test_create_scan_request_accepts_https_webhook_url():
    req = CreateScanRequest(repo_url="https://github.com/test/agent", webhook_url="https://api.promptshop.co/webhooks/agentgate")
    assert req.webhook_url == "https://api.promptshop.co/webhooks/agentgate"


def test_create_scan_request_allows_localhost_webhook_in_dev_mode():
    import os
    os.environ["AGENTGATE_DEV_MODE"] = "1"
    try:
        req = CreateScanRequest(repo_url="https://github.com/test/agent", webhook_url="http://localhost:3000/hook")
        assert req.webhook_url == "http://localhost:3000/hook"
    finally:
        del os.environ["AGENTGATE_DEV_MODE"]


def test_create_scan_request_rejects_invalid_runtime():
    with pytest.raises(ValidationError, match="runtime"):
        CreateScanRequest(repo_url="https://github.com/test/agent", runtime="node")


def test_create_scan_request_accepts_python_runtime():
    req = CreateScanRequest(repo_url="https://github.com/test/agent", runtime="python")
    assert req.runtime == "python"


def test_webhook_payload_coverage_fields():
    payload = WebhookPayload(
        scan_id="scan_abc123",
        verdict="allow_clean",
        score=None,
        report_url="https://example.com/report",
        coverage_status="limited",
        coverage_recommendation="manual_review",
    )
    assert payload.coverage_status == "limited"
    assert payload.coverage_recommendation == "manual_review"
