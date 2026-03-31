import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from types import SimpleNamespace

from agentgate.worker.tasks import run_scan_job


@pytest.mark.asyncio
async def test_run_scan_job_forwards_unified_phase_progress_and_completes():
    mock_ctx = {
        "db": AsyncMock(),
        "scan_runner": MagicMock(),
        "webhook_secret": "whsec_test",
    }
    mock_ctx["scan_runner"].clone_repo = AsyncMock(return_value=Path("/tmp/repo"))
    mock_ctx["scan_runner"].build_trust_config = MagicMock(
        return_value=SimpleNamespace(hosted_url="https://agent.example.com")
    )
    async def _run_scan(config, *, event_callback=None):
        assert config.hosted_url == "https://agent.example.com"
        assert event_callback is not None
        await event_callback(
            {
                "status": "scanning",
                "phase": "source_review_started",
                "detail": "Reviewing source code.",
                "event_type": "scan.phase",
                "payload": {"stage": "source_review"},
            }
        )
        await event_callback(
            {
                "status": "deploying",
                "phase": "deployment_started",
                "detail": "Deployment started.",
                "event_type": "scan.phase",
                "payload": {"stage": "deploy"},
            }
        )
        await event_callback(
            {
                "status": "scanning",
                "phase": "live_attack_scan_started",
                "detail": "Running live security attacks.",
                "event_type": "scan.phase",
                "payload": {"stage": "live_attack"},
            }
        )
        return SimpleNamespace(
            verdict="allow_clean",
            score={"checks_run": 11, "checks_passed": 11, "checks_failed": 0},
            report={
                "scorecard": {},
                "coverage": {
                    "level": "full",
                    "notes": ["All runtime phases executed."],
                    "exercised_surfaces": ["/", "/docs"],
                    "skipped_surfaces": [],
                },
            },
            terminal_status="completed",
            error=None,
        )

    mock_ctx["scan_runner"].run_scan = AsyncMock(side_effect=_run_scan)
    mock_ctx["scan_runner"].cleanup = MagicMock()
    mock_ctx["scan_runner"].work_dir = Path("/tmp/agentgate-scans")
    mock_ctx["db"].get_scan_internal = AsyncMock(return_value={"webhook_url": None})
    mock_ctx["db"].record_scan_event = AsyncMock()

    await run_scan_job(
        mock_ctx,
        scan_id="scan_abc123",
        repo_url="https://github.com/test/agent",
        git_ref="feature/hosted-api",
        entrypoint="main.py",
        runtime="python",
        manifest_path=None,
        dockerfile_path="Dockerfile.api",
    )

    assert mock_ctx["db"].record_scan_event.await_count >= 4
    recorded_phases = [
        call.kwargs["phase"]
        for call in mock_ctx["db"].record_scan_event.await_args_list
        if "phase" in call.kwargs
    ]
    assert "source_review_started" in recorded_phases
    assert "deployment_started" in recorded_phases
    assert "live_attack_scan_started" in recorded_phases
    assert recorded_phases[-1] == "scan_completed"
    mock_ctx["scan_runner"].cleanup.assert_called_once_with("scan_abc123")


@pytest.mark.asyncio
async def test_run_scan_job_delivers_webhook_with_coverage_fields():
    mock_ctx = {
        "db": AsyncMock(),
        "scan_runner": MagicMock(),
        "webhook_secret": "whsec_test",
        "public_base_url": "https://api.example.com",
    }
    mock_ctx["scan_runner"].clone_repo = AsyncMock(return_value=Path("/tmp/repo"))
    mock_ctx["scan_runner"].build_trust_config = MagicMock(
        return_value=SimpleNamespace(hosted_url="https://agent.example.com")
    )
    mock_ctx["scan_runner"].run_scan = AsyncMock(
        return_value=SimpleNamespace(
            verdict="allow_clean",
            score={"checks_run": 11, "checks_passed": 11, "checks_failed": 0},
            report={
                "coverage": {
                    "level": "none",
                    "notes": ["No hosted runtime trace was captured."],
                    "exercised_surfaces": [],
                    "skipped_surfaces": ["/", "/docs"],
                }
            },
            terminal_status="completed",
            error=None,
        )
    )
    mock_ctx["scan_runner"].cleanup = MagicMock()
    mock_ctx["scan_runner"].work_dir = Path("/tmp/agentgate-scans")
    mock_ctx["db"].get_scan_internal = AsyncMock(return_value={"webhook_url": "https://example.com/webhook"})
    mock_ctx["db"].record_scan_event = AsyncMock()

    with patch("agentgate.worker.tasks.deliver_webhook", new=AsyncMock(return_value=True)) as deliver:
        await run_scan_job(
            mock_ctx,
            scan_id="scan_abc123",
            repo_url="https://github.com/test/agent",
            git_ref="feature/hosted-api",
            entrypoint="main.py",
            runtime="python",
            manifest_path=None,
            dockerfile_path="Dockerfile.api",
        )

    deliver.assert_awaited_once()
    _, kwargs = deliver.await_args
    assert kwargs["coverage_status"] == "limited"
    assert kwargs["coverage_recommendation"] == "manual_review"
    assert kwargs["report_url"] == "https://api.example.com/v1/scans/scan_abc123/report"
    terminal_fields = mock_ctx["db"].record_scan_event.await_args_list[-1].kwargs["fields"]
    assert terminal_fields["report"]["coverage_status"] == "limited"
    assert terminal_fields["report"]["coverage_recommendation"] == "manual_review"


@pytest.mark.asyncio
async def test_run_scan_job_marks_failed_unified_scan_without_webhook():
    mock_ctx = {
        "db": AsyncMock(),
        "scan_runner": MagicMock(),
        "webhook_secret": "whsec_test",
        "public_base_url": "https://api.example.com",
    }
    mock_ctx["scan_runner"].clone_repo = AsyncMock(return_value=Path("/tmp/repo"))
    mock_ctx["scan_runner"].build_trust_config = MagicMock(
        return_value=SimpleNamespace(hosted_url="https://agent.example.com")
    )

    async def _run_scan(config, *, event_callback=None):
        assert config.hosted_url == "https://agent.example.com"
        if event_callback is not None:
            await event_callback(
                {
                    "status": "scanning",
                    "phase": "source_review_completed",
                    "detail": "Source review completed.",
                    "event_type": "scan.phase",
                    "payload": {"stage": "source_review"},
                }
            )
            await event_callback(
                {
                    "status": "failed",
                    "phase": "live_attack_scan_failed",
                    "detail": "Agent never became usable enough for live attacks.",
                    "event_type": "scan.failed",
                    "payload": {"stage": "live_attack"},
                }
            )
        return SimpleNamespace(
            verdict=None,
            score=None,
            report={
                "coverage": {
                    "level": "limited",
                    "notes": ["Live attack phase could not run."],
                    "exercised_surfaces": [],
                    "skipped_surfaces": ["/", "/docs"],
                    "coverage_recommendation": "manual_review",
                },
                "failure_reason": "live_attack_unusable",
            },
            terminal_status="failed",
            error="Agent never became usable enough for the mandatory live attack scan.",
        )

    mock_ctx["scan_runner"].run_scan = AsyncMock(side_effect=_run_scan)
    mock_ctx["scan_runner"].cleanup = MagicMock()
    mock_ctx["scan_runner"].work_dir = Path("/tmp/agentgate-scans")
    mock_ctx["db"].get_scan_internal = AsyncMock(return_value={"webhook_url": "https://example.com/webhook"})
    mock_ctx["db"].record_scan_event = AsyncMock()

    with patch("agentgate.worker.tasks.deliver_webhook", new=AsyncMock(return_value=True)) as deliver:
        await run_scan_job(
            mock_ctx,
            scan_id="scan_abc123",
            repo_url="https://github.com/test/agent",
            git_ref="feature/hosted-api",
            entrypoint="main.py",
            runtime="python",
            manifest_path=None,
            dockerfile_path="Dockerfile.api",
        )

    deliver.assert_not_awaited()
    terminal_fields = mock_ctx["db"].record_scan_event.await_args_list[-1].kwargs["fields"]
    assert terminal_fields["error"] == "Agent never became usable enough for the mandatory live attack scan."
    assert terminal_fields["report"]["failure_reason"] == "live_attack_unusable"
    assert terminal_fields["report"]["coverage_status"] == "limited"
    assert terminal_fields["report"]["coverage_recommendation"] == "manual_review"
    assert mock_ctx["scan_runner"].cleanup.called
