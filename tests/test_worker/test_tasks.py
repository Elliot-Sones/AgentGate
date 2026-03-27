import pytest
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path

from agentgate.worker.tasks import run_scan_job


@pytest.mark.asyncio
async def test_run_scan_job_updates_status():
    mock_ctx = {
        "db": AsyncMock(),
        "scan_runner": MagicMock(),
        "webhook_secret": "whsec_test",
    }
    mock_ctx["scan_runner"].clone_repo = AsyncMock(return_value=Path("/tmp/repo"))
    mock_ctx["scan_runner"].build_trust_config = MagicMock()
    mock_ctx["scan_runner"].run_scan = AsyncMock(return_value=MagicMock(
        verdict="allow_clean",
        score={"checks_run": 11, "checks_passed": 11, "checks_failed": 0},
        report={"scorecard": {}},
        error=None,
    ))
    mock_ctx["scan_runner"].cleanup = MagicMock()
    mock_ctx["scan_runner"].work_dir = Path("/tmp/agentgate-scans")
    mock_ctx["db"].get_scan_internal = AsyncMock(return_value={"webhook_url": None})

    await run_scan_job(
        mock_ctx,
        scan_id="scan_abc123",
        repo_url="https://github.com/test/agent",
        entrypoint="main.py",
        runtime="python",
        manifest_path=None,
    )

    assert mock_ctx["db"].update_scan_status.call_count >= 3
    mock_ctx["scan_runner"].cleanup.assert_called_once_with("scan_abc123")
