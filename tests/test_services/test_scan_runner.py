import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from agentgate.services.scan_runner import ScanRunner


def test_scan_runner_init():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    assert runner.work_dir == Path("/tmp/agentgate-test-runner")


@pytest.mark.asyncio
async def test_scan_runner_clone_repo():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    with patch("agentgate.services.scan_runner.subprocess") as mock_subprocess:
        mock_subprocess.run = MagicMock(return_value=MagicMock(returncode=0))
        result = await runner.clone_repo(
            repo_url="https://github.com/test/agent", scan_id="scan_abc123",
        )
        mock_subprocess.run.assert_called_once()


@pytest.mark.asyncio
async def test_scan_runner_build_config():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    config = runner.build_trust_config(
        source_dir=Path("/tmp/agentgate-test-runner/scan_abc123/repo"),
        manifest_path="trust_manifest.yaml",
        output_dir=Path("/tmp/agentgate-test-runner/scan_abc123/output"),
    )
    assert config.source_dir == Path("/tmp/agentgate-test-runner/scan_abc123/repo")
