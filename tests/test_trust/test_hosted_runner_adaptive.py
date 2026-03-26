from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from agentgate.trust.runtime.hosted_runner import HostedRuntimeRunner


def _make_runner(tmp_path: Path, adaptive_api_key: str = "") -> HostedRuntimeRunner:
    return HostedRuntimeRunner(
        base_url="https://agent.example.com",
        adaptive_api_key=adaptive_api_key,
        adaptive_model="claude-sonnet-4-6",
        source_dir=tmp_path,
        manifest={"declared_tools": ["search"], "declared_external_domains": []},
        static_findings=["some-finding"],
    )


def test_adaptive_probing_used_when_api_key_present(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, adaptive_api_key="sk-test-key")

    mock_report = MagicMock()
    mock_report.probe_results = []
    mock_orchestrator = MagicMock()
    mock_orchestrator.run.return_value = ([], [mock_report])

    with (
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._probe_static",
            return_value=[],
        ),
        patch(
            "agentgate.trust.runtime.adaptive.orchestrator.AdaptiveProbeOrchestrator",
            return_value=mock_orchestrator,
        ),
    ):
        probe_responses, reports = runner._probe_adaptive(MagicMock())

    mock_orchestrator.run.assert_called_once()


def test_fallback_to_static_probes_without_api_key(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, adaptive_api_key="")

    static_responses = [
        {
            "method": "GET",
            "path": "/",
            "status_code": 200,
            "body_snippet": "ok",
            "content_type": "",
            "error": "",
        },
    ]

    with patch.object(runner, "_probe_static", return_value=static_responses) as mock_static:
        bank = MagicMock()
        bank.tokens.return_value = {}
        # Simulate run_profile path selection without actual HTTP
        result = runner._probe_static(bank)

    mock_static.assert_called_once_with(bank)
    assert result == static_responses


def test_adaptive_probing_mode_tracked(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, adaptive_api_key="sk-test-key")

    mock_report = MagicMock()
    mock_report.probe_results = []
    mock_orchestrator = MagicMock()
    mock_orchestrator.run.return_value = ([], [mock_report])

    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    with (
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._probe_static",
            return_value=[],
        ),
        patch(
            "agentgate.trust.runtime.adaptive.orchestrator.AdaptiveProbeOrchestrator",
            return_value=mock_orchestrator,
        ),
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._fetch_railway_logs",
            return_value="",
        ),
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._discover_railway_context",
            return_value=None,
        ),
    ):
        runner.run_profile(profile="hosted", canary_profile="standard", artifact_dir=artifact_dir)

    assert runner.probing_mode == "adaptive"


def test_static_probing_mode_tracked(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, adaptive_api_key="")

    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    with (
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._probe_static",
            return_value=[],
        ),
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._fetch_railway_logs",
            return_value="",
        ),
        patch(
            "agentgate.trust.runtime.hosted_runner.HostedRuntimeRunner._discover_railway_context",
            return_value=None,
        ),
    ):
        runner.run_profile(profile="hosted", canary_profile="standard", artifact_dir=artifact_dir)

    assert runner.probing_mode == "static"
