import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from types import SimpleNamespace

from agentgate.adapters.base import AdapterResponse, AgentAdapter
from agentgate.scanner import ProbeError
from agentgate.detectors import DETECTOR_REGISTRY
from agentgate.models.agent import AgentConfig
from agentgate.services.scan_runner import ScanRunner
from agentgate.trust.models import GeneratedRuntimeProfile, TrustScanResult, TrustScorecard
from agentgate.trust.policy import TrustVerdict
from agentgate.trust.runtime.railway_executor import RailwayExecutionResult


def test_scan_runner_init():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    assert runner.work_dir == Path("/tmp/agentgate-test-runner")


class _DummyAdapter(AgentAdapter):
    async def send(self, payload, **kwargs):
        raise NotImplementedError

    async def send_conversation(self, conversation, **kwargs):
        raise NotImplementedError

    async def reset(self):
        return None


@pytest.mark.asyncio
async def test_scan_runner_clone_repo():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    with patch("agentgate.services.scan_runner.subprocess") as mock_subprocess:
        mock_subprocess.run = MagicMock(return_value=MagicMock(returncode=0))
        result = await runner.clone_repo(
            repo_url="https://github.com/test/agent", git_ref="feature/hosted-api", scan_id="scan_abc123",
        )
        mock_subprocess.run.assert_called_once()
        clone_cmd = mock_subprocess.run.call_args.args[0]
        assert "--branch" in clone_cmd
        assert "feature/hosted-api" in clone_cmd


def test_scan_runner_resolves_github_tree_url():
    clone_url, git_ref = ScanRunner._resolve_clone_target(
        repo_url="https://github.com/test/agent/tree/feature/hosted-api",
        git_ref=None,
    )

    assert clone_url == "https://github.com/test/agent"
    assert git_ref == "feature/hosted-api"


@pytest.mark.asyncio
async def test_scan_runner_build_config():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    config = runner.build_trust_config(
        source_dir=Path("/tmp/agentgate-test-runner/scan_abc123/repo"),
        manifest_path="trust_manifest.yaml",
        dockerfile_path="Dockerfile.api",
        output_dir=Path("/tmp/agentgate-test-runner/scan_abc123/output"),
    )
    assert config.source_dir == Path("/tmp/agentgate-test-runner/scan_abc123/repo")
    assert config.dockerfile_path == Path("/tmp/agentgate-test-runner/scan_abc123/repo/Dockerfile.api")


def test_scan_runner_builds_budgeted_hosted_security_profile():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    source_review = {
        "attack_hints": [
            "integration:slack",
            "prompt_surface:System prompt requests hidden instructions",
        ]
    }
    scan_config = runner._build_security_scan_config(source_review=source_review)

    assert scan_config.budget.max_agent_calls == 30
    assert scan_config.budget.max_llm_judge_calls == 0
    assert scan_config.budget.max_attacker_calls == 0
    assert scan_config.max_retries == 1
    assert scan_config.enable_adaptive_attacks is False
    assert scan_config.enable_converters is False
    assert scan_config.test_case_runs_override == 1
    assert scan_config.detectors == [
        "prompt_injection",
        "system_prompt_leak",
        "tool_misuse",
        "data_exfiltration",
        "xpia",
        "goal_hijacking",
    ]
    assert scan_config.detector_case_limits == {
        "prompt_injection": 6,
        "system_prompt_leak": 4,
        "tool_misuse": 6,
        "data_exfiltration": 6,
        "xpia": 2,
        "goal_hijacking": 2,
    }


def test_scan_runner_hosted_security_profile_stays_within_30_requests():
    runner = ScanRunner(work_dir=Path("/tmp/agentgate-test-runner"))
    source_review = {
        "attack_hints": [
            "integration:shopify",
            "declared_domain:api.example.com",
            "prompt_surface:Prompt sink in runtime path",
        ]
    }
    scan_config = runner._build_security_scan_config(source_review=source_review)
    agent = AgentConfig(url="https://example.com/invoke", name="Hosted Submission")
    adapter = _DummyAdapter()

    planned_requests = 0
    for detector_name in scan_config.detectors or []:
        detector = DETECTOR_REGISTRY[detector_name](adapter=adapter, config=scan_config)
        cases = detector.generate(agent)
        limit = scan_config.detector_case_limits.get(detector_name, len(cases))
        planned_requests += min(len(cases), limit)

    assert planned_requests <= 30


@pytest.mark.asyncio
async def test_scan_runner_deploy_submission_passes_inferred_port_to_executor(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    repo_dir = tmp_path / "scan_abc123" / "repo"
    repo_dir.mkdir(parents=True)
    config = runner.build_trust_config(
        source_dir=repo_dir,
        manifest_path=None,
        dockerfile_path=None,
        output_dir=tmp_path / "scan_abc123" / "output",
    )
    generated_profile = GeneratedRuntimeProfile(
        dockerfile_path=str(repo_dir / "docker" / "Dockerfile.service"),
        port_candidates=[8080, 8501],
        issued_runtime_env={"OPENAI_API_KEY": "test-openai"},
    )
    source_review = {
        "config": config,
        "result": TrustScanResult(
            scorecard=TrustScorecard(
                checks_run=0,
                checks_passed=0,
                checks_failed=0,
                findings_total=0,
                findings_by_severity={},
                verdict=TrustVerdict.ALLOW_CLEAN,
                duration_seconds=0.0,
            ),
            findings=[],
            generated_runtime_profile=generated_profile,
        ),
    }

    captured: dict[str, object] = {}

    class _Executor:
        def deploy_submission(self, **kwargs):
            captured.update(kwargs)
            return RailwayExecutionResult(
                workspace_dir=tmp_path,
                project_id="proj_1",
                project_name="agentgate-scan",
                environment_name="production",
                service_name="submission-agent",
                public_url="https://submission.example.com",
            )

    with patch.object(ScanRunner, "_build_executor", return_value=_Executor()), patch(
        "agentgate.trust.runtime.platform_integrations.issue_all_available_credentials",
        return_value={},
    ):
        deployment = await runner._deploy_submission(
            config=config,
            source_review=source_review,
            event_callback=None,
        )

    assert deployment.public_url == "https://submission.example.com"
    assert captured["runtime_env"]["PORT"] == "8080"


@pytest.mark.asyncio
async def test_scan_runner_waits_for_live_attack_readiness(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    agent_config = AgentConfig(
        url="https://submission.example.com/invoke",
        name="Hosted Submission",
        request_field="message",
        response_field="answer",
    )

    responses = iter(
        [
            AdapterResponse(text="", status_code=502, error="HTTP 502: Application failed to respond"),
            AdapterResponse(text="hello", status_code=200, error=None),
        ]
    )
    calls: list[str] = []

    class _Adapter:
        async def send(self, message):
            calls.append(message)
            return next(responses)

        async def close(self):
            return None

    with patch("agentgate.services.scan_runner.HTTPAdapter", return_value=_Adapter()):
        await runner._await_live_attack_readiness(
            agent_config=agent_config,
            timeout_seconds=1.0,
            poll_seconds=0.0,
        )

    assert calls == ["hello", "hello"]


@pytest.mark.asyncio
async def test_scan_runner_unified_flow_reuses_one_deployment_and_feeds_forward(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    config = runner.build_trust_config(
        source_dir=tmp_path / "scan_abc123" / "repo",
        manifest_path="trust_manifest.yaml",
        dockerfile_path="Dockerfile.api",
        output_dir=tmp_path / "scan_abc123" / "output",
    )

    source_review = {
        "phase": "source_review",
        "status": "completed",
        "attack_hints": ["uses_slack_tool", "prompt_sink"],
    }
    deployment = SimpleNamespace(
        public_url="https://submission.example.com",
        project_id="proj_1",
        project_name="agentgate-scan",
        environment_name="production",
        service_name="submission-agent",
        reused_pool=True,
    )
    live_attack = {
        "phase": "live_attack_scan",
        "status": "completed",
        "findings": [{"id": "sec-1", "severity": "critical"}],
        "score": {"checks_run": 12, "checks_passed": 10, "checks_failed": 2},
        "verdict": "block",
    }
    adaptive_review = {
        "phase": "adaptive_runtime_review",
        "status": "completed",
        "findings": [{"id": "trust-1", "severity": "high"}],
    }
    merged_report = {
        "phases": {
            "source_review": source_review,
            "deployment": {
                "public_url": deployment.public_url,
                "service_name": deployment.service_name,
            },
            "live_attack_scan": live_attack,
            "adaptive_runtime_review": adaptive_review,
        },
        "verdict": "block",
        "score": {"checks_run": 13, "checks_passed": 10, "checks_failed": 3},
    }

    with patch.object(
        ScanRunner,
        "_run_source_review",
        new=AsyncMock(return_value=source_review),
        create=True,
    ) as source_review_mock, patch.object(
        ScanRunner,
        "_deploy_submission",
        new=AsyncMock(return_value=deployment),
        create=True,
    ) as deploy_mock, patch.object(
        ScanRunner,
        "_run_live_attack_scan",
        new=AsyncMock(return_value=live_attack),
        create=True,
    ) as live_attack_mock, patch.object(
        ScanRunner,
        "_run_adaptive_runtime_review",
        new=AsyncMock(return_value=adaptive_review),
        create=True,
    ) as adaptive_mock, patch.object(
        ScanRunner,
        "_merge_scan_results",
        new=MagicMock(return_value=merged_report),
        create=True,
    ) as merge_mock, patch.object(
        ScanRunner,
        "_cleanup_deployment",
        new=MagicMock(),
        create=True,
    ) as cleanup_mock:
        result = await runner.run_scan(config)

    source_review_mock.assert_awaited_once()
    deploy_mock.assert_awaited_once()
    live_attack_mock.assert_awaited_once()
    adaptive_mock.assert_awaited_once()
    merge_mock.assert_called_once()
    cleanup_mock.assert_called_once_with(deployment)

    live_kwargs = live_attack_mock.await_args.kwargs
    assert live_kwargs["source_review"] == source_review
    assert live_kwargs["deployment"] == deployment
    assert live_kwargs["source_review"]["attack_hints"] == ["uses_slack_tool", "prompt_sink"]

    adaptive_kwargs = adaptive_mock.await_args.kwargs
    assert adaptive_kwargs["source_review"] == source_review
    assert adaptive_kwargs["deployment"] == deployment
    assert adaptive_kwargs["live_attack"] == live_attack

    merge_kwargs = merge_mock.call_args.kwargs
    assert merge_kwargs["source_review"] == source_review
    assert merge_kwargs["deployment"] == deployment
    assert merge_kwargs["live_attack"] == live_attack
    assert merge_kwargs["adaptive_review"] == adaptive_review

    assert result.terminal_status == "completed"
    assert result.verdict == "block"
    assert result.score == merged_report["score"]
    assert result.report == merged_report


@pytest.mark.asyncio
async def test_scan_runner_marks_failed_when_live_attack_never_becomes_usable(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    config = runner.build_trust_config(
        source_dir=tmp_path / "scan_abc123" / "repo",
        manifest_path="trust_manifest.yaml",
        dockerfile_path="Dockerfile.api",
        output_dir=tmp_path / "scan_abc123" / "output",
    )

    source_review = {
        "phase": "source_review",
        "status": "completed",
        "attack_hints": ["prompt_sink"],
    }
    deployment = SimpleNamespace(
        public_url="https://submission.example.com",
        project_id="proj_1",
        project_name="agentgate-scan",
        environment_name="production",
        service_name="submission-agent",
        reused_pool=True,
    )
    unusable_live_attack = {
        "phase": "live_attack_scan",
        "status": "failed",
        "usable": False,
        "error": "agent never became usable enough for the mandatory live attack phase",
    }
    partial_report = {
        "phases": {
            "source_review": source_review,
            "deployment": {
                "public_url": deployment.public_url,
                "service_name": deployment.service_name,
            },
            "live_attack_scan": {
                "status": "failed",
                "detail": "agent never became usable enough for the mandatory live attack phase",
            },
        },
        "coverage_status": "limited",
        "coverage_recommendation": "manual_review",
    }

    with patch.object(
        ScanRunner,
        "_run_source_review",
        new=AsyncMock(return_value=source_review),
        create=True,
    ), patch.object(
        ScanRunner,
        "_deploy_submission",
        new=AsyncMock(return_value=deployment),
        create=True,
    ), patch.object(
        ScanRunner,
        "_run_live_attack_scan",
        new=AsyncMock(return_value=unusable_live_attack),
        create=True,
    ) as live_attack_mock, patch.object(
        ScanRunner,
        "_run_adaptive_runtime_review",
        new=AsyncMock(),
        create=True,
    ) as adaptive_mock, patch.object(
        ScanRunner,
        "_merge_scan_results",
        new=MagicMock(return_value=partial_report),
        create=True,
    ) as merge_mock, patch.object(
        ScanRunner,
        "_cleanup_deployment",
        new=MagicMock(),
        create=True,
    ) as cleanup_mock:
        result = await runner.run_scan(config)

    live_attack_mock.assert_awaited_once()
    adaptive_mock.assert_not_called()
    merge_mock.assert_called_once()
    cleanup_mock.assert_called_once_with(deployment)

    merge_kwargs = merge_mock.call_args.kwargs
    assert merge_kwargs["source_review"] == source_review
    assert merge_kwargs["deployment"] == deployment
    assert merge_kwargs["live_attack"] == unusable_live_attack
    assert merge_kwargs["adaptive_review"] is None

    assert result.terminal_status == "failed"
    assert result.verdict is None
    assert result.score is None
    assert result.error == "agent never became usable enough for the mandatory live attack phase"
    assert result.report == partial_report


@pytest.mark.asyncio
async def test_await_live_attack_readiness_raises_structured_probe_error_on_401(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    agent_config = AgentConfig(url="https://example.com/chat", name="test")

    class _Adapter:
        async def send(self, message):
            return AdapterResponse(text="Unauthorized", status_code=401, error=None)

        async def close(self):
            return None

    with patch("agentgate.services.scan_runner.HTTPAdapter", return_value=_Adapter()):
        with pytest.raises(ProbeError) as exc_info:
            await runner._await_live_attack_readiness(
                agent_config=agent_config,
                timeout_seconds=0.1,
                poll_seconds=0.05,
            )

    exc = exc_info.value
    assert exc.status_code == 401
    assert exc.target_url == "https://example.com/chat"
    assert "Unauthorized" in exc.response_excerpt


@pytest.mark.asyncio
async def test_await_live_attack_readiness_raises_none_status_on_connection_error(tmp_path):
    runner = ScanRunner(work_dir=tmp_path)
    agent_config = AgentConfig(url="https://example.com/chat", name="test")

    class _Adapter:
        async def send(self, message):
            return AdapterResponse(text="", status_code=0, error="Connection refused")

        async def close(self):
            return None

    with patch("agentgate.services.scan_runner.HTTPAdapter", return_value=_Adapter()):
        with pytest.raises(ProbeError) as exc_info:
            await runner._await_live_attack_readiness(
                agent_config=agent_config,
                timeout_seconds=0.1,
                poll_seconds=0.05,
            )

    exc = exc_info.value
    assert exc.status_code is None


def test_classify_probe_failure_401_is_auth_required():
    exc = ProbeError("HTTP 401", status_code=401)
    assert ScanRunner._classify_probe_failure(exc) == "auth_required"


def test_classify_probe_failure_403_is_auth_required():
    exc = ProbeError("HTTP 403", status_code=403)
    assert ScanRunner._classify_probe_failure(exc) == "auth_required"


def test_classify_probe_failure_404_is_endpoint_not_found():
    exc = ProbeError("HTTP 404", status_code=404)
    assert ScanRunner._classify_probe_failure(exc) == "endpoint_not_found"


def test_classify_probe_failure_500_is_deployment_unusable():
    exc = ProbeError("HTTP 500", status_code=500)
    assert ScanRunner._classify_probe_failure(exc) == "deployment_unusable"


def test_classify_probe_failure_502_is_deployment_unusable():
    exc = ProbeError("HTTP 502", status_code=502)
    assert ScanRunner._classify_probe_failure(exc) == "deployment_unusable"


def test_classify_probe_failure_none_status_is_boot_timeout():
    exc = ProbeError("Connection refused", status_code=None)
    assert ScanRunner._classify_probe_failure(exc) == "boot_timeout"
