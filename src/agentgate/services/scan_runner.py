from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
import ipaddress
import logging
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from agentgate.adapters.http import HTTPAdapter
from agentgate.config import ScanBudget, ScanConfig
from agentgate.models.agent import AgentConfig
from agentgate.models.score import FailedTest
from agentgate.scanner import ProbeError, ScanResult as SecurityScanResult, Scanner
from agentgate.trust.checks import BaseTrustCheck, default_trust_checks
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.models import (
    CoverageSummary,
    GeneratedRuntimeProfile,
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustSeverity,
)
from agentgate.trust.normalizer import normalize_finding
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.runtime.railway_executor import (
    RailwayExecutionError,
    RailwayExecutionResult,
    RailwayExecutor,
)
from agentgate.trust.signals import TrustSignal

logger = logging.getLogger(__name__)
_GITHUB_TREE_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/tree/(?P<ref>.+)$"
)
_SOURCE_REVIEW_SENTINEL = "agentgate://source-review"
_SECURITY_SEVERITY_MAP: dict[str, TrustSeverity] = {
    "data_exfiltration": TrustSeverity.CRITICAL,
    "tool_misuse": TrustSeverity.CRITICAL,
    "system_prompt_leak": TrustSeverity.CRITICAL,
    "prompt_injection": TrustSeverity.HIGH,
    "goal_hijacking": TrustSeverity.HIGH,
    "xpia": TrustSeverity.HIGH,
    "policy_violation": TrustSeverity.HIGH,
    "reliability": TrustSeverity.MEDIUM,
    "scope_adherence": TrustSeverity.MEDIUM,
    "input_validation": TrustSeverity.MEDIUM,
    "hallucination": TrustSeverity.MEDIUM,
    "harmful_content": TrustSeverity.MEDIUM,
}
_SECURITY_CATEGORY_MAP: dict[str, TrustCategory] = {
    "data_exfiltration": TrustCategory.EGRESS,
    "tool_misuse": TrustCategory.TOOL_INTEGRITY,
    "system_prompt_leak": TrustCategory.HIDDEN_BEHAVIOR,
    "prompt_injection": TrustCategory.HIDDEN_BEHAVIOR,
    "goal_hijacking": TrustCategory.HIDDEN_BEHAVIOR,
    "xpia": TrustCategory.HIDDEN_BEHAVIOR,
    "policy_violation": TrustCategory.HIDDEN_BEHAVIOR,
    "reliability": TrustCategory.RUNTIME_INTEGRITY,
    "scope_adherence": TrustCategory.RUNTIME_INTEGRITY,
    "input_validation": TrustCategory.RUNTIME_INTEGRITY,
    "hallucination": TrustCategory.RUNTIME_INTEGRITY,
    "harmful_content": TrustCategory.RUNTIME_INTEGRITY,
}
_SECURITY_CONTEXT_FILE_MAP = {"runtime://live_attack": "runtime_code"}
_SECURITY_CONTEXT_REACHABILITY = {"runtime://live_attack": "on_execution_path"}
_HOSTED_SECURITY_CORE_LIMITS: dict[str, int] = {
    "prompt_injection": 6,
    "system_prompt_leak": 4,
    "tool_misuse": 6,
    "data_exfiltration": 6,
}
_HOSTED_SECURITY_EXTRA_LIMITS: dict[str, int] = {
    "xpia": 2,
    "goal_hijacking": 2,
    "input_validation": 2,
}
_DOCS_OPENAPI_URL_RE = re.compile(
    r"""(?:openapiUrl|url)\s*[:=]\s*["'](?P<path>[^"']*openapi\.json[^"']*)["']""",
    re.IGNORECASE,
)
_INTERACTIVE_ROUTE_TOKENS = (
    "/invoke",
    "/api/v1/chat",
    "/chat",
    "/query",
    "/search",
    "/run",
    "/predict",
)


@dataclass
class ScanRunResult:
    verdict: str | None
    score: dict | None
    report: dict
    terminal_status: str = "completed"
    error: str | None = None
    failure_reason: str | None = None


class ScanRunner:
    def __init__(
        self,
        work_dir: Path,
        *,
        railway_workspace_id: str = "",
        railway_pool_workspace_dir: Path | None = None,
        railway_pool_environment: str = "",
        railway_pool_service: str = "submission-agent",
        adaptive_trust: bool = False,
    ) -> None:
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.railway_workspace_id = railway_workspace_id
        self.railway_pool_workspace_dir = railway_pool_workspace_dir
        self.railway_pool_environment = railway_pool_environment
        self.railway_pool_service = railway_pool_service
        self.adaptive_trust = adaptive_trust

    async def clone_repo(self, *, repo_url: str, git_ref: str | None, scan_id: str) -> Path:
        clone_dir = self.work_dir / scan_id / "repo"
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        clone_url, resolved_ref = self._resolve_clone_target(repo_url=repo_url, git_ref=git_ref)
        self._assert_public_clone_target(clone_url)
        clone_cmd = ["git", "clone", "--depth", "1"]
        if resolved_ref:
            clone_cmd.extend(["--branch", resolved_ref, "--single-branch"])
        clone_cmd.extend([clone_url, str(clone_dir)])
        result = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
        return clone_dir

    @staticmethod
    def _resolve_clone_target(*, repo_url: str, git_ref: str | None) -> tuple[str, str | None]:
        if git_ref:
            return repo_url, git_ref.strip()

        match = _GITHUB_TREE_URL_RE.match(repo_url.strip())
        if not match:
            return repo_url, None

        owner = match.group("owner")
        repo = match.group("repo")
        ref = match.group("ref").strip("/")
        clone_url = f"https://github.com/{owner}/{repo}"
        return clone_url, ref or None

    @staticmethod
    def _assert_public_clone_target(repo_url: str) -> None:
        parsed = urlparse(repo_url)
        hostname = parsed.hostname or ""
        if parsed.scheme not in {"http", "https"} or not hostname:
            return

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            results = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise RuntimeError(f"git clone target could not be resolved: {hostname}") from exc

        for _, _, _, _, sockaddr in results:
            addr = ipaddress.ip_address(sockaddr[0])
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                raise RuntimeError(
                    f"git clone target {hostname} resolves to private address {addr}"
                )

    def build_trust_config(
        self,
        *,
        source_dir: Path,
        manifest_path: str | None,
        dockerfile_path: str | None,
        output_dir: Path,
    ) -> TrustScanConfig:
        resolved_manifest = source_dir / manifest_path if manifest_path else None
        resolved_dockerfile = source_dir / dockerfile_path if dockerfile_path else None
        return TrustScanConfig(
            source_dir=source_dir,
            image_ref="",
            manifest_path=resolved_manifest,
            dockerfile_path=resolved_dockerfile,
            output_dir=output_dir,
            quiet=True,
            railway_workspace_id=self.railway_workspace_id,
            railway_pool_workspace_dir=self.railway_pool_workspace_dir,
            railway_pool_environment=self.railway_pool_environment,
            railway_pool_service=self.railway_pool_service,
            adaptive_trust=self.adaptive_trust,
        )

    async def run_scan(
        self,
        config: TrustScanConfig,
        *,
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None = None,
    ) -> ScanRunResult:
        deployment: RailwayExecutionResult | None = None
        source_review: dict[str, object] | None = None
        live_attack: dict[str, object] | None = None
        adaptive_review: dict[str, object] | None = None

        try:
            source_review = await self._run_source_review(config=config, event_callback=event_callback)
            deployment = await self._deploy_submission(
                config=config,
                source_review=source_review,
                event_callback=event_callback,
            )
            live_attack = await self._run_live_attack_scan(
                config=config,
                source_review=source_review,
                deployment=deployment,
                event_callback=event_callback,
            )
            live_attack_usable = self._live_attack_usable(live_attack)
            if not live_attack_usable:
                error = str(live_attack.get("error") or "").strip() or (
                    "Agent never became usable enough for the mandatory live attack scan."
                )
                failure_reason = str(live_attack.get("failure_reason") or "live_attack_unusable")
                report = self._merge_scan_results(
                    source_review=source_review,
                    deployment=deployment,
                    live_attack=live_attack,
                    adaptive_review=None,
                    terminal_status="failed",
                    failure_reason=failure_reason,
                )
                return ScanRunResult(
                    verdict=None,
                    score=None,
                    report=report,
                    terminal_status="failed",
                    error=error,
                    failure_reason=failure_reason,
                )

            adaptive_review = await self._run_adaptive_runtime_review(
                config=config,
                source_review=source_review,
                deployment=deployment,
                live_attack=live_attack,
                event_callback=event_callback,
            )
            report = self._merge_scan_results(
                source_review=source_review,
                deployment=deployment,
                live_attack=live_attack,
                adaptive_review=adaptive_review,
                terminal_status="completed",
                failure_reason=None,
            )
            return ScanRunResult(
                verdict=str(report.get("verdict")) if report.get("verdict") else None,
                score=report.get("score") if isinstance(report.get("score"), dict) else None,
                report=report,
                terminal_status="completed",
                error=None,
            )
        except RailwayExecutionError as exc:
            error = str(exc).strip() or "Deployment failed before live attack scanning could start."
            live_attack = {
                "phase": "live_attack_scan",
                "status": "failed",
                "usable": False,
                "error": error,
                "failure_reason": "deployment_failed",
                "report": {
                    "phase": "live_attack_scan",
                    "status": "failed",
                    "detail": error,
                },
            }
            report = self._merge_scan_results(
                source_review=source_review,
                deployment=deployment,
                live_attack=live_attack,
                adaptive_review=None,
                terminal_status="failed",
                failure_reason="deployment_failed",
            )
            return ScanRunResult(
                verdict=None,
                score=None,
                report=report,
                terminal_status="failed",
                error=error,
                failure_reason="deployment_failed",
            )
        finally:
            if deployment is not None:
                try:
                    await self._emit_event(
                        event_callback,
                        status="scanning",
                        phase="cleanup_started",
                        detail="Cleaning up the temporary Railway deployment.",
                        event_type="scan.cleanup",
                    )
                    self._cleanup_deployment(deployment)
                    await self._emit_event(
                        event_callback,
                        status="scanning",
                        phase="cleanup_completed",
                        detail="Temporary Railway deployment cleaned up.",
                        event_type="scan.cleanup",
                    )
                except Exception:
                    logger.exception("Failed to cleanup temporary Railway deployment after hosted scan.")
                    await self._emit_event(
                        event_callback,
                        status="scanning",
                        phase="cleanup_failed",
                        detail="Failed to clean up the temporary Railway deployment.",
                        event_type="scan.warning",
                    )

    async def _run_source_review(
        self,
        *,
        config: TrustScanConfig,
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None,
    ) -> dict[str, object]:
        await self._emit_event(
            event_callback,
            status="scanning",
            phase="source_review_started",
            detail="Inspecting the repository before deployment.",
            event_type="scan.phase",
        )
        source_config = replace(config)
        source_config.hosted_url = _SOURCE_REVIEW_SENTINEL
        source_config.keep_environment_on_failure = True
        if not source_config.strict_production_contract and not source_config.railway_workspace_id:
            source_config.strict_production_contract = True
        checks = [check for check in default_trust_checks() if not self._is_runtime_check(check)]

        from agentgate.trust.scanner import TrustScanner

        result = await TrustScanner(config=source_config, checks=checks).run()
        attack_hints = self._build_attack_hints(result)
        prior_findings = self._summarize_findings(result.findings)
        payload = {
            "attack_hints": attack_hints,
            "check_count": len(checks),
            "finding_count": len(result.findings),
        }
        await self._emit_event(
            event_callback,
            status="scanning",
            phase="source_review_completed",
            detail="Static source review completed.",
            event_type="scan.phase",
            payload=payload,
        )
        return {
            "phase": "source_review",
            "status": "completed",
            "attack_hints": attack_hints,
            "prior_findings": prior_findings,
            "config": source_config,
            "result": result,
            "report": result.model_dump(mode="json"),
        }

    async def _deploy_submission(
        self,
        *,
        config: TrustScanConfig,
        source_review: dict[str, object],
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None,
    ) -> RailwayExecutionResult:
        review_config = source_review["config"]
        assert isinstance(review_config, TrustScanConfig)
        generated_profile = source_review["result"].generated_runtime_profile if isinstance(source_review.get("result"), TrustScanResult) else None

        await self._emit_event(
            event_callback,
            status="deploying",
            phase="deployment_started",
            detail="Deploying the submission to Railway.",
            event_type="scan.phase",
            payload={
                "pool_mode": bool(config.railway_pool_workspace_dir),
                "dependency_count": len(review_config.dependencies),
            },
        )

        runtime_env = dict(review_config.runtime_env)
        # Ensure platform credentials from the generated profile reach the deployed agent.
        # The source review's TrustScanner._apply_generated_profile uses setdefault on
        # review_config.runtime_env, but if the profile was empty or integration detection
        # didn't fire, the credentials won't be there. Merge them explicitly.
        if generated_profile is not None:
            for key, value in getattr(generated_profile, "issued_runtime_env", {}).items():
                runtime_env.setdefault(key, value)
            if "PORT" not in runtime_env and generated_profile.port_candidates:
                runtime_env["PORT"] = str(generated_profile.port_candidates[0])
        # Also inject any AGENTGATE_PLATFORM_* credentials directly from the worker
        # environment as a fallback, so agents get LLM keys even if source-level
        # integration detection missed them.
        from agentgate.trust.runtime.platform_integrations import issue_all_available_credentials
        for key, value in issue_all_available_credentials().items():
            runtime_env.setdefault(key, value)

        deployment = self._build_executor(config).deploy_submission(
            source_dir=review_config.source_dir or config.source_dir or self.work_dir,
            dockerfile_path=self._resolve_deployment_dockerfile(
                generated_profile,
                review_config,
            ),
            dependencies=review_config.dependencies,
            runtime_env=runtime_env,
            issued_integrations=self._issued_integrations(generated_profile),
        )
        await self._emit_event(
            event_callback,
            status="deploying",
            phase="deployment_ready",
            detail="Railway deployment is ready for live attack scanning.",
            event_type="scan.phase",
            payload={
                "public_url": deployment.public_url,
                "project_id": deployment.project_id,
                "project_name": deployment.project_name,
                "environment_name": deployment.environment_name,
                "service_name": deployment.service_name,
                "reused_pool": deployment.reused_pool,
            },
        )
        return deployment

    async def _run_live_attack_scan(
        self,
        *,
        config: TrustScanConfig,
        source_review: dict[str, object],
        deployment: RailwayExecutionResult,
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None,
    ) -> dict[str, object]:
        generated_profile = self._generated_profile_from_phase(source_review)
        await self._await_live_surface_ready(
            base_url=deployment.public_url,
            runtime_profile=generated_profile,
        )
        target_url, request_field = self._resolve_security_target(deployment.public_url, generated_profile)
        target_url, request_field = await self._resolve_live_security_target(
            base_url=deployment.public_url,
            runtime_profile=generated_profile,
            fallback_target_url=target_url,
            fallback_request_field=request_field,
        )
        response_field = self._resolve_security_response_field(target_url)
        attack_hints = [str(item) for item in source_review.get("attack_hints", [])]

        await self._emit_event(
            event_callback,
            status="scanning",
            phase="live_attack_scan_started",
            detail="Running the mandatory live attack scan.",
            event_type="scan.phase",
            payload={
                "target_url": target_url,
                "request_field": request_field,
                "response_field": response_field,
                "attack_hint_count": len(attack_hints),
            },
        )

        try:
            agent_config = self._build_security_agent_config(
                source_review=source_review,
                target_url=target_url,
                request_field=request_field,
                response_field=response_field,
                attack_hints=attack_hints,
            )
            try:
                await self._await_live_attack_readiness(agent_config=agent_config)
            except ProbeError as exc:
                if self._should_skip_live_attack_scan(
                    runtime_profile=generated_profile,
                    base_url=deployment.public_url,
                    target_url=target_url,
                ):
                    detail = (
                        "No interactive text endpoint was discovered; skipping the generic live "
                        "attack scan and continuing with runtime integration checks."
                    )
                    await self._emit_event(
                        event_callback,
                        status="scanning",
                        phase="live_attack_scan_skipped",
                        detail=detail,
                        event_type="scan.phase",
                        payload={
                            "target_url": target_url,
                            "reason": "integration_only_agent",
                            "probe_error": str(exc),
                        },
                    )
                    return {
                        "phase": "live_attack_scan",
                        "status": "skipped",
                        "usable": True,
                        "error": None,
                        "failure_reason": None,
                        "report": {
                            "phase": "live_attack_scan",
                            "status": "skipped",
                            "detail": detail,
                            "target_url": target_url,
                            "request_field": request_field,
                            "response_field": response_field,
                            "attack_hints": attack_hints,
                        },
                    }
                raise
            scan_config = self._build_security_scan_config(source_review=source_review)
            scanner = Scanner(agent_config=agent_config, scan_config=scan_config)
            result = await asyncio.wait_for(scanner.run(), timeout=720)
        except asyncio.TimeoutError:
            error = "Live attack scan timed out after 12 minutes."
            await self._emit_event(
                event_callback,
                status="failed",
                phase="live_attack_scan_failed",
                detail=error,
                event_type="scan.failed",
                payload={"target_url": target_url},
            )
            return {
                "phase": "live_attack_scan",
                "status": "failed",
                "usable": False,
                "error": error,
                "failure_reason": "live_attack_timeout",
                "report": {
                    "phase": "live_attack_scan",
                    "status": "failed",
                    "detail": error,
                    "target_url": target_url,
                },
            }
        except ProbeError as exc:
            error = str(exc).strip() or "Agent never became usable enough for the mandatory live attack scan."
            failure_reason = self._classify_probe_failure(exc)
            if failure_reason == "auth_required":
                generated_profile = self._generated_profile_from_phase(source_review)
                auth_likely = generated_profile.auth_likely if generated_profile else False
                if auth_likely:
                    error = (
                        f"Agent returned HTTP {exc.status_code}. "
                        "Static analysis detected auth patterns confirming the agent requires "
                        "authentication credentials not available in sandbox."
                    )
                else:
                    error = (
                        f"Agent returned HTTP {exc.status_code}. "
                        "No auth patterns were detected in source — the "
                        f"{exc.status_code} may be from an upstream dependency or "
                        "middleware not visible in code."
                    )
            await self._emit_event(
                event_callback,
                status="failed",
                phase="live_attack_scan_failed",
                detail=error,
                event_type="scan.failed",
                payload={"target_url": target_url},
            )
            report_payload: dict[str, object] = {
                "phase": "live_attack_scan",
                "status": "failed",
                "detail": error,
                "target_url": target_url,
                "request_field": request_field,
                "response_field": response_field,
                "attack_hints": attack_hints,
            }
            if failure_reason == "boot_timeout":
                report_payload["reachable_before_timeout"] = exc.reachable_before_timeout
            return {
                "phase": "live_attack_scan",
                "status": "failed",
                "usable": False,
                "error": error,
                "failure_reason": failure_reason,
                "report": report_payload,
            }

        usable = result.scorecard.total_tests_run > 0
        bridged_findings = self._bridge_security_findings(result)
        prior_findings = self._summarize_findings(bridged_findings)
        report = {
            "phase": "live_attack_scan",
            "status": "completed" if usable else "failed",
            "usable": usable,
            "target_url": target_url,
            "request_field": request_field,
            "response_field": response_field,
            "attack_hints": attack_hints,
            "scorecard": result.scorecard.model_dump(mode="json"),
            "results_by_detector": {
                detector: [item.model_dump(mode="json") for item in results]
                for detector, results in result.results_by_detector.items()
            },
            "errors": dict(result.errors),
            "findings": [finding.model_dump(mode="json") for finding in bridged_findings],
            "duration_seconds": round(result.duration, 3),
        }
        if not usable:
            report["detail"] = "Security detectors did not execute any live tests."
            report["failure_reason"] = "live_attack_unusable"
        await self._emit_event(
            event_callback,
            status="scanning" if usable else "failed",
            phase="live_attack_scan_completed" if usable else "live_attack_scan_failed",
            detail=(
                "Live attack scanning completed."
                if usable
                else "Security detectors did not execute any live tests."
            ),
            event_type="scan.phase" if usable else "scan.failed",
            payload={
                "target_url": target_url,
                "tests_run": result.scorecard.total_tests_run,
                "tests_failed": result.scorecard.total_tests_failed,
                "finding_count": len(bridged_findings),
            },
        )
        return {
            "phase": "live_attack_scan",
            "status": report["status"],
            "usable": usable,
            "error": None if usable else "Security detectors did not execute any live tests.",
            "failure_reason": None if usable else "live_attack_unusable",
            "report": report,
            "result": result,
            "findings": bridged_findings,
            "prior_findings": prior_findings,
            "score": {
                "checks_run": result.scorecard.total_tests_run,
                "checks_passed": result.scorecard.total_tests_passed,
                "checks_failed": result.scorecard.total_tests_failed,
            },
        }

    async def _run_adaptive_runtime_review(
        self,
        *,
        config: TrustScanConfig,
        source_review: dict[str, object],
        deployment: RailwayExecutionResult,
        live_attack: dict[str, object],
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None,
    ) -> dict[str, object]:
        await self._emit_event(
            event_callback,
            status="scanning",
            phase="adaptive_runtime_review_started",
            detail="Running adaptive runtime review against the deployed agent.",
            event_type="scan.phase",
        )

        runtime_config = replace(source_review["config"])
        assert isinstance(runtime_config, TrustScanConfig)
        runtime_config.hosted_url = deployment.public_url
        runtime_config.railway_workspace_dir = deployment.workspace_dir
        runtime_config.railway_service = deployment.service_name
        runtime_config.railway_environment = deployment.environment_name
        runtime_config.keep_environment_on_failure = True
        runtime_config.prior_findings_seed = (
            list(source_review.get("prior_findings", []))
            + list(live_attack.get("prior_findings", []))
        )
        runtime_checks = [check for check in default_trust_checks() if self._is_runtime_check(check)]

        from agentgate.trust.scanner import TrustScanner

        result = await TrustScanner(config=runtime_config, checks=runtime_checks).run()
        await self._emit_event(
            event_callback,
            status="scanning",
            phase="adaptive_runtime_review_completed",
            detail="Adaptive runtime review completed.",
            event_type="scan.phase",
            payload={
                "check_count": len(runtime_checks),
                "finding_count": len(result.findings),
                "coverage_level": result.coverage.level if result.coverage is not None else "limited",
            },
        )
        return {
            "phase": "adaptive_runtime_review",
            "status": "completed",
            "config": runtime_config,
            "result": result,
            "report": result.model_dump(mode="json"),
        }

    def _merge_scan_results(
        self,
        *,
        source_review: dict[str, object] | None,
        deployment: RailwayExecutionResult | None,
        live_attack: dict[str, object] | None,
        adaptive_review: dict[str, object] | None,
        terminal_status: str,
        failure_reason: str | None,
    ) -> dict:
        source_result = source_review.get("result") if source_review else None
        runtime_result = adaptive_review.get("result") if adaptive_review else None
        source_findings = list(source_result.findings) if isinstance(source_result, TrustScanResult) else []
        security_findings = list(live_attack.get("findings", [])) if live_attack else []
        runtime_findings = list(runtime_result.findings) if isinstance(runtime_result, TrustScanResult) else []
        merged_findings = source_findings + security_findings + runtime_findings

        coverage = (
            runtime_result.coverage
            if isinstance(runtime_result, TrustScanResult) and runtime_result.coverage is not None
            else CoverageSummary(
                level="limited",
                notes=[
                    "The hosted scan did not complete all runtime phases."
                    if terminal_status == "failed"
                    else "No adaptive runtime review completed."
                ],
                coverage_recommendation="manual_review",
            )
        )
        policy = TrustPolicy()
        verdict = (
            policy.verdict_for_findings(merged_findings).value
            if terminal_status == "completed"
            else None
        )
        score = (
            {
                "checks_run": self._phase_checks_run(source_result, live_attack, runtime_result),
                "checks_passed": self._phase_checks_passed(source_result, live_attack, runtime_result),
                "checks_failed": self._phase_checks_failed(source_result, live_attack, runtime_result),
            }
            if terminal_status == "completed"
            else None
        )
        report = {
            "scan_kind": "unified_hosted",
            "status": terminal_status,
            "failure_reason": failure_reason,
            "failure_explanation": self._explain_failure(failure_reason),
            "coverage_status": coverage.level,
            "coverage_recommendation": coverage.coverage_recommendation,
            "coverage": coverage.model_dump(mode="json"),
            "verdict": verdict,
            "score": score,
            "findings": [finding.model_dump(mode="json") for finding in merged_findings],
            "phases": {
                "source_review": source_review.get("report") if source_review else None,
                "deployment": self._deployment_report(deployment),
                "live_attack_scan": live_attack.get("report") if live_attack else None,
                "adaptive_runtime_review": adaptive_review.get("report") if adaptive_review else None,
            },
        }
        return report

    def _cleanup_deployment(self, deployment: RailwayExecutionResult) -> None:
        self._build_executor(None).cleanup(deployment)

    @staticmethod
    def _live_attack_usable(live_attack: dict[str, object] | None) -> bool:
        if not isinstance(live_attack, dict):
            return False
        if "usable" in live_attack:
            return bool(live_attack.get("usable"))
        return str(live_attack.get("status") or "").strip().lower() == "completed"

    def _build_executor(self, config: TrustScanConfig | None) -> RailwayExecutor:
        config = config or TrustScanConfig(
            source_dir=None,
            image_ref="",
            manifest_path=None,
            output_dir=self.work_dir,
            railway_workspace_id=self.railway_workspace_id,
            railway_pool_workspace_dir=self.railway_pool_workspace_dir,
            railway_pool_environment=self.railway_pool_environment,
            railway_pool_service=self.railway_pool_service,
        )
        return RailwayExecutor(
            workspace_id=config.railway_workspace_id,
            project_token=config.railway_project_token,
            pool_workspace_dir=config.railway_pool_workspace_dir,
            pool_environment=config.railway_pool_environment,
            pool_service_name=config.railway_pool_service or "submission-agent",
        )

    @staticmethod
    def _is_runtime_check(check: BaseTrustCheck) -> bool:
        check_id = str(getattr(check, "check_id", "") or "").strip().lower()
        return check_id.startswith("runtime_")

    @staticmethod
    def _resolve_deployment_dockerfile(
        generated_profile: GeneratedRuntimeProfile | None,
        config: TrustScanConfig,
    ) -> Path | None:
        dockerfile_path = str(generated_profile.dockerfile_path).strip() if generated_profile else ""
        if dockerfile_path and config.source_dir is not None:
            path = Path(dockerfile_path)
            if not path.is_absolute():
                return config.source_dir / path
            return path
        return config.dockerfile_path

    @staticmethod
    def _issued_integrations(generated_profile: GeneratedRuntimeProfile | None) -> list[str]:
        if generated_profile is None:
            return []
        return list(generated_profile.issued_integrations)

    @staticmethod
    def _build_attack_hints(result: TrustScanResult) -> list[str]:
        hints: list[str] = []
        overview = result.agent_overview
        if overview is not None:
            for tool in overview.declared_tools[:5]:
                text = str(tool).strip()
                if text:
                    hints.append(f"declared_tool:{text}")
            for integration in overview.integrations[:5]:
                text = str(integration).strip()
                if text:
                    hints.append(f"integration:{text}")
            for domain in overview.declared_external_domains[:5]:
                text = str(domain).strip()
                if text:
                    hints.append(f"declared_domain:{text}")

        for finding in result.findings:
            if finding.check_id == "static_prompt_tool_inspection":
                hints.append(f"prompt_surface:{finding.title}")
            elif finding.check_id == "static_code_signals":
                hints.append(f"code_signal:{finding.title}")

        generated_profile = getattr(result, "generated_runtime_profile", None)
        if generated_profile is not None and getattr(generated_profile, "auth_likely", False):
            hints.append("auth_signal:detected")

        deduped: list[str] = []
        seen: set[str] = set()
        for hint in hints:
            if hint not in seen:
                seen.add(hint)
                deduped.append(hint)
        return deduped[:12]

    @staticmethod
    def _summarize_findings(findings: list[TrustFinding], *, cap: int = 20) -> list[str]:
        summaries: list[str] = []
        for finding in findings:
            location = ""
            if finding.location_path:
                location = f" — {finding.location_path}"
                if finding.location_line:
                    location += f":{finding.location_line}"
            summaries.append(f"[{finding.severity.value.upper()}] {finding.title}{location}")
            if len(summaries) >= cap:
                break
        return summaries

    def _build_security_agent_config(
        self,
        *,
        source_review: dict[str, object],
        target_url: str,
        request_field: str,
        response_field: str,
        attack_hints: list[str],
    ) -> AgentConfig:
        review_result = source_review.get("result")
        overview = review_result.agent_overview if isinstance(review_result, TrustScanResult) else None
        generated_profile = self._generated_profile_from_phase(source_review)
        capabilities: list[str] = []
        if overview is not None:
            capabilities.extend(str(item).strip() for item in overview.declared_tools if str(item).strip())
            capabilities.extend(str(item).strip() for item in overview.integrations if str(item).strip())
        if generated_profile is not None:
            capabilities.extend(str(item).strip() for item in generated_profile.integrations if str(item).strip())
        capabilities = list(dict.fromkeys(item for item in capabilities if item))

        description_parts: list[str] = []
        if overview is not None:
            if overview.description:
                description_parts.append(overview.description)
            if overview.business_use_case:
                description_parts.append(f"Business use case: {overview.business_use_case}")
        description_parts.append(
            "Source review identified likely attack surfaces that should guide dynamic probes."
        )
        return AgentConfig(
            url=target_url,
            name=(overview.name if overview and overview.name else "Hosted Submission"),
            description=" ".join(part for part in description_parts if part).strip(),
            capabilities=capabilities,
            attack_hints=attack_hints,
            request_field=request_field,
            response_field=response_field,
            request_defaults=self._security_request_defaults(target_url),
        )

    @staticmethod
    def _classify_probe_failure(exc: ProbeError) -> str:
        if exc.status_code in (401, 403):
            return "auth_required"
        if exc.status_code == 404:
            return "endpoint_not_found"
        if exc.status_code is not None and exc.status_code >= 500:
            return "deployment_unusable"
        return "boot_timeout"

    @staticmethod
    def _explain_failure(failure_reason: str | None, error: str | None = None) -> dict | None:
        if not failure_reason:
            return None
        explanations: dict[str, dict[str, str]] = {
            "auth_required": {
                "title": "Authentication Required",
                "description": (
                    "The agent returned 401/403 during live probing. It requires "
                    "authentication credentials (API key, Bearer token, or login) that "
                    "AgentGate cannot simulate in its sandbox environment."
                ),
                "action": (
                    "Provide test credentials or a sandbox environment where the agent "
                    "can be probed without authentication. Alternatively, submit a trust "
                    "manifest with auth configuration."
                ),
            },
            "endpoint_not_found": {
                "title": "Endpoint Not Found",
                "description": (
                    "The live target endpoint returned 404. AgentGate discovered the "
                    "agent's API surface but the selected endpoint does not exist or "
                    "has a different path than expected."
                ),
                "action": (
                    "Verify the agent exposes an HTTP endpoint at the expected path. "
                    "If the agent uses a non-standard route, provide an OpenAPI spec or "
                    "trust manifest with the correct entrypoint."
                ),
            },
            "deployment_unusable": {
                "title": "Deployment Not Responding",
                "description": (
                    "The agent was deployed but returned 5xx errors. It booted but is not "
                    "serving usable responses — likely a missing dependency, configuration "
                    "error, or runtime crash."
                ),
                "action": (
                    "Check the agent's logs for startup errors. Common causes: missing "
                    "environment variables, database connection failures, or incompatible "
                    "dependencies."
                ),
            },
            "boot_timeout": {
                "title": "Agent Never Started",
                "description": (
                    "The agent was deployed but never became reachable over HTTP within the "
                    "timeout window. It may have crashed on startup, entered an infinite "
                    "loop, or failed to bind to the expected port."
                ),
                "action": (
                    "Ensure the agent starts an HTTP server on the PORT environment variable "
                    "(default 8000). Check that the Dockerfile CMD actually launches the "
                    "server process."
                ),
            },
            "deployment_failed": {
                "title": "Deployment Failed",
                "description": (
                    "The agent could not be built or deployed to the sandbox environment. "
                    "This usually means the repository is missing a Dockerfile, has build "
                    "errors, or is not structured as a deployable service."
                ),
                "action": (
                    "Ensure the repository contains a Dockerfile that builds and runs "
                    "successfully. The agent must be a deployable HTTP service, not a "
                    "library or CLI tool. Static analysis still ran — review findings for "
                    "source-level issues."
                ),
            },
            "live_attack_timeout": {
                "title": "Scan Timed Out",
                "description": (
                    "The live security scan exceeded the 12-minute time limit. The agent "
                    "was responding but the security detectors could not complete within "
                    "the allowed window."
                ),
                "action": (
                    "This may indicate the agent is very slow to respond. Consider "
                    "optimizing agent response times."
                ),
            },
            "live_attack_unusable": {
                "title": "Security Tests Could Not Execute",
                "description": (
                    "The agent was reachable and responded to probes, but the security "
                    "detectors could not execute any meaningful tests. The agent may not "
                    "be responding with usable content."
                ),
                "action": (
                    "Verify the agent returns meaningful responses (not empty or error "
                    "pages) when given natural language input. Check that the "
                    "request/response format matches a standard chat or query API."
                ),
            },
        }
        explanation = explanations.get(failure_reason)
        if explanation:
            return {
                "reason": failure_reason,
                "title": explanation["title"],
                "description": explanation["description"],
                "action": explanation["action"],
            }
        return {
            "reason": failure_reason,
            "title": failure_reason.replace("_", " ").title(),
            "description": error or "The scan could not complete.",
            "action": "Review the scan events and full report for details.",
        }

    def _build_security_scan_config(self, *, source_review: dict[str, object]) -> ScanConfig:
        detectors, case_limits = self._select_hosted_security_profile(source_review)
        return ScanConfig(
            anthropic_api_key="",
            timeout_seconds=15.0,
            max_retries=1,
            budget=ScanBudget(
                max_agent_calls=30,
                max_llm_judge_calls=0,
                max_attacker_calls=0,
            ),
            detectors=detectors,
            evaluation_mode="heuristic",
            enable_adaptive_attacks=False,
            enable_converters=False,
            detector_case_limits=case_limits,
            test_case_runs_override=1,
        )

    async def _await_live_attack_readiness(
        self,
        *,
        agent_config: AgentConfig,
        timeout_seconds: float = 60.0,
        poll_seconds: float = 3.0,
    ) -> None:
        adapter = HTTPAdapter(agent_config, timeout=30.0, max_retries=1)
        deadline = time.monotonic() + timeout_seconds
        last_error = "Agent never became usable enough for the mandatory live attack scan."
        last_status_code: int | None = None
        last_body: str = ""
        reachable_before_timeout = False
        try:
            while time.monotonic() < deadline:
                response = await adapter.send("hello")
                if not response.error and response.status_code < 400 and response.text.strip():
                    return
                if response.status_code > 0:
                    reachable_before_timeout = True
                if response.error:
                    last_error = f"Agent returned error: {response.error}"
                    last_status_code = response.status_code or None
                    if response.status_code > 0:
                        last_body = response.error[:500]
                elif response.status_code >= 400:
                    last_error = f"Agent returned HTTP {response.status_code}: {response.text[:200]}"
                    last_status_code = response.status_code
                    last_body = response.text[:500]
                else:
                    last_error = "Agent returned an empty response"
                await asyncio.sleep(poll_seconds)
        finally:
            await adapter.close()
        raise ProbeError(
            last_error,
            status_code=last_status_code,
            target_url=agent_config.url,
            response_excerpt=last_body,
            reachable_before_timeout=reachable_before_timeout,
        )

    async def _await_live_surface_ready(
        self,
        *,
        base_url: str,
        runtime_profile: GeneratedRuntimeProfile | None = None,
        timeout_seconds: float = 60.0,
        poll_seconds: float = 3.0,
    ) -> None:
        probes = self._build_live_surface_probes(base_url=base_url, runtime_profile=runtime_profile)
        deadline = time.monotonic() + timeout_seconds
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            while time.monotonic() < deadline:
                for method, candidate in probes:
                    try:
                        response = await getattr(client, method.lower())(candidate)
                    except Exception:
                        continue
                    if response.status_code < 500:
                        return
                await asyncio.sleep(poll_seconds)
        raise ProbeError("Hosted deployment never exposed a usable HTTP surface.")

    def _select_hosted_security_profile(
        self,
        source_review: dict[str, object],
    ) -> tuple[list[str], dict[str, int]]:
        detectors = list(_HOSTED_SECURITY_CORE_LIMITS)
        case_limits = dict(_HOSTED_SECURITY_CORE_LIMITS)

        hints = [str(item).strip().lower() for item in source_review.get("attack_hints", [])]
        generated_profile = self._generated_profile_from_phase(source_review)
        probe_paths = [
            str(path).strip().lower()
            for path in (generated_profile.probe_paths if generated_profile is not None else [])
            if str(path).strip()
        ]

        extras: list[str] = []
        if any(hint.startswith("integration:") or hint.startswith("declared_domain:") for hint in hints):
            extras.append("xpia")
        if any(hint.startswith("prompt_surface:") or hint.startswith("code_signal:") for hint in hints):
            extras.append("goal_hijacking")
        if any(
            token in path
            for path in probe_paths
            for token in ("/invoke", "/query", "/search", "/predict")
        ):
            extras.append("input_validation")

        for detector_name in extras:
            if detector_name in case_limits:
                continue
            detectors.append(detector_name)
            case_limits[detector_name] = _HOSTED_SECURITY_EXTRA_LIMITS[detector_name]

        return detectors, case_limits

    @staticmethod
    def _resolve_security_target(
        base_url: str,
        runtime_profile: GeneratedRuntimeProfile | None,
    ) -> tuple[str, str]:
        normalized_base = base_url.rstrip("/")
        if runtime_profile is None:
            return normalized_base, "question"

        candidates = [
            path
            for path in runtime_profile.probe_paths
            if path.startswith("/")
            and path not in {"/", "/docs", "/openapi.json", "/health", "/healthz"}
        ]
        for token in _INTERACTIVE_ROUTE_TOKENS:
            chosen = next((path for path in candidates if token in path.lower()), "")
            if not chosen:
                continue
            request_field = "question"
            lowered = chosen.lower()
            if "/invoke" in lowered:
                request_field = "message"
            elif "/chat" in lowered:
                request_field = "message"
            elif "/query" in lowered or "/search" in lowered:
                request_field = "query"
            return f"{normalized_base}{chosen}", request_field
        return normalized_base, "question"

    async def _resolve_live_security_target(
        self,
        *,
        base_url: str,
        runtime_profile: GeneratedRuntimeProfile | None,
        fallback_target_url: str,
        fallback_request_field: str,
    ) -> tuple[str, str]:
        normalized_base = base_url.rstrip("/")
        openapi_urls: list[str] = [f"{normalized_base}/openapi.json"]
        pages_to_check = [normalized_base, f"{normalized_base}/docs", f"{normalized_base}/redoc"]
        if runtime_profile is not None:
            for path in runtime_profile.probe_paths:
                cleaned = str(path).strip()
                if not cleaned.startswith("/"):
                    continue
                lowered = cleaned.lower()
                if lowered.endswith("/docs") or lowered.endswith("/redoc") or lowered.endswith("/openapi.json"):
                    pages_to_check.append(f"{normalized_base}{cleaned}")

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for page_url in self._unique_preserving_order(pages_to_check):
                try:
                    response = await client.get(page_url)
                except Exception:
                    continue
                if response.status_code >= 400:
                    continue

                content_type = response.headers.get("content-type", "").lower()
                if "json" in content_type:
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = None
                    if isinstance(payload, dict):
                        discovered = self._choose_openapi_target(payload)
                        if discovered is not None:
                            path, request_field = discovered
                            return f"{normalized_base}{path}", request_field
                        for key in ("openapi_url", "swagger_url", "docs_url", "redoc_url"):
                            value = payload.get(key)
                            if isinstance(value, str) and value.startswith("/"):
                                openapi_urls.append(urljoin(f"{normalized_base}/", value))

                for discovered in self._extract_openapi_urls(response.text, page_url):
                    openapi_urls.append(discovered)

            for openapi_url in self._unique_preserving_order(openapi_urls):
                try:
                    response = await client.get(openapi_url)
                except Exception:
                    continue
                if response.status_code >= 400:
                    continue
                try:
                    payload = response.json()
                except ValueError:
                    continue
                if not isinstance(payload, dict):
                    continue
                discovered = self._choose_openapi_target(payload)
                if discovered is None:
                    continue
                path, request_field = discovered
                return f"{normalized_base}{path}", request_field

        return fallback_target_url, fallback_request_field

    @staticmethod
    def _extract_openapi_urls(text: str, page_url: str) -> list[str]:
        urls: list[str] = []
        for match in _DOCS_OPENAPI_URL_RE.finditer(text):
            path = match.group("path").strip()
            if not path:
                continue
            urls.append(urljoin(page_url, path))
        return urls

    @staticmethod
    def _choose_openapi_target(spec: dict[str, object]) -> tuple[str, str] | None:
        raw_paths = spec.get("paths")
        if not isinstance(raw_paths, dict):
            return None

        schemas = {}
        components = spec.get("components")
        if isinstance(components, dict):
            raw_schemas = components.get("schemas")
            if isinstance(raw_schemas, dict):
                schemas = raw_schemas

        def _resolve_request_field(operation: dict) -> str | None:
            """Extract the first string field name from the request body schema."""
            body = operation.get("requestBody")
            if not isinstance(body, dict):
                return None
            content = body.get("content")
            if not isinstance(content, dict):
                return None
            for media_type, media_obj in content.items():
                if not isinstance(media_obj, dict):
                    continue
                schema = media_obj.get("schema")
                if not isinstance(schema, dict):
                    continue
                ref = schema.get("$ref")
                if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
                    schema_name = ref.rsplit("/", 1)[-1]
                    schema = schemas.get(schema_name, schema)
                props = schema.get("properties")
                if isinstance(props, dict):
                    for field_name, field_spec in props.items():
                        if isinstance(field_spec, dict) and field_spec.get("type") in ("string", None):
                            return str(field_name)
            return None

        _DEFAULT_REQUEST_FIELDS: dict[str, str] = {
            "/invoke": "message",
            "/chat": "message",
            "/query": "query",
            "/search": "query",
            "/run": "message",
            "/predict": "message",
        }

        best: tuple[int, str, str] | None = None
        for path, operations in raw_paths.items():
            if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
                continue
            lowered = path.lower()
            if any(token in lowered for token in ("/auth", "/login", "/logout", "/register", "/token")):
                continue
            if any(token in lowered for token in ("/docs", "openapi", "/health", "/metrics", "/history")):
                continue
            if "/stream" in lowered:
                continue

            method_names = {
                method.lower()
                for method, value in operations.items()
                if isinstance(method, str) and isinstance(value, dict)
            }
            if "post" not in method_names and not method_names.intersection({"get", "put", "patch"}):
                continue

            score = 0
            if "/invoke" in lowered:
                score = 500
            elif "/chat" in lowered:
                score = 450
            elif "/query" in lowered or "/search" in lowered:
                score = 400
            elif "/run" in lowered or "/predict" in lowered:
                score = 350
            else:
                continue

            # Try to read the real field name from the OpenAPI schema
            request_field: str | None = None
            post_op = operations.get("post") if isinstance(operations.get("post"), dict) else None
            if post_op is not None:
                request_field = _resolve_request_field(post_op)

            # Fall back to heuristic defaults if schema doesn't have the field
            if not request_field:
                for token, default_field in _DEFAULT_REQUEST_FIELDS.items():
                    if token in lowered:
                        request_field = default_field
                        break
            if not request_field:
                request_field = "question"

            if "post" in method_names:
                score += 50
            score += min(len(path), 80)

            candidate = (score, path, request_field)
            if best is None or candidate[0] > best[0]:
                best = candidate

        if best is None:
            return None
        return best[1], best[2]

    @staticmethod
    def _security_request_defaults(target_url: str) -> dict[str, object]:
        path = urlparse(target_url).path.lower()
        defaults: dict[str, object] = {}
        if path.endswith("/search") or path.endswith("/query"):
            defaults["user_id"] = "agentgate-security-scan"
        return defaults

    @staticmethod
    def _resolve_security_response_field(target_url: str) -> str:
        path = urlparse(target_url).path.lower()
        if path.endswith("/search") or path.endswith("/query"):
            return "results"
        return "answer"

    @staticmethod
    def _generated_profile_from_phase(phase_result: dict[str, object]) -> GeneratedRuntimeProfile | None:
        result = phase_result.get("result")
        if isinstance(result, TrustScanResult):
            return result.generated_runtime_profile
        return None

    @staticmethod
    def _unique_preserving_order(items: list[str]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _build_live_surface_probes(
        self,
        *,
        base_url: str,
        runtime_profile: GeneratedRuntimeProfile | None,
    ) -> list[tuple[str, str]]:
        normalized_base = base_url.rstrip("/")
        generic_paths = ["", "/docs", "/health", "/healthz"]
        paths = list(generic_paths)
        integration_paths: set[str] = set()
        if runtime_profile is not None:
            for path in runtime_profile.probe_paths:
                cleaned = str(path).strip()
                if cleaned.startswith("/"):
                    paths.append(cleaned)
            for routes in runtime_profile.integration_routes.values():
                for route in routes:
                    cleaned = str(route).strip()
                    if cleaned.startswith("/"):
                        paths.append(cleaned)
                        integration_paths.add(cleaned)

        probes: list[tuple[str, str]] = []
        for path in self._unique_preserving_order(paths):
            url = normalized_base if not path else f"{normalized_base}{path}"
            if path in integration_paths or self._looks_like_webhook_path(path):
                probes.extend(
                    [
                        ("HEAD", url),
                        ("OPTIONS", url),
                        ("GET", url),
                    ]
                )
            else:
                probes.append(("GET", url))
        return probes

    @staticmethod
    def _looks_like_webhook_path(path: str) -> bool:
        lowered = path.lower()
        return any(token in lowered for token in ("/webhook", "/webhooks", "/events"))

    @staticmethod
    def _has_interactive_probe_path(runtime_profile: GeneratedRuntimeProfile | None) -> bool:
        if runtime_profile is None:
            return False
        for path in runtime_profile.probe_paths:
            lowered = str(path).strip().lower()
            if any(token in lowered for token in _INTERACTIVE_ROUTE_TOKENS):
                return True
        return False

    def _should_skip_live_attack_scan(
        self,
        *,
        runtime_profile: GeneratedRuntimeProfile | None,
        base_url: str,
        target_url: str,
    ) -> bool:
        if runtime_profile is None:
            return False
        if not runtime_profile.integration_routes:
            return False
        if self._has_interactive_probe_path(runtime_profile):
            return False
        return target_url.rstrip("/") == base_url.rstrip("/")

    def _bridge_security_findings(self, result: SecurityScanResult) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        for detector in result.scorecard.detectors:
            for failed_test in detector.failed_tests:
                findings.append(self._security_failed_test_to_finding(detector.name, failed_test))
        for detector_name, error in result.errors.items():
            signal = TrustSignal(
                check_id=f"security_{detector_name}",
                signal_type="security_detector_error",
                title=f"Security detector {detector_name} failed",
                summary=f"Security detector '{detector_name}' raised an error: {error}",
                raw_evidence=str(error),
                detection_method="inconclusive",
                source_location="runtime://live_attack",
                base_severity=TrustSeverity.MEDIUM,
                category=TrustCategory.RUNTIME_INTEGRITY,
                recommendation="Review the detector error and rerun the hosted scan.",
            )
            findings.append(
                normalize_finding(
                    signal,
                    file_map=_SECURITY_CONTEXT_FILE_MAP,
                    reachability_map=_SECURITY_CONTEXT_REACHABILITY,
                    evidence_strength="inconclusive",
                    runtime_attribution="request_time",
                    attribution_confidence="medium",
                )
            )
        return findings

    def _security_failed_test_to_finding(self, detector_name: str, failed_test: FailedTest) -> TrustFinding:
        evaluation_method = getattr(failed_test.evaluation_method, "value", failed_test.evaluation_method)
        evidence_strength = "llm_inferred" if str(evaluation_method) == "llm_judge" else "heuristic"
        signal = TrustSignal(
            check_id=f"security_{detector_name}",
            signal_type="security_failed_test",
            title=f"Live attack detector {detector_name} found a failing test",
            summary=failed_test.evidence or failed_test.test_name or detector_name,
            raw_evidence=failed_test.output_response or failed_test.evidence or failed_test.input_payload,
            detection_method=evidence_strength,
            source_location="runtime://live_attack",
            base_severity=_SECURITY_SEVERITY_MAP.get(detector_name, TrustSeverity.MEDIUM),
            category=_SECURITY_CATEGORY_MAP.get(detector_name, TrustCategory.RUNTIME_INTEGRITY),
            recommendation=(
                f"Review the failing {detector_name} live attack case '{failed_test.test_name}' "
                "and harden the agent against the demonstrated behavior."
            ),
        )
        finding = normalize_finding(
            signal,
            file_map=_SECURITY_CONTEXT_FILE_MAP,
            reachability_map=_SECURITY_CONTEXT_REACHABILITY,
            evidence_strength=evidence_strength,
            runtime_attribution="request_time",
            attribution_confidence="high",
        )
        finding.confidence = failed_test.confidence
        finding.expected = failed_test.input_payload
        finding.observed = failed_test.output_response or failed_test.evidence
        return finding

    @staticmethod
    def _phase_checks_run(
        source_result: TrustScanResult | None,
        live_attack: dict[str, object] | None,
        runtime_result: TrustScanResult | None,
    ) -> int:
        total = 0
        if source_result is not None:
            total += source_result.scorecard.checks_run
        if live_attack and isinstance(live_attack.get("score"), dict):
            total += int(live_attack["score"].get("checks_run") or 0)
        if runtime_result is not None:
            total += runtime_result.scorecard.checks_run
        return total

    @staticmethod
    def _phase_checks_passed(
        source_result: TrustScanResult | None,
        live_attack: dict[str, object] | None,
        runtime_result: TrustScanResult | None,
    ) -> int:
        total = 0
        if source_result is not None:
            total += source_result.scorecard.checks_passed
        if live_attack and isinstance(live_attack.get("score"), dict):
            total += int(live_attack["score"].get("checks_passed") or 0)
        if runtime_result is not None:
            total += runtime_result.scorecard.checks_passed
        return total

    @staticmethod
    def _phase_checks_failed(
        source_result: TrustScanResult | None,
        live_attack: dict[str, object] | None,
        runtime_result: TrustScanResult | None,
    ) -> int:
        total = 0
        if source_result is not None:
            total += source_result.scorecard.checks_failed
        if live_attack and isinstance(live_attack.get("score"), dict):
            total += int(live_attack["score"].get("checks_failed") or 0)
        if runtime_result is not None:
            total += runtime_result.scorecard.checks_failed
        return total

    @staticmethod
    def _deployment_report(deployment: RailwayExecutionResult | None) -> dict | None:
        if deployment is None:
            return None
        return {
            "platform": "railway",
            "project_id": deployment.project_id,
            "project_name": deployment.project_name,
            "environment_name": deployment.environment_name,
            "service_name": deployment.service_name,
            "public_url": deployment.public_url,
            "dependency_services": list(deployment.dependency_services),
            "issued_integrations": list(deployment.issued_integrations),
            "reused_pool": deployment.reused_pool,
            "notes": list(deployment.notes),
        }

    async def _emit_event(
        self,
        event_callback: Callable[[dict[str, object]], Awaitable[None] | None] | None,
        *,
        status: str,
        phase: str,
        detail: str,
        event_type: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        if event_callback is None:
            return
        event: dict[str, object] = {
            "status": status,
            "phase": phase,
            "detail": detail,
            "event_type": event_type,
        }
        if payload:
            event["payload"] = payload
        result = event_callback(event)
        if hasattr(result, "__await__"):
            await result

    def cleanup(self, scan_id: str) -> None:
        scan_dir = self.work_dir / scan_id
        if scan_dir.exists():
            shutil.rmtree(scan_dir, ignore_errors=True)
