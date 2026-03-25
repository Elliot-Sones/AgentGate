from __future__ import annotations

import logging
import time

from agentgate.progress import ScanProgressDisplay
from agentgate.trust.checks import BaseTrustCheck, default_trust_checks
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.integrations.agentdojo_runner import AgentDojoRunner
from agentgate.trust.metadata import (
    build_runtime_summary,
    build_submission_profile as build_listing_submission_profile,
)
from agentgate.trust.models import (
    AgentOverview,
    CheckRecord,
    ConfidenceSummary,
    CoverageSummary,
    DeploymentSummary,
    DependencyRecord,
    EvidenceRef,
    GeneratedRuntimeProfile,
    RuntimeInspect,
    RuntimeProfile,
    SubmissionSupport,
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
)
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES
from agentgate.trust.runtime.railway_executor import RailwayExecutionError, RailwayExecutor
from agentgate.trust.runtime.submission_profile import (
    build_submission_profile as build_generated_runtime_profile,
)

logger = logging.getLogger(__name__)


class TrustScanner:
    """Phase 2 scanner for agent trust and malware-style analysis."""

    def __init__(
        self,
        config: TrustScanConfig,
        checks: list[BaseTrustCheck] | None = None,
        policy: TrustPolicy | None = None,
        progress: ScanProgressDisplay | None = None,
    ) -> None:
        self.config = config
        self.checks = checks or default_trust_checks()
        self.policy = policy or TrustPolicy(version=config.policy_version)
        self._progress = progress

    async def run(self) -> TrustScanResult:
        start = time.monotonic()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.config.load_allowlist()

        ctx = TrustScanContext(config=self.config)
        findings: list[TrustFinding] = []
        check_records: list[CheckRecord] = []
        checks_failed = 0
        deployment_error = ""
        should_cleanup = False

        try:
            self._prepare_context(ctx)
            unsupported_finding = self._unsupported_submission_finding(ctx)
            if unsupported_finding is not None:
                findings.append(unsupported_finding)
                return self._build_result(
                    ctx=ctx,
                    start=start,
                    findings=findings,
                    check_records=check_records,
                    checks_failed=0,
                    deployment_error="",
                )

            if not self.config.hosted_url and ctx.source_dir is not None:
                try:
                    deployment = RailwayExecutor(
                        workspace_id=self.config.railway_workspace_id,
                    ).deploy_submission(
                        source_dir=ctx.source_dir,
                        dependencies=ctx.config.dependencies,
                        runtime_env=self._deployment_runtime_env(ctx),
                        issued_integrations=(
                            ctx.generated_runtime_profile.issued_integrations
                            if ctx.generated_runtime_profile is not None
                            else []
                        ),
                    )
                except RailwayExecutionError as exc:
                    deployment_error = str(exc)
                    findings.append(
                        TrustFinding(
                            check_id="deployment",
                            title="Submission deployment failed",
                            category=TrustCategory.RUNTIME_INTEGRITY,
                            severity=TrustSeverity.CRITICAL,
                            passed=False,
                            summary=deployment_error,
                            recommendation=(
                                "Fix the Dockerfile, runtime configuration, or Railway deployment "
                                "requirements before rerunning the trust scan."
                            ),
                        )
                    )
                    return self._build_result(
                        ctx=ctx,
                        start=start,
                        findings=findings,
                        check_records=check_records,
                        checks_failed=0,
                        deployment_error=deployment_error,
                    )

                should_cleanup = True
                ctx.deployment_result = deployment
                self._apply_deployment_result(ctx, deployment)

            for check in self.checks:
                if self._progress is not None:
                    self._progress.mark_running(check.check_id)
                status = "completed"
                try:
                    check_findings = await check.run(ctx)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.exception("Trust check failed unexpectedly: %s", check.check_id)
                    status = "error"
                    if self._progress is not None:
                        self._progress.mark_error(check.check_id, str(exc))
                    check_findings = [
                        TrustFinding(
                            check_id=check.check_id,
                            title="Trust check execution error",
                            category=TrustCategory.HIDDEN_BEHAVIOR,
                            severity=TrustSeverity.HIGH,
                            passed=False,
                            summary=f"Check '{check.check_id}' raised an exception: {exc}",
                            recommendation="Inspect check implementation and rerun.",
                        )
                    ]
                else:
                    if self._progress is not None:
                        self._progress.mark_completed(check.check_id)

                failed = any(not f.passed for f in check_findings)
                check_records.append(CheckRecord(
                    check_id=check.check_id,
                    description=getattr(check, "description", ""),
                    status=status,
                    findings_count=len(check_findings),
                    failed=failed,
                ))

                findings.extend(check_findings)
                if failed:
                    checks_failed += 1

            # Optional AgentDojo bridge
            dojo_findings = AgentDojoRunner().run(self.config.agentdojo_suite)
            findings.extend(dojo_findings)
            if dojo_findings and any(not f.passed for f in dojo_findings):
                checks_failed += 1

            return self._build_result(
                ctx=ctx,
                start=start,
                findings=findings,
                check_records=check_records,
                checks_failed=checks_failed,
                deployment_error="",
            )
        finally:
            if (
                should_cleanup
                and ctx.deployment_result is not None
                and not self.config.keep_environment_on_failure
            ):
                try:
                    RailwayExecutor(
                        workspace_id=self.config.railway_workspace_id,
                    ).cleanup(ctx.deployment_result)
                except Exception:  # pragma: no cover - cleanup best effort
                    logger.exception("Failed to cleanup temporary Railway deployment.")

    def _profiles_used(self) -> list[str]:
        if self.config.profile == "both":
            return ["review", "prodlike"]
        return [self.config.profile]

    def _prepare_context(self, ctx: TrustScanContext) -> None:
        ctx.load_manifest()
        if ctx.source_dir is not None:
            ctx.infer_runtime_config_from_source()
            assessment, runtime_profile = build_generated_runtime_profile(
                source_dir=ctx.source_dir,
                manifest=ctx.manifest,
                dependencies=ctx.config.dependencies,
                runtime_env=ctx.config.runtime_env,
                enforce_production_contract=(
                    self.config.strict_production_contract or not self.config.hosted_url
                ),
            )
            ctx.submission_support_assessment = assessment
            ctx.generated_runtime_profile = runtime_profile
            self._apply_generated_profile(ctx)
            return

        if self.config.strict_production_contract:
            ctx.submission_support_assessment = SubmissionSupport(
                supported=False,
                status="unsupported_build",
                reason="source_missing",
                detail="Strict production mode requires source code and a Dockerfile.",
                notes=[],
            )
        else:
            ctx.submission_support_assessment = SubmissionSupport(
                supported=True,
                status="best_effort_hosted",
                reason="",
                detail="Running hosted analysis without source preflight.",
                notes=["No source submission was provided, so build/deploy validation was skipped."],
            )

    def _apply_generated_profile(self, ctx: TrustScanContext) -> None:
        profile = ctx.generated_runtime_profile
        if profile is None:
            return
        self.config.egress_allowlist.update(profile.allow_domains)
        for key, value in profile.issued_runtime_env.items():
            self.config.runtime_env.setdefault(key, value)

    def _deployment_runtime_env(self, ctx: TrustScanContext) -> dict[str, str]:
        runtime_env = dict(self.config.runtime_env)
        profile = ctx.generated_runtime_profile
        if profile is not None:
            runtime_env.update(profile.issued_runtime_env)
        return runtime_env

    def _apply_deployment_result(self, ctx: TrustScanContext, deployment) -> None:
        self.config.hosted_url = deployment.public_url
        self.config.railway_workspace_dir = deployment.workspace_dir
        self.config.railway_service = deployment.service_name
        self.config.railway_environment = deployment.environment_name
        ctx.hosted_runtime_context.update(
            {
                "execution_platform": "railway",
                "project_id": deployment.project_id,
                "project_name": deployment.project_name,
                "environment_name": deployment.environment_name,
                "service_name": deployment.service_name,
                "public_url": deployment.public_url,
                "dependency_services": list(deployment.dependency_services),
                "issued_integrations": list(deployment.issued_integrations),
            }
        )

    def _unsupported_submission_finding(self, ctx: TrustScanContext) -> TrustFinding | None:
        assessment = ctx.submission_support_assessment
        if assessment is None or assessment.supported:
            return None
        return TrustFinding(
            check_id="submission_preflight",
            title="Submission is outside the supported production contract",
            category=TrustCategory.RUNTIME_INTEGRITY,
            severity=TrustSeverity.CRITICAL,
            passed=False,
            summary=assessment.detail or assessment.reason or assessment.status,
            recommendation=(
                "Provide a Dockerfile-based HTTP agent submission that only requires approved "
                "dependencies and platform-issued integrations."
            ),
            observed=assessment.status,
        )

    def _build_result(
        self,
        *,
        ctx: TrustScanContext,
        start: float,
        findings: list[TrustFinding],
        check_records: list[CheckRecord],
        checks_failed: int,
        deployment_error: str,
    ) -> TrustScanResult:
        checks_run = len(check_records) + (1 if self.config.agentdojo_suite else 0)
        checks_passed = max(checks_run - checks_failed, 0)
        verdict = self.policy.verdict_for_findings(findings)
        counts = self.policy.summary_counts(findings)
        duration = time.monotonic() - start
        scorecard = TrustScorecard(
            checks_run=checks_run,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            findings_total=len(findings),
            findings_by_severity=counts,
            verdict=verdict,
            duration_seconds=round(duration, 3),
            policy_version=self.policy.version,
        )

        artifacts_manifest = [
            EvidenceRef.from_path("artifact", p, "Trust scan artifact") for p in ctx.artifacts
        ]
        metadata = {
            "image_ref": self.config.image_ref,
            "source_dir": str(self.config.source_dir) if self.config.source_dir else "",
            "manifest_path": str(self.config.manifest_path) if self.config.manifest_path else "",
            "profiles": self._profiles_used(),
            "egress_allowlist_size": len(self.config.egress_allowlist),
            "runtime_seconds": self.config.runtime_seconds,
            "canary_profile": self.config.canary_profile,
            "report_profile": self.config.report_profile,
            "submission_profile": build_listing_submission_profile(ctx),
        }
        metadata.update(build_runtime_summary(ctx))
        if deployment_error:
            metadata["deployment_error"] = deployment_error

        coverage = self._build_coverage_summary(ctx)
        confidence = self._build_confidence_summary(ctx, coverage, deployment_error)

        return TrustScanResult(
            scorecard=scorecard,
            findings=findings,
            metadata=metadata,
            artifacts_manifest=artifacts_manifest,
            agent_overview=self._build_agent_overview(ctx),
            checks=check_records,
            runtime_profiles=self._build_runtime_profiles(ctx),
            dependencies=self._build_dependencies(ctx),
            submission_support=self._build_submission_support(ctx),
            generated_runtime_profile=self._build_generated_runtime_profile(ctx),
            deployment_summary=self._build_deployment_summary(ctx, deployment_error),
            coverage=coverage,
            confidence=confidence,
        )

    @staticmethod
    def _build_agent_overview(ctx: TrustScanContext) -> AgentOverview | None:
        m = ctx.manifest
        if not isinstance(m, dict):
            return None

        def _str_list(val: object) -> list[str]:
            if isinstance(val, list):
                return [str(v) for v in val]
            return []

        return AgentOverview(
            name=str(m.get("agent_name", "")),
            description=str(m.get("description", "")),
            version=str(m.get("version", "")),
            category=str(m.get("solution_category", "")),
            business_use_case=str(m.get("business_use_case", "")),
            customer_data_access=_str_list(m.get("customer_data_access")),
            declared_tools=_str_list(m.get("declared_tools")),
            declared_external_domains=_str_list(m.get("declared_external_domains")),
            business_claims=_str_list(m.get("business_claims")),
            integrations=_str_list(m.get("integrations")),
            permissions=_str_list(m.get("permissions")),
        )

    @staticmethod
    def _build_runtime_profiles(ctx: TrustScanContext) -> list[RuntimeProfile]:
        profiles: list[RuntimeProfile] = []
        for name, trace in ctx.runtime_traces.items():
            inspect_data = None
            if trace.inspect_user or trace.inspect_exit_code is not None:
                inspect_data = RuntimeInspect(
                    user=trace.inspect_user,
                    network_mode=trace.inspect_network_mode,
                    exit_code=trace.inspect_exit_code,
                    ports=trace.inspect_ports,
                    env_keys=trace.inspect_env_keys,
                    capabilities=trace.inspect_capabilities,
                    oom_killed=trace.inspect_oom_killed,
                )
            profiles.append(RuntimeProfile(
                name=name,
                network_mode=trace.inspect_network_mode,
                status=trace.status,
                network_destinations=trace.network_destinations,
                internal_destinations=trace.internal_network_destinations,
                tool_calls=trace.tool_calls,
                process_events=trace.process_events,
                canary_hits=trace.canary_hits,
                probe_responses=trace.probe_responses,
                inspect=inspect_data,
            ))
        return profiles

    @staticmethod
    def _build_dependencies(ctx: TrustScanContext) -> list[DependencyRecord]:
        manifest_deps: set[str] = set()
        if isinstance(ctx.manifest, dict):
            for d in ctx.manifest.get("dependencies", []):
                if isinstance(d, dict):
                    svc = d.get("service", "")
                    if svc:
                        manifest_deps.add(str(svc).lower())

        notes = ctx.config.dependency_inference_notes
        records: list[DependencyRecord] = []
        for spec in ctx.config.dependencies:
            svc_def = ALLOWED_SERVICES.get(spec.service)
            records.append(DependencyRecord(
                service=spec.service,
                source="declared" if spec.service in manifest_deps else "inferred",
                image=svc_def.image if svc_def else "",
                port=svc_def.ports[0] if svc_def and svc_def.ports else 0,
                healthy=True,
                inference_note=next(
                    (n for n in notes if spec.service in n), ""
                ),
            ))
        return records

    @staticmethod
    def _build_submission_support(ctx: TrustScanContext) -> SubmissionSupport | None:
        assessment = ctx.submission_support_assessment
        if assessment is None:
            return None
        if isinstance(assessment, SubmissionSupport):
            return assessment
        return SubmissionSupport(
            supported=assessment.supported,
            status=assessment.status,
            reason=assessment.reason,
            detail=assessment.detail,
            notes=list(assessment.notes),
        )

    @staticmethod
    def _build_generated_runtime_profile(ctx: TrustScanContext) -> GeneratedRuntimeProfile | None:
        profile = ctx.generated_runtime_profile
        if profile is None:
            return None
        return GeneratedRuntimeProfile(
            build_strategy=profile.build_strategy,
            dockerfile_path=profile.dockerfile_path,
            entrypoint=profile.entrypoint,
            http_supported=profile.http_supported,
            port_candidates=list(profile.port_candidates),
            probe_paths=list(profile.probe_paths),
            dependencies=list(profile.dependencies),
            runtime_env_keys=list(profile.runtime_env_keys),
            integrations=list(profile.integrations),
            unsupported_integrations=list(profile.unsupported_integrations),
            issued_integrations=list(profile.issued_integrations),
            allow_domains=list(profile.allow_domains),
            notes=list(profile.notes),
        )

    @staticmethod
    def _build_deployment_summary(
        ctx: TrustScanContext,
        deployment_error: str = "",
    ) -> DeploymentSummary | None:
        result = ctx.deployment_result
        if result is None and not deployment_error:
            return None
        if result is None:
            return DeploymentSummary(
                platform="railway",
                build_status="failed",
                deployment_status="failed",
                notes=[deployment_error] if deployment_error else [],
            )
        status = "ready" if result.public_url else "failed"
        notes = []
        if deployment_error:
            notes.append(deployment_error)
        return DeploymentSummary(
            platform="railway",
            build_status="ready" if result.public_url else "failed",
            deployment_status=status,
            project_id=result.project_id,
            project_name=result.project_name,
            environment_name=result.environment_name,
            service_name=result.service_name,
            public_url=result.public_url,
            dependency_services=list(result.dependency_services),
            issued_integrations=list(result.issued_integrations),
            notes=notes,
        )

    @staticmethod
    def _build_coverage_summary(ctx: TrustScanContext) -> CoverageSummary:
        exercised: set[str] = set()
        skipped: set[str] = set()
        notes: list[str] = []

        expected_paths: set[str] = set()
        if ctx.generated_runtime_profile is not None:
            expected_paths.update(ctx.generated_runtime_profile.probe_paths)
        if not expected_paths:
            expected_paths.update({"/", "/docs", "/openapi.json"})

        for trace in ctx.runtime_traces.values():
            for response in trace.probe_responses:
                path = str(response.get("path") or "").strip()
                if not path:
                    continue
                if response.get("status_code", 0):
                    exercised.add(path)
                else:
                    skipped.add(path)

        skipped.update(path for path in expected_paths if path not in exercised)

        if exercised and expected_paths and exercised >= expected_paths:
            level = "full"
        elif exercised:
            level = "partial"
        else:
            level = "none"

        if ctx.manifest is None:
            notes.append("No user trust manifest was provided; runtime profile was source-generated.")
        if ctx.source_dir is None:
            notes.append("No source submission was provided, so build/deploy validation was skipped.")
        if not ctx.runtime_traces:
            notes.append("No hosted runtime trace was captured.")

        return CoverageSummary(
            level=level,
            exercised_surfaces=sorted(exercised),
            skipped_surfaces=sorted(skipped),
            notes=notes,
        )

    @staticmethod
    def _build_confidence_summary(
        ctx: TrustScanContext,
        coverage: CoverageSummary,
        deployment_error: str = "",
    ) -> ConfidenceSummary:
        score = 20
        drivers: list[str] = []

        if ctx.source_dir is not None:
            score += 20
            drivers.append("Source submission was available for preflight analysis.")
        else:
            drivers.append("No source submission was available.")

        if ctx.manifest is not None:
            score += 10
            drivers.append("A trust manifest contributed declared intent and metadata.")
        else:
            drivers.append("No user trust manifest was provided.")

        if ctx.generated_runtime_profile is not None and ctx.generated_runtime_profile.http_supported:
            score += 15
            drivers.append("Generated runtime profile identified an HTTP-serving agent shape.")

        if ctx.deployment_result is not None and ctx.deployment_result.public_url:
            score += 15
            drivers.append("The submitted agent was deployed into a temporary Railway environment.")
        elif ctx.config.hosted_url:
            score += 10
            drivers.append("A hosted URL was available for runtime evaluation.")
        else:
            drivers.append("No hosted URL was available for runtime evaluation.")

        if coverage.level == "full":
            score += 20
            drivers.append("Hosted probe coverage exercised the expected runtime surfaces.")
        elif coverage.level == "partial":
            score += 10
            drivers.append("Hosted probe coverage exercised part of the expected runtime surface.")
        else:
            drivers.append("Hosted probe coverage was minimal or unavailable.")

        if ctx.hosted_runtime_context:
            score += 5
            drivers.append("Runtime context included deployment evidence from Railway.")
        if deployment_error:
            score -= 20
            drivers.append("Deployment failed before full runtime evaluation could complete.")

        score = max(min(score, 100), 0)
        if score >= 80:
            evidence_quality = "strong"
        elif score >= 60:
            evidence_quality = "moderate"
        else:
            evidence_quality = "weak"

        return ConfidenceSummary(
            score=score,
            evidence_quality=evidence_quality,
            inconclusive=(coverage.level == "none" or score < 60),
            drivers=drivers,
        )
