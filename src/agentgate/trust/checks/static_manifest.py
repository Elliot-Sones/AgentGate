from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity


class StaticManifestCheck(BaseTrustCheck):
    check_id = "static_manifest"
    description = "Validates the trust manifest has required fields and correct structure."

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        ctx.load_manifest()

        if ctx.manifest is None:
            missing_manifest = (
                ctx.manifest_path is None
                or not ctx.manifest_path.exists()
                or "not found" in (ctx.manifest_error or "").lower()
                or "no manifest path provided" in (ctx.manifest_error or "").lower()
            )
            if missing_manifest:
                return [
                    self.finding(
                        title="Trust manifest not provided",
                        category=TrustCategory.DECLARATION,
                        severity=TrustSeverity.INFO,
                        passed=True,
                        summary=(
                            "No trust manifest was supplied. AgentGate will rely on the "
                            "generated runtime profile and source analysis for this scan."
                        ),
                        recommendation=(
                            "Provide a trust manifest to improve declared tools, domains, "
                            "permissions, and buyer-facing descriptions."
                        ),
                        location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                    )
                ]
            findings.append(
                self.finding(
                    title="Trust manifest missing or unreadable",
                    category=TrustCategory.DECLARATION,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary=ctx.manifest_error or "Trust manifest was not found.",
                    recommendation="Provide a valid trust manifest with declared domains, tools, and permissions.",
                    location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                )
            )
            return findings

        required = ["submission_id", "agent_name", "entrypoint"]
        for key in required:
            if not ctx.manifest.get(key):
                findings.append(
                    self.finding(
                        title=f"Missing required manifest field: {key}",
                        category=TrustCategory.DECLARATION,
                        severity=TrustSeverity.MEDIUM,
                        passed=False,
                        summary=f"Manifest is missing required key '{key}'.",
                        recommendation="Add all required top-level manifest keys.",
                        location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                    )
                )

        domains = ctx.manifest.get("declared_external_domains", [])
        if not isinstance(domains, list):
            findings.append(
                self.finding(
                    title="Manifest declared_external_domains type mismatch",
                    category=TrustCategory.DECLARATION,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="declared_external_domains must be a list of domains.",
                    recommendation="Use list format for declared_external_domains.",
                    location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                )
            )

        for error in ctx.config.dependency_validation_errors:
            findings.append(
                self.finding(
                    title="Manifest dependency configuration is invalid",
                    category=TrustCategory.DECLARATION,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary=error,
                    recommendation=(
                        "Use only approved dependency services and ensure "
                        "'dependencies' and 'runtime_env' use object/list syntax."
                    ),
                    location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                )
            )

        if not findings:
            findings.append(
                self.finding(
                    title="Manifest parsed successfully",
                    category=TrustCategory.DECLARATION,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="Trust manifest is present and satisfies required fields.",
                    location_path=str(ctx.manifest_path) if ctx.manifest_path else "",
                )
            )

        return findings
