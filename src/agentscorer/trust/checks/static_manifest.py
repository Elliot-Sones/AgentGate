from __future__ import annotations

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


class StaticManifestCheck(BaseTrustCheck):
    check_id = "static_manifest"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        ctx.load_manifest()

        if ctx.manifest is None:
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
