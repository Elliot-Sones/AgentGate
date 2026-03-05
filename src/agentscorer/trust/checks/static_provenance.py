from __future__ import annotations

import shutil
import subprocess

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


class StaticProvenanceCheck(BaseTrustCheck):
    check_id = "static_provenance"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        image_ref = ctx.config.image_ref
        if "@sha256:" not in image_ref:
            findings.append(
                self.finding(
                    title="Image reference missing immutable digest",
                    category=TrustCategory.PROVENANCE,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=f"Image '{image_ref}' is not pinned by digest.",
                    recommendation="Submit immutable image references using @sha256 digest.",
                    observed=image_ref,
                )
            )

        cosign = shutil.which("cosign")
        if cosign is None:
            findings.append(
                self.finding(
                    title="Cosign not available — signature verification skipped",
                    category=TrustCategory.PROVENANCE,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="cosign binary not found; image signature could not be verified.",
                    recommendation="Install cosign on review runners for provenance verification.",
                )
            )
            return findings

        cmd = ["cosign", "verify", image_ref]
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = "\n".join([completed.stdout or "", completed.stderr or ""]).strip()
            artifact = ctx.artifact_dir / "cosign_verify.log"
            artifact.write_text(output)
            ctx.add_artifact(artifact)

            if completed.returncode != 0:
                findings.append(
                    self.finding(
                        title="Image signature verification failed",
                        category=TrustCategory.PROVENANCE,
                        severity=TrustSeverity.HIGH,
                        passed=False,
                        summary="cosign verify failed for submitted image.",
                        recommendation="Sign image artifact and provide verifiable provenance before submission.",
                        observed=output[:400],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title="Image signature verification passed",
                        category=TrustCategory.PROVENANCE,
                        severity=TrustSeverity.INFO,
                        passed=True,
                        summary="cosign verify returned success.",
                    )
                )
        except Exception as exc:
            findings.append(
                self.finding(
                    title="Cosign verification error",
                    category=TrustCategory.PROVENANCE,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=f"Unable to complete cosign verify: {exc}",
                    recommendation="Re-run with working cosign setup and network access.",
                )
            )

        return findings
