from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


class StaticProvenanceCheck(BaseTrustCheck):
    check_id = "static_provenance"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        if ctx.manifest is None and ctx.manifest_path is not None:
            ctx.load_manifest()

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

        identity_args, identity_error = _cosign_verification_identity_args(ctx)
        if identity_error:
            findings.append(
                self.finding(
                    title="Missing pinned cosign identity constraints",
                    category=TrustCategory.PROVENANCE,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary=identity_error,
                    recommendation=(
                        "Declare trusted signer identity in manifest provenance "
                        "(certificate_identity + certificate_oidc_issuer) or provide cosign_key."
                    ),
                )
            )
            return findings

        cmd = ["cosign", "verify", *identity_args, image_ref]
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
                        summary="cosign verify returned success with pinned identity constraints.",
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


def _cosign_verification_identity_args(ctx: TrustScanContext) -> tuple[list[str], str]:
    manifest = ctx.manifest if isinstance(ctx.manifest, dict) else {}
    provenance = manifest.get("provenance", {})
    if not isinstance(provenance, dict):
        return [], "Manifest provenance section is missing or invalid."

    key_ref = str(provenance.get("cosign_key", "")).strip()
    if key_ref:
        key_path = Path(key_ref)
        if not key_path.is_absolute() and ctx.source_dir is not None:
            key_path = (ctx.source_dir / key_path).resolve()
        if not key_path.exists():
            return [], f"Configured cosign key does not exist: {key_path}"
        return ["--key", str(key_path)], ""

    identity = str(provenance.get("certificate_identity", "")).strip()
    issuer = str(provenance.get("certificate_oidc_issuer", "")).strip()
    if not identity or not issuer:
        return (
            [],
            (
                "Manifest provenance must include certificate_identity and "
                "certificate_oidc_issuer, or provide cosign_key."
            ),
        )
    return [
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
    ], ""
