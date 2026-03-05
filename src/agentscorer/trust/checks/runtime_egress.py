from __future__ import annotations

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


class RuntimeEgressCheck(BaseTrustCheck):
    check_id = "runtime_egress"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        if not ctx.runtime_traces:
            return [
                self.finding(
                    title="No runtime traces available for egress analysis",
                    category=TrustCategory.EGRESS,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Runtime egress check requires runtime sandbox traces.",
                    recommendation="Enable runtime checks and ensure image runs in the sandbox.",
                )
            ]

        declared = set()
        if ctx.manifest and isinstance(ctx.manifest.get("declared_external_domains"), list):
            declared = {str(v).lower() for v in ctx.manifest["declared_external_domains"]}
        allowlist = {d.lower() for d in ctx.config.egress_allowlist}

        all_allowed = declared | allowlist
        violations: list[tuple[str, str]] = []

        for profile, trace in ctx.runtime_traces.items():
            for dest in trace.network_destinations:
                if _is_allowed(dest, all_allowed):
                    continue
                if dest in {"localhost", "127.0.0.1", "0.0.0.0", "::", "::1"}:
                    continue
                violations.append((profile, dest))

        if violations:
            for profile, dest in violations:
                findings.append(
                    self.finding(
                        title="Undeclared outbound egress detected",
                        category=TrustCategory.EGRESS,
                        severity=TrustSeverity.CRITICAL,
                        passed=False,
                        summary=f"Profile '{profile}' connected to '{dest}' outside declared/allowlisted domains.",
                        recommendation="Block submission and require explicit domain declaration and justification.",
                        observed=dest,
                        expected=", ".join(sorted(all_allowed)) or "No external destinations",
                    )
                )
            return findings

        findings.append(
            self.finding(
                title="Runtime egress matched declarations",
                category=TrustCategory.EGRESS,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="Observed runtime destinations were within declared/allowlisted domains.",
            )
        )
        return findings


def _is_allowed(dest: str, allowed: set[str]) -> bool:
    if not allowed:
        return False
    for candidate in allowed:
        c = candidate.strip().lower()
        if not c:
            continue
        if dest == c:
            return True
        if dest.endswith(f".{c}"):
            return True
    return False
