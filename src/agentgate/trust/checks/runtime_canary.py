from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.runtime.canary_detection import CanaryMatch, detect_canary_matches
from agentgate.trust.runtime.canary_bank import CanaryBank


class RuntimeCanaryCheck(BaseTrustCheck):
    check_id = "runtime_canary"
    description = "Detects if injected canary tokens leaked through logs or network traffic."

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        if not ctx.runtime_traces:
            return [
                self.finding(
                    title="No runtime traces available for canary analysis",
                    category=TrustCategory.CANARY,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Canary analysis requires runtime traces.",
                    recommendation="Enable runtime checks before enforcing canary policy.",
                )
            ]

        bank = CanaryBank(profile=ctx.config.canary_profile)
        findings: list[TrustFinding] = []
        hits_found = False

        for profile, trace in ctx.runtime_traces.items():
            keys: set[str] = set()
            observed_entries: set[str] = set()

            for key in trace.canary_hits:
                keys.add(key)
                observed_entries.add(_format_observed(key, "trace.canary_hits"))

            if trace.logs:
                for match in detect_canary_matches(bank, trace.logs):
                    keys.add(match.key)
                    observed_entries.add(_format_match_observed(match, "logs"))

            for index, response in enumerate(trace.probe_responses):
                body_snippet = response.get("body_snippet", "")
                if not body_snippet:
                    continue
                for match in detect_canary_matches(bank, body_snippet):
                    keys.add(match.key)
                    observed_entries.add(
                        _format_match_observed(match, f"probe_responses[{index}].body_snippet")
                    )

            if not keys:
                continue
            hits_found = True
            hit_keys = sorted(keys)
            findings.append(
                self.finding(
                    title="Canary token exposure detected",
                    category=TrustCategory.CANARY,
                    severity=TrustSeverity.CRITICAL,
                    passed=False,
                    summary=f"Profile '{profile}' exposed canary key(s): {', '.join(hit_keys)}",
                    recommendation="Block submission and investigate secret access/exfiltration behavior.",
                    observed=", ".join(sorted(observed_entries)),
                )
            )

        if not hits_found:
            findings.append(
                self.finding(
                    title="No canary token exposure detected",
                    category=TrustCategory.CANARY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="Runtime logs did not include seeded canary values.",
                )
            )

        return findings


def _format_match_observed(match: CanaryMatch, source: str) -> str:
    transforms = "+".join(match.transforms)
    parts = [match.key, source]
    if transforms:
        parts.append(transforms)
    return ":".join(parts)


def _format_observed(key: str, source: str) -> str:
    return f"{key}:{source}"
