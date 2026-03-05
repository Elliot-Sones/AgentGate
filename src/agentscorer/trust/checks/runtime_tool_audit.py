from __future__ import annotations

from pathlib import PurePosixPath

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


class RuntimeToolAuditCheck(BaseTrustCheck):
    check_id = "runtime_tool_audit"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        declared_tools = _declared_tool_names(ctx.manifest or {})

        if not ctx.runtime_traces:
            return [
                self.finding(
                    title="No runtime traces available for tool audit",
                    category=TrustCategory.TOOL_INTEGRITY,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Tool auditing requires runtime traces.",
                    recommendation="Enable runtime checks before enforcing tool integrity gates.",
                )
            ]

        observed_tools: set[str] = set()
        for trace in ctx.runtime_traces.values():
            observed_tools.update(t.lower() for t in trace.tool_calls)
            observed_tools.update(_tool_hints_from_process_events(trace.process_events))

        if not observed_tools:
            findings.append(
                self.finding(
                    title="Tool audit lacked trustworthy telemetry",
                    category=TrustCategory.TOOL_INTEGRITY,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=(
                        "No tool-call markers or executable process events were observed, "
                        "so tool-integrity verification is incomplete."
                    ),
                    recommendation=(
                        "Require structured runtime tool telemetry (e.g., TOOL_CALL markers) "
                        "or platform-level tool tracing before allowing publication."
                    ),
                )
            )
            return findings

        undeclared = sorted(t for t in observed_tools if t not in declared_tools)
        if undeclared:
            findings.append(
                self.finding(
                    title="Observed undeclared tool invocation",
                    category=TrustCategory.TOOL_INTEGRITY,
                    severity=TrustSeverity.HIGH,
                    passed=False,
                    summary=(
                        "Runtime invoked tool(s) that are not declared in trust manifest: "
                        + ", ".join(undeclared)
                    ),
                    recommendation="Declare all runtime tools and review undeclared invocations for hidden behavior.",
                    observed=", ".join(undeclared),
                    expected=", ".join(sorted(declared_tools)) or "No tool usage",
                )
            )
        else:
            findings.append(
                self.finding(
                    title="Observed tools match declarations",
                    category=TrustCategory.TOOL_INTEGRITY,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="All observed tool calls are declared in trust manifest.",
                )
            )

        return findings


def _declared_tool_names(manifest: dict) -> set[str]:
    raw = manifest.get("declared_tools", [])
    names: set[str] = set()

    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                names.add(item.lower())
            elif isinstance(item, dict) and item.get("name"):
                names.add(str(item["name"]).lower())
    return names


def _tool_hints_from_process_events(events: list[str]) -> set[str]:
    hints: set[str] = set()
    for event in events:
        if ":" not in event:
            continue
        payload = event.split(":", 1)[1].strip()
        if not payload:
            continue
        executable = payload.split()[0].strip()
        if not executable:
            continue
        normalized = PurePosixPath(executable).name.lower()
        if normalized:
            hints.add(normalized)
    return hints
