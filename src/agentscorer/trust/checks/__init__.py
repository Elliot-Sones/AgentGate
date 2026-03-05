from __future__ import annotations

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.checks.runtime_behavior_diff import RuntimeBehaviorDiffCheck
from agentscorer.trust.checks.runtime_canary import RuntimeCanaryCheck
from agentscorer.trust.checks.runtime_egress import RuntimeEgressCheck
from agentscorer.trust.checks.runtime_sandbox import RuntimeSandboxCheck
from agentscorer.trust.checks.runtime_tool_audit import RuntimeToolAuditCheck
from agentscorer.trust.checks.static_code_signals import StaticCodeSignalsCheck
from agentscorer.trust.checks.static_dependency_risk import StaticDependencyRiskCheck
from agentscorer.trust.checks.static_manifest import StaticManifestCheck
from agentscorer.trust.checks.static_prompt_tool_inspection import (
    StaticPromptToolInspectionCheck,
)
from agentscorer.trust.checks.static_provenance import StaticProvenanceCheck


def default_trust_checks() -> list[BaseTrustCheck]:
    return [
        StaticManifestCheck(),
        StaticPromptToolInspectionCheck(),
        StaticDependencyRiskCheck(),
        StaticProvenanceCheck(),
        StaticCodeSignalsCheck(),
        RuntimeSandboxCheck(),
        RuntimeEgressCheck(),
        RuntimeCanaryCheck(),
        RuntimeToolAuditCheck(),
        RuntimeBehaviorDiffCheck(),
    ]


__all__ = [
    "BaseTrustCheck",
    "default_trust_checks",
    "StaticManifestCheck",
    "StaticPromptToolInspectionCheck",
    "StaticDependencyRiskCheck",
    "StaticProvenanceCheck",
    "StaticCodeSignalsCheck",
    "RuntimeSandboxCheck",
    "RuntimeEgressCheck",
    "RuntimeCanaryCheck",
    "RuntimeToolAuditCheck",
    "RuntimeBehaviorDiffCheck",
]
