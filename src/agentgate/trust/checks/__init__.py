from __future__ import annotations

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.checks.runtime_behavior_diff import RuntimeBehaviorDiffCheck
from agentgate.trust.checks.runtime_canary import RuntimeCanaryCheck
from agentgate.trust.checks.runtime_egress import RuntimeEgressCheck
from agentgate.trust.checks.runtime_hosted import HostedRuntimeCheck
from agentgate.trust.checks.runtime_tool_audit import RuntimeToolAuditCheck
from agentgate.trust.checks.static_code_signals import StaticCodeSignalsCheck
from agentgate.trust.checks.static_dependency_risk import StaticDependencyRiskCheck
from agentgate.trust.checks.static_manifest import StaticManifestCheck
from agentgate.trust.checks.static_prompt_tool_inspection import (
    StaticPromptToolInspectionCheck,
)
from agentgate.trust.checks.static_provenance import StaticProvenanceCheck


def default_trust_checks() -> list[BaseTrustCheck]:
    return [
        StaticManifestCheck(),
        StaticPromptToolInspectionCheck(),
        StaticDependencyRiskCheck(),
        StaticProvenanceCheck(),
        StaticCodeSignalsCheck(),
        HostedRuntimeCheck(),
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
    "HostedRuntimeCheck",
    "RuntimeEgressCheck",
    "RuntimeCanaryCheck",
    "RuntimeToolAuditCheck",
    "RuntimeBehaviorDiffCheck",
]
