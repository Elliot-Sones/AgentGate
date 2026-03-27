from __future__ import annotations

from agentgate.trust.runtime.adaptive.specialists.base import BaseSpecialist
from agentgate.trust.runtime.adaptive.specialists.behavior_consistency import (
    BehaviorConsistencyChecker,
)
from agentgate.trust.runtime.adaptive.specialists.canary_stresser import CanaryStresser
from agentgate.trust.runtime.adaptive.specialists.data_boundary import DataBoundaryTester
from agentgate.trust.runtime.adaptive.specialists.egress_prober import EgressProber
from agentgate.trust.runtime.adaptive.specialists.memory_poisoning import MemoryPoisoningProber
from agentgate.trust.runtime.adaptive.specialists.tool_exerciser import ToolExerciser

SPECIALIST_REGISTRY: dict[str, type[BaseSpecialist]] = {
    "tool_exerciser": ToolExerciser,
    "egress_prober": EgressProber,
    "data_boundary": DataBoundaryTester,
    "canary_stresser": CanaryStresser,
    "behavior_consistency": BehaviorConsistencyChecker,
    "memory_poisoning": MemoryPoisoningProber,
}

__all__ = [
    "BaseSpecialist",
    "BehaviorConsistencyChecker",
    "CanaryStresser",
    "DataBoundaryTester",
    "EgressProber",
    "MemoryPoisoningProber",
    "ToolExerciser",
    "SPECIALIST_REGISTRY",
]
