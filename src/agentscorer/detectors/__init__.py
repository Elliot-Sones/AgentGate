from __future__ import annotations

from agentscorer.detectors.base import BaseDetector
from agentscorer.detectors.prompt_injection import PromptInjectionDetector
from agentscorer.detectors.system_prompt_leak import SystemPromptLeakDetector
from agentscorer.detectors.data_exfiltration import DataExfiltrationDetector
from agentscorer.detectors.hallucination import HallucinationDetector
from agentscorer.detectors.input_validation import InputValidationDetector
from agentscorer.detectors.tool_misuse import ToolMisuseDetector
from agentscorer.detectors.goal_hijacking import GoalHijackingDetector
from agentscorer.detectors.xpia import XPIADetector
from agentscorer.detectors.harmful_content import HarmfulContentDetector
from agentscorer.detectors.policy_violation import PolicyViolationDetector
from agentscorer.detectors.reliability import ReliabilityDetector
from agentscorer.detectors.scope_adherence import ScopeAdherenceDetector

DETECTOR_REGISTRY: dict[str, type[BaseDetector]] = {
    "prompt_injection": PromptInjectionDetector,
    "system_prompt_leak": SystemPromptLeakDetector,
    "data_exfiltration": DataExfiltrationDetector,
    "hallucination": HallucinationDetector,
    "input_validation": InputValidationDetector,
    "tool_misuse": ToolMisuseDetector,
    "goal_hijacking": GoalHijackingDetector,
    "xpia": XPIADetector,
    "harmful_content": HarmfulContentDetector,
    "policy_violation": PolicyViolationDetector,
    "reliability": ReliabilityDetector,
    "scope_adherence": ScopeAdherenceDetector,
}

ALL_DETECTORS = list(DETECTOR_REGISTRY.keys())


def get_detector(name: str) -> type[BaseDetector]:
    if name not in DETECTOR_REGISTRY:
        raise ValueError(f"Unknown detector: {name}. Available: {ALL_DETECTORS}")
    return DETECTOR_REGISTRY[name]


def get_all_detectors() -> dict[str, type[BaseDetector]]:
    return dict(DETECTOR_REGISTRY)


__all__ = [
    "BaseDetector",
    "DETECTOR_REGISTRY",
    "ALL_DETECTORS",
    "get_detector",
    "get_all_detectors",
    "PromptInjectionDetector",
    "SystemPromptLeakDetector",
    "DataExfiltrationDetector",
    "HallucinationDetector",
    "InputValidationDetector",
    "ToolMisuseDetector",
    "GoalHijackingDetector",
    "XPIADetector",
    "HarmfulContentDetector",
    "PolicyViolationDetector",
    "ReliabilityDetector",
    "ScopeAdherenceDetector",
]
