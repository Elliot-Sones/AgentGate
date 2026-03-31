from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agentgate.trust.models import TrustCategory, TrustSeverity

PolicyEvidenceBucket = Literal["strong", "weak"]

EVIDENCE_STRENGTH_VALUES = frozenset(
    {
        "procfs_confirmed",
        "dns_only",
        "log_only",
        "llm_inferred",
        "heuristic",
        "inconclusive",
    }
)


@dataclass(slots=True)
class SignalContext:
    """Structured context attached by the normalizer."""

    file_class: str = "unknown"
    reachability: str = "unknown"
    destination_class: str = ""
    evidence_strength: str = "heuristic"
    runtime_attribution: str = "unknown"
    attribution_confidence: str = "low"

    def __post_init__(self) -> None:
        self.file_class = self.file_class.strip() or "unknown"
        self.reachability = self.reachability.strip() or "unknown"
        self.destination_class = self.destination_class.strip()
        self.evidence_strength = self.evidence_strength.strip() or "heuristic"
        self.runtime_attribution = self.runtime_attribution.strip() or "unknown"
        self.attribution_confidence = self.attribution_confidence.strip() or "low"

    def evidence_bucket(self) -> PolicyEvidenceBucket:
        return evidence_bucket(self)


def evidence_bucket(context: SignalContext) -> PolicyEvidenceBucket:
    """Map evidence strength into the policy buckets used by verdicting."""

    if context.evidence_strength == "procfs_confirmed":
        return "strong"
    if (
        context.evidence_strength == "heuristic"
        and context.reachability == "on_execution_path"
        and context.attribution_confidence == "high"
    ):
        return "strong"
    return "weak"


def is_strong_evidence(context: SignalContext) -> bool:
    return evidence_bucket(context) == "strong"


@dataclass(slots=True)
class TrustSignal:
    """Raw observation emitted by a check before normalization."""

    check_id: str
    signal_type: str
    title: str
    summary: str
    raw_evidence: str
    detection_method: str
    source_location: str
    base_severity: TrustSeverity
    category: TrustCategory
    recommendation: str = ""
