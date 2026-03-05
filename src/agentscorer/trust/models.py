from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class TrustSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TrustCategory(str, Enum):
    SUPPLY_CHAIN = "supply_chain"
    PROVENANCE = "provenance"
    HIDDEN_BEHAVIOR = "hidden_behavior"
    EGRESS = "egress"
    CANARY = "canary"
    TOOL_INTEGRITY = "tool_integrity"
    SANDBOX_EVASION = "sandbox_evasion"
    DECLARATION = "declaration"


class TrustVerdict(str, Enum):
    ALLOW_CLEAN = "allow_clean"
    ALLOW_WITH_WARNINGS = "allow_with_warnings"
    MANUAL_REVIEW = "manual_review"
    BLOCK = "block"


class EvidenceRef(BaseModel):
    kind: str
    path: str = ""
    sha256: str = ""
    description: str = ""

    @classmethod
    def from_path(
        cls,
        kind: str,
        path: str | Path,
        description: str = "",
    ) -> "EvidenceRef":
        p = Path(path)
        digest = ""
        if p.exists() and p.is_file():
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        return cls(kind=kind, path=str(p), sha256=digest, description=description)


class TrustFinding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    check_id: str
    title: str
    category: TrustCategory
    severity: TrustSeverity
    passed: bool
    confidence: float = 0.95
    summary: str = ""
    recommendation: str = ""
    location_path: str = ""
    location_line: int = 0
    expected: str = ""
    observed: str = ""
    evidence: list[EvidenceRef] = []


class TrustScorecard(BaseModel):
    checks_run: int
    checks_passed: int
    checks_failed: int
    findings_total: int
    findings_by_severity: dict[str, int]
    verdict: TrustVerdict
    duration_seconds: float
    policy_version: str = "trust-policy-v1"


class TrustScanResult(BaseModel):
    scorecard: TrustScorecard
    findings: list[TrustFinding]
    metadata: dict[str, str | int | float | list[str] | dict[str, str]] = {}
    artifacts_manifest: list[EvidenceRef] = []


def verdict_rank(verdict: TrustVerdict) -> int:
    rank = {
        TrustVerdict.ALLOW_CLEAN: 0,
        TrustVerdict.ALLOW_WITH_WARNINGS: 1,
        TrustVerdict.MANUAL_REVIEW: 2,
        TrustVerdict.BLOCK: 3,
    }
    return rank[verdict]


def severity_counts(findings: list[TrustFinding]) -> dict[str, int]:
    counts = {s.value: 0 for s in TrustSeverity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
