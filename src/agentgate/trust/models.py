from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

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
    RUNTIME_INTEGRITY = "runtime_integrity"
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


class CheckRecord(BaseModel):
    """What was tested and its outcome."""

    check_id: str
    description: str
    status: str = "completed"  # completed | skipped | error
    findings_count: int = 0
    failed: bool = False


class RuntimeInspect(BaseModel):
    """Runtime inspection telemetry captured during hosted agent evaluation."""

    user: str = ""
    network_mode: str = ""
    exit_code: int | None = None
    ports: list[str] = []
    env_keys: list[str] = []
    capabilities: list[str] = []
    oom_killed: bool = False


class RuntimeProfile(BaseModel):
    """What happened during a single hosted runtime evaluation profile."""

    name: str
    network_mode: str = ""
    status: str = "ok"  # ok | timeout | error | unavailable
    network_destinations: list[str] = []
    internal_destinations: list[str] = []
    tool_calls: list[str] = []
    process_events: list[str] = []
    canary_hits: list[str] = []
    probe_responses: list[dict[str, Any]] = []
    inspect: RuntimeInspect | None = None


class DependencyRecord(BaseModel):
    """A backing service that was started as a sidecar."""

    service: str
    source: str = "declared"  # declared | inferred
    image: str = ""
    port: int = 0
    healthy: bool = True
    inference_note: str = ""


class AgentOverview(BaseModel):
    """What the agent is, from the manifest."""

    name: str = ""
    description: str = ""
    version: str = ""
    category: str = ""
    business_use_case: str = ""
    customer_data_access: list[str] = []
    declared_tools: list[str] = []
    declared_external_domains: list[str] = []
    business_claims: list[str] = []
    integrations: list[str] = []
    permissions: list[str] = []


class ReportEnrichment(BaseModel):
    executive_summary: str = ""
    finding_narratives: dict[str, str] = {}
    reviewer_guidance: list[str] = []
    buyer_disclosure: list[str] = []
    model: str = ""
    prompt_version: str = ""
    generated_at: str = ""
    generated_by_llm: bool = False


class SubmissionSupport(BaseModel):
    supported: bool = True
    status: str = "supported"
    reason: str = ""
    detail: str = ""
    notes: list[str] = []


class GeneratedRuntimeProfile(BaseModel):
    build_strategy: str = "dockerfile"
    dockerfile_path: str = ""
    entrypoint: str = ""
    http_supported: bool = False
    port_candidates: list[int] = []
    probe_paths: list[str] = []
    dependencies: list[str] = []
    runtime_env_keys: list[str] = []
    integrations: list[str] = []
    unsupported_integrations: list[str] = []
    issued_integrations: list[str] = []
    integration_sandboxes: list[dict[str, Any]] = []
    integration_routes: dict[str, list[str]] = {}
    allow_domains: list[str] = []
    notes: list[str] = []


class DeploymentSummary(BaseModel):
    platform: str = ""
    build_status: str = "not_started"
    deployment_status: str = "not_started"
    project_id: str = ""
    project_name: str = ""
    environment_name: str = ""
    service_name: str = ""
    public_url: str = ""
    dependency_services: list[str] = []
    issued_integrations: list[str] = []
    integration_sandboxes: list[dict[str, Any]] = []
    notes: list[str] = []


class CoverageSummary(BaseModel):
    level: str = "none"
    exercised_surfaces: list[str] = []
    skipped_surfaces: list[str] = []
    notes: list[str] = []


class ConfidenceSummary(BaseModel):
    score: int = 0
    evidence_quality: str = "weak"
    inconclusive: bool = True
    drivers: list[str] = []


class TrustScanResult(BaseModel):
    scorecard: TrustScorecard
    findings: list[TrustFinding]
    metadata: dict[str, Any] = {}
    artifacts_manifest: list[EvidenceRef] = []

    # Structured data for reports
    agent_overview: AgentOverview | None = None
    checks: list[CheckRecord] = []
    runtime_profiles: list[RuntimeProfile] = []
    dependencies: list[DependencyRecord] = []
    enrichment: ReportEnrichment | None = None
    submission_support: SubmissionSupport | None = None
    generated_runtime_profile: GeneratedRuntimeProfile | None = None
    deployment_summary: DeploymentSummary | None = None
    coverage: CoverageSummary | None = None
    confidence: ConfidenceSummary | None = None


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
