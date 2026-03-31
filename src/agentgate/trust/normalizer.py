from __future__ import annotations

from pathlib import Path

from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.signals import SignalContext, TrustSignal, evidence_bucket

_SEVERITY_LADDER: tuple[TrustSeverity, ...] = (
    TrustSeverity.INFO,
    TrustSeverity.LOW,
    TrustSeverity.MEDIUM,
    TrustSeverity.HIGH,
    TrustSeverity.CRITICAL,
)
_SEVERITY_INDEX = {severity: idx for idx, severity in enumerate(_SEVERITY_LADDER)}
_NON_RUNTIME_FILE_CLASSES = {
    "test",
    "fixture",
    "example",
    "docs",
    "tooling",
    "vendored",
    "generated",
}


def normalize_finding(
    signal: TrustSignal,
    *,
    file_map: dict[object, str] | None = None,
    reachability_map: dict[object, str] | None = None,
    destination_class: str = "",
    evidence_strength: str | None = None,
    runtime_attribution: str = "unknown",
    attribution_confidence: str = "low",
    destination_declared: bool = True,
) -> TrustFinding:
    source_path, source_line = _split_source_location(signal.source_location)
    file_class = _lookup_context_value(file_map, source_path)
    reachability = _lookup_context_value(reachability_map, source_path)
    ctx = SignalContext(
        file_class=file_class,
        reachability=reachability,
        destination_class=destination_class,
        evidence_strength=evidence_strength or signal.detection_method,
        runtime_attribution=runtime_attribution,
        attribution_confidence=attribution_confidence,
    )

    severity = signal.base_severity
    severity = _apply_file_rules(severity, file_class=file_class, reachability=reachability)
    severity = _apply_destination_rules(
        severity,
        destination_class=destination_class,
        destination_declared=destination_declared,
    )
    severity = _apply_evidence_rules(
        severity,
        evidence_strength=ctx.evidence_strength,
        reachability=reachability,
        attribution_confidence=ctx.attribution_confidence,
    )

    finding = TrustFinding(
        check_id=signal.check_id,
        title=signal.title,
        category=signal.category,
        severity=severity,
        passed=severity == TrustSeverity.INFO,
        summary=signal.summary,
        recommendation=signal.recommendation,
        location_path=source_path if source_path else "",
        location_line=source_line,
        observed=signal.raw_evidence,
    )
    _attach_metadata(finding, context=ctx, base_severity=signal.base_severity, legacy_interpretation=False)
    return finding


def tag_legacy_finding(finding: TrustFinding) -> TrustFinding:
    base_severity = finding.severity
    _attach_metadata(finding, context=None, base_severity=base_severity, legacy_interpretation=True)
    return finding


def is_strong_evidence(
    *,
    evidence_strength: str,
    reachability: str = "unknown",
    attribution_confidence: str = "low",
) -> bool:
    return (
        evidence_bucket(
            SignalContext(
                evidence_strength=evidence_strength,
                reachability=reachability,
                attribution_confidence=attribution_confidence,
            )
        )
        == "strong"
    )


def policy_evidence_bucket(
    *,
    evidence_strength: str,
    reachability: str = "unknown",
    attribution_confidence: str = "low",
) -> str:
    return evidence_bucket(
        SignalContext(
            evidence_strength=evidence_strength,
            reachability=reachability,
            attribution_confidence=attribution_confidence,
        )
    )


def _apply_file_rules(
    severity: TrustSeverity,
    *,
    file_class: str,
    reachability: str,
) -> TrustSeverity:
    if file_class in _NON_RUNTIME_FILE_CLASSES and reachability == "not_reached":
        return _cap_severity(severity, TrustSeverity.INFO)
    if file_class in _NON_RUNTIME_FILE_CLASSES and reachability == "unknown":
        return _lower_severity(severity, bands=1, floor=TrustSeverity.LOW)
    if file_class == "test" and reachability == "on_execution_path":
        return _cap_severity(severity, TrustSeverity.MEDIUM)
    if reachability == "not_reached":
        return _lower_severity(severity, bands=1, floor=TrustSeverity.LOW)
    return severity


def _apply_destination_rules(
    severity: TrustSeverity,
    *,
    destination_class: str,
    destination_declared: bool,
) -> TrustSeverity:
    if destination_class in {"platform_internal_verified", "declared_business"}:
        return _cap_severity(severity, TrustSeverity.INFO)
    if destination_class == "framework_telemetry":
        return _cap_severity(severity, TrustSeverity.INFO)
    if destination_class == "dependency_service":
        return _cap_severity(
            severity,
            TrustSeverity.INFO if destination_declared else TrustSeverity.LOW,
        )
    if destination_class == "undeclared_known":
        return _cap_severity(severity, TrustSeverity.MEDIUM)
    return severity


def _apply_evidence_rules(
    severity: TrustSeverity,
    *,
    evidence_strength: str,
    reachability: str,
    attribution_confidence: str,
) -> TrustSeverity:
    if evidence_strength == "llm_inferred" and attribution_confidence == "low":
        return _cap_severity(severity, TrustSeverity.MEDIUM)
    if evidence_strength == "heuristic" and reachability != "on_execution_path":
        return severity
    return severity


def _cap_severity(severity: TrustSeverity, cap: TrustSeverity) -> TrustSeverity:
    if _SEVERITY_INDEX[severity] > _SEVERITY_INDEX[cap]:
        return cap
    return severity


def _lower_severity(
    severity: TrustSeverity,
    *,
    bands: int,
    floor: TrustSeverity,
) -> TrustSeverity:
    target_index = max(_SEVERITY_INDEX[severity] - bands, _SEVERITY_INDEX[floor])
    return _SEVERITY_LADDER[target_index]


def _split_source_location(source_location: str) -> tuple[str, int]:
    text = source_location.strip()
    if not text:
        return "", 0

    if ":" not in text:
        return text, 0

    prefix, suffix = text.rsplit(":", 1)
    if suffix.isdigit():
        return prefix, int(suffix)
    if prefix.endswith(".py") or "/" in prefix or "\\" in prefix:
        return prefix, 0
    return text, 0


def _lookup_context_value(
    mapping: dict[object, str] | None,
    source_path: str,
    *,
    default: str = "unknown",
) -> str:
    if not mapping or not source_path:
        return default

    if source_path in mapping:
        return mapping[source_path]

    path_key = Path(source_path)
    if path_key in mapping:
        return mapping[path_key]

    posix_key = path_key.as_posix()
    if posix_key in mapping:
        return mapping[posix_key]

    return default


def _attach_metadata(
    finding: TrustFinding,
    *,
    context: SignalContext | None,
    base_severity: TrustSeverity | None,
    legacy_interpretation: bool,
) -> None:
    finding.__dict__["context"] = context
    finding.__dict__["base_severity"] = base_severity
    finding.__dict__["legacy_interpretation"] = legacy_interpretation
