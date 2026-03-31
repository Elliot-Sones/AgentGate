from __future__ import annotations

from pathlib import Path

from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.normalizer import SignalContext, TrustSignal, normalize_finding, tag_legacy_finding


def _signal(
    *,
    severity: TrustSeverity,
    source_location: str,
    summary: str = "summary",
    raw_evidence: str = "evidence",
) -> TrustSignal:
    return TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Suspicious code signal",
        summary=summary,
        raw_evidence=raw_evidence,
        detection_method="heuristic",
        source_location=source_location,
        base_severity=severity,
        category=TrustCategory.HIDDEN_BEHAVIOR,
        recommendation="Review the flagged code.",
    )


def test_test_file_not_reached_caps_to_info() -> None:
    finding = normalize_finding(
        _signal(severity=TrustSeverity.HIGH, source_location="tests/test_security.py:10"),
        file_map={"tests/test_security.py": "test"},
        reachability_map={"tests/test_security.py": "not_reached"},
    )

    assert finding.severity == TrustSeverity.INFO
    assert finding.base_severity == TrustSeverity.HIGH
    assert finding.context.file_class == "test"
    assert finding.context.reachability == "not_reached"


def test_path_key_context_maps_are_resolved() -> None:
    finding = normalize_finding(
        _signal(severity=TrustSeverity.HIGH, source_location="tests/test_security.py:10"),
        file_map={Path("tests/test_security.py"): "test"},
        reachability_map={Path("tests/test_security.py"): "not_reached"},
    )

    assert finding.severity == TrustSeverity.INFO
    assert finding.context.file_class == "test"
    assert finding.context.reachability == "not_reached"


def test_runtime_code_on_path_preserves_severity() -> None:
    finding = normalize_finding(
        _signal(severity=TrustSeverity.HIGH, source_location="src/agent/core.py:42"),
        file_map={"src/agent/core.py": "runtime_code"},
        reachability_map={"src/agent/core.py": "on_execution_path"},
    )

    assert finding.severity == TrustSeverity.HIGH
    assert finding.context.file_class == "runtime_code"
    assert finding.context.reachability == "on_execution_path"


def test_not_reached_alone_lowers_by_one_band() -> None:
    finding = normalize_finding(
        _signal(severity=TrustSeverity.HIGH, source_location="src/unused_module.py:5"),
        file_map={"src/unused_module.py": "runtime_code"},
        reachability_map={"src/unused_module.py": "not_reached"},
    )

    assert finding.severity == TrustSeverity.MEDIUM


def test_unknown_reachability_no_downgrade() -> None:
    finding = normalize_finding(
        _signal(severity=TrustSeverity.HIGH, source_location="src/plugins/loader.py:5"),
        file_map={"src/plugins/loader.py": "runtime_code"},
        reachability_map={"src/plugins/loader.py": "unknown"},
    )

    assert finding.severity == TrustSeverity.HIGH


def test_platform_internal_verified_defaults_to_info() -> None:
    finding = normalize_finding(
        TrustSignal(
            check_id="runtime_egress",
            signal_type="outbound_connection",
            title="Outbound connection",
            summary="Connection to internal IP",
            raw_evidence="10.165.167.93",
            detection_method="procfs_socket",
            source_location="runtime:startup",
            base_severity=TrustSeverity.CRITICAL,
            category=TrustCategory.EGRESS,
            recommendation="Review the destination.",
        ),
        destination_class="platform_internal_verified",
        evidence_strength="procfs_confirmed",
        runtime_attribution="startup",
    )

    assert finding.severity == TrustSeverity.INFO
    assert finding.context.destination_class == "platform_internal_verified"


def test_unknown_external_preserves_severity() -> None:
    finding = normalize_finding(
        TrustSignal(
            check_id="runtime_egress",
            signal_type="outbound_connection",
            title="Unknown destination",
            summary="Connection to unknown host",
            raw_evidence="sketchy-server.xyz",
            detection_method="procfs_socket",
            source_location="runtime:request_time",
            base_severity=TrustSeverity.HIGH,
            category=TrustCategory.EGRESS,
            recommendation="Review the destination.",
        ),
        destination_class="unknown_external",
        evidence_strength="procfs_confirmed",
        runtime_attribution="request_time",
        attribution_confidence="high",
    )

    assert finding.severity == TrustSeverity.HIGH


def test_legacy_finding_tagged() -> None:
    legacy = TrustFinding(
        check_id="static_manifest",
        title="Manifest missing",
        category=TrustCategory.DECLARATION,
        severity=TrustSeverity.INFO,
        passed=True,
        summary="No manifest",
    )

    tagged = tag_legacy_finding(legacy)
    assert tagged.legacy_interpretation is True
    assert tagged.base_severity == TrustSeverity.INFO
    assert getattr(tagged, "context", None) is None
