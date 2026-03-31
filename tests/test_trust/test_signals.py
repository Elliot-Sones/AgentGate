from __future__ import annotations

from pathlib import Path

from agentgate.trust.config import TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustSeverity
from agentgate.trust.signals import (
    SignalContext,
    TrustSignal,
    evidence_bucket,
    is_strong_evidence,
)


def test_trust_signal_construction() -> None:
    signal = TrustSignal(
        check_id="static_code_signals",
        signal_type="pattern_match",
        title="Dynamic exec detected",
        summary="exec() call found in source",
        raw_evidence="exec(user_input)",
        detection_method="heuristic",
        source_location="src/agent/core.py:42",
        base_severity=TrustSeverity.HIGH,
        category=TrustCategory.HIDDEN_BEHAVIOR,
        recommendation="Remove dynamic exec calls.",
    )

    assert signal.check_id == "static_code_signals"
    assert signal.base_severity == TrustSeverity.HIGH
    assert signal.detection_method == "heuristic"


def test_signal_context_defaults() -> None:
    ctx = SignalContext()

    assert ctx.file_class == "unknown"
    assert ctx.reachability == "unknown"
    assert ctx.destination_class == ""
    assert ctx.evidence_strength == "heuristic"
    assert ctx.runtime_attribution == "unknown"
    assert ctx.attribution_confidence == "low"


def test_signal_context_normalizes_whitespace() -> None:
    ctx = SignalContext(
        file_class=" test ",
        reachability=" on_execution_path ",
        destination_class=" framework_telemetry ",
        evidence_strength=" heuristic ",
        runtime_attribution=" request_time ",
        attribution_confidence=" high ",
    )

    assert ctx.file_class == "test"
    assert ctx.reachability == "on_execution_path"
    assert ctx.destination_class == "framework_telemetry"
    assert ctx.evidence_strength == "heuristic"
    assert ctx.runtime_attribution == "request_time"
    assert ctx.attribution_confidence == "high"


def test_signal_context_bucket_and_strongness() -> None:
    ctx = SignalContext(
        file_class="runtime_code",
        reachability="on_execution_path",
        evidence_strength="heuristic",
        attribution_confidence="high",
    )

    assert evidence_bucket(ctx) == "strong"
    assert is_strong_evidence(ctx) is True


def test_signal_context_weak_bucket() -> None:
    ctx = SignalContext(
        file_class="test",
        reachability="not_reached",
        evidence_strength="log_only",
        attribution_confidence="medium",
    )

    assert evidence_bucket(ctx) == "weak"
    assert is_strong_evidence(ctx) is False


def test_trust_scan_context_support_fields_default_empty(tmp_path: Path) -> None:
    config = TrustScanConfig(
        source_dir=tmp_path,
        image_ref="",
        manifest_path=None,
        output_dir=tmp_path / "out",
    )
    ctx = TrustScanContext(config=config)

    assert ctx.file_classification_map == {}
    assert ctx.reachability_graph == {}
    assert ctx.destination_taxonomy == {}
