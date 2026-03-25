from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from agentgate.reports.report_enricher import ReportEnricher
from agentgate.trust.models import (
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
    TrustVerdict,
)


def _result() -> TrustScanResult:
    return TrustScanResult(
        scorecard=TrustScorecard(
            checks_run=1,
            checks_passed=0,
            checks_failed=1,
            findings_total=1,
            findings_by_severity={
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            verdict=TrustVerdict.MANUAL_REVIEW,
            duration_seconds=0.2,
            policy_version="trust-policy-v1",
        ),
        findings=[
            TrustFinding(
                id="finding-1",
                check_id="runtime_egress",
                title="Undeclared outbound egress detected",
                category=TrustCategory.EGRESS,
                severity=TrustSeverity.HIGH,
                passed=False,
                summary="Connected to an undeclared domain.",
                recommendation="Review outbound domains.",
            )
        ],
        metadata={"submission_profile": {"agent_name": "Demo Agent"}},
        artifacts_manifest=[],
    )


def test_report_enricher_is_noop_without_api_key() -> None:
    result = _result()

    enriched = ReportEnricher(api_key="", enabled=True).enrich(result)

    assert enriched.enrichment is None


def test_report_enricher_attaches_structured_enrichment() -> None:
    result = _result()
    response = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="text",
                text="""{
  "executive_summary": "Reviewer summary.",
  "finding_narratives": {
    "finding-1": "This finding means the agent talked to an undeclared endpoint."
  },
  "reviewer_guidance": ["Escalate for review."],
  "buyer_disclosure": ["This listing is under review."]
}""",
            )
        ]
    )

    with patch("agentgate.reports.report_enricher.anthropic.Anthropic") as mock_cls:
        mock_client = mock_cls.return_value
        mock_client.messages.create.return_value = response
        enriched = ReportEnricher(api_key="test-key", enabled=True).enrich(result)

    assert enriched.enrichment is not None
    assert enriched.enrichment.executive_summary == "Reviewer summary."
    assert enriched.enrichment.finding_narratives["finding-1"] == (
        "This finding means the agent talked to an undeclared endpoint."
    )
    assert enriched.enrichment.reviewer_guidance == ["Escalate for review."]
    assert enriched.enrichment.buyer_disclosure == ["This listing is under review."]
    assert enriched.enrichment.generated_by_llm is True
