from __future__ import annotations

from pathlib import Path

from agentgate.models.score import DetectorSummary, LetterGrade, ScoreCard
from agentgate.reports.trust_html_report import TrustHTMLReport
from agentgate.reports.trust_json_report import TrustJSONReport
from agentgate.trust.models import (
    ConfidenceSummary,
    CoverageSummary,
    DeploymentSummary,
    GeneratedRuntimeProfile,
    ReportEnrichment,
    SubmissionSupport,
    TrustCategory,
    TrustFinding,
    TrustScanResult,
    TrustScorecard,
    TrustSeverity,
    TrustVerdict,
)


def _sample_result() -> TrustScanResult:
    return TrustScanResult(
        scorecard=TrustScorecard(
            checks_run=5,
            checks_passed=3,
            checks_failed=2,
            findings_total=2,
            findings_by_severity={
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 1,
            },
            verdict=TrustVerdict.BLOCK,
            duration_seconds=1.2,
            policy_version="trust-policy-v1",
        ),
        findings=[
            TrustFinding(
                id="finding-egress",
                check_id="runtime_egress",
                title="Undeclared outbound egress detected",
                category=TrustCategory.EGRESS,
                severity=TrustSeverity.CRITICAL,
                passed=False,
                summary="Connected to telemetry-collector.attacker.example outside declared domains.",
                recommendation="Block submission and require explicit domain declaration.",
                observed="telemetry-collector.attacker.example",
            ),
            TrustFinding(
                id="finding-tool",
                check_id="runtime_tool_audit",
                title="Observed undeclared tool invocation",
                category=TrustCategory.TOOL_INTEGRITY,
                severity=TrustSeverity.HIGH,
                passed=False,
                summary="Runtime invoked tool(s) not declared in trust manifest.",
                recommendation="Declare all runtime tools and remove hidden tool paths.",
            ),
        ],
        metadata={
            "report_profile": "promptshop",
            "submission_profile": {
                "agent_name": "ShopFlow Support Copilot",
                "description": "Customer support assistant for Shopify stores.",
                "solution_category": "Customer Support",
                "business_use_case": "Resolve order and return questions",
                "declared_tools": [
                    "lookup_order",
                    "search_products",
                    "check_return_policy",
                ],
                "declared_external_domains": [],
                "permissions": ["read_orders", "read_products"],
                "customer_data_access": ["orders", "product catalog"],
                "integrations": ["shopify admin api"],
                "business_claims": ["handles returns", "answers order questions"],
            },
            "observed_external_destinations": [
                "telemetry-collector.attacker.example",
            ],
            "observed_tools": ["lookup_order", "search_products"],
            "hosted_runtime_context": {
                "probing_mode": "static",
                "probe_count": 4,
                "railway_log_lines": 12,
            },
        },
        artifacts_manifest=[],
        submission_support=SubmissionSupport(
            supported=True,
            status="supported",
            detail="Submission satisfies the current production contract.",
        ),
        generated_runtime_profile=GeneratedRuntimeProfile(
            build_strategy="dockerfile",
            dockerfile_path="/tmp/Dockerfile",
            http_supported=True,
            probe_paths=["/", "/docs"],
            dependencies=["postgres"],
            issued_integrations=["openai"],
        ),
        deployment_summary=DeploymentSummary(
            platform="railway",
            build_status="ready",
            deployment_status="ready",
            project_name="agentgate-scan-demo",
            public_url="https://demo.up.railway.app",
        ),
        coverage=CoverageSummary(
            level="partial",
            exercised_surfaces=["/docs"],
            skipped_surfaces=["/openapi.json"],
            notes=["No user trust manifest was provided; runtime profile was source-generated."],
        ),
        confidence=ConfidenceSummary(
            score=78,
            evidence_quality="moderate",
            inconclusive=False,
            drivers=["Hosted probe coverage exercised part of the expected runtime surface."],
        ),
    )


def _sample_security_scorecard() -> ScoreCard:
    return ScoreCard(
        grade=LetterGrade.C,
        total_tests_run=12,
        total_tests_passed=9,
        total_tests_failed=3,
        pass_rate=0.75,
        detectors=[
            DetectorSummary(
                name="prompt_injection",
                tests_run=4,
                tests_passed=3,
                tests_failed=1,
            )
        ],
    )


def test_trust_json_report_includes_marketplace_summaries() -> None:
    report = TrustJSONReport()
    data = report.generate(_sample_result(), profile="promptshop")

    assert data["report_profile"] == "promptshop"
    assert data["listing_summary"]["agent_name"] == "ShopFlow Support Copilot"
    assert data["reviewer_summary"]["publish_recommendation"] == "Do not publish"
    assert data["listing_summary"]["customer_data_access"] == ["orders", "product catalog"]
    assert data["reviewer_summary"]["primary_concerns"]
    assert data["coverage"]["level"] == "partial"
    assert data["confidence"]["score"] == 78
    assert data["generated_runtime_profile"]["build_strategy"] == "dockerfile"
    assert data["presentation"]["report_title"] == "PromptShop Marketplace Trust Report"
    assert data["presentation"]["report_summary"]["coverage_summary"].startswith("Partial coverage")
    assert data["testing_overview"]["mode"] == "static"
    assert data["testing_overview"]["probe_count"] == 4
    assert data["run_snapshot"]["headline"] == "This run used AgentGate's normal static hosted trust checks."


def test_trust_presentation_includes_report_title_and_scope() -> None:
    report = TrustJSONReport()
    data = report.generate(_sample_result(), profile="promptshop")

    assert data["listing_summary"]["agent_name"] == "ShopFlow Support Copilot"
    presentation_title = "PromptShop Marketplace Trust Report"
    html = TrustHTMLReport().generate(_sample_result(), profile="promptshop")
    assert presentation_title in html
    assert "What This Report Means" in html
    assert "What AgentGate Did" in html
    assert (
        "AgentGate found a blocking issue or could not satisfy the production trust contract"
        in html
    )
    assert "AgentGate deployed the submission into a temporary Railway environment." in html
    assert "Reviewed submitted source code and generated a runtime profile." in html
    assert "Deployed the submission into a temporary Railway environment before testing it." in html
    assert "Final decision: block." in html
    assert "What Actually Happened In This Run" in html
    assert "Hosted Runtime Testing" in html
    assert "AgentGate used static hosted probing and sent 4 HTTP probe(s) to the live agent endpoint." in html
    assert "Compared with an adaptive run: this used only the standard hosted probe set." in html


def test_trust_html_report_renders_promptshop_sections(tmp_path: Path) -> None:
    report = TrustHTMLReport()
    html = report.generate(_sample_result(), profile="promptshop")

    assert "ShopFlow Support Copilot" in html
    assert "PromptShop Marketplace Trust Report" in html
    assert "BLOCKED" in html
    assert "Summary" in html
    assert "How It Was Tested" in html
    assert "Decision & Findings" in html
    assert "What This Agent Does" in html
    assert "Reviewer Actions" in html
    assert "How AgentGate Tested This Agent" in html
    assert "Decision and Findings" in html
    assert "Deployment Summary" in html
    assert "Adaptive Specialist Breakdown" in html

    path = tmp_path / "trust.html"
    report.save(path)
    assert path.exists()


def test_trust_reports_prefer_enrichment_when_present() -> None:
    result = _sample_result()
    result.enrichment = ReportEnrichment(
        executive_summary="LLM summary for reviewers.",
        finding_narratives={
            "finding-egress": "The agent reached an undeclared telemetry endpoint during hosted evaluation."
        },
        reviewer_guidance=["Escalate to a marketplace reviewer."],
        buyer_disclosure=["This agent is currently under additional trust review."],
        model="claude-haiku-4-5-20251001",
        prompt_version="trust-report-enrichment-v1",
        generated_at="2026-03-25T00:00:00Z",
        generated_by_llm=True,
    )

    data = TrustJSONReport().generate(result, profile="promptshop")

    assert data["reviewer_summary"]["decision_notes"] == "LLM summary for reviewers."
    assert data["reviewer_summary"]["required_actions"] == ["Escalate to a marketplace reviewer."]
    assert data["listing_summary"]["buyer_summary"] == (
        "This agent is currently under additional trust review."
    )
    assert data["reviewer_summary"]["primary_concerns"][0]["summary"] == (
        "The agent reached an undeclared telemetry endpoint during hosted evaluation."
    )
    assert data["enrichment"]["generated_by_llm"] is True


def test_trust_reports_surface_adaptive_specialist_details() -> None:
    result = _sample_result()
    result.metadata["hosted_runtime_context"] = {
        "probing_mode": "adaptive",
        "probe_count": 6,
        "railway_log_lines": 0,
        "adaptive_specialists": [
            {
                "specialist": "tool_exerciser",
                "severity": "medium",
                "findings": [],
                "evidence": [],
                "probes_sent": 2,
                "probes_succeeded": 1,
            },
            {
                "specialist": "data_boundary",
                "severity": "high",
                "findings": [{"title": "Boundary issue"}],
                "evidence": [{"kind": "response"}],
                "probes_sent": 1,
                "probes_succeeded": 1,
            },
        ],
    }

    data = TrustJSONReport().generate(result, profile="promptshop")
    html = TrustHTMLReport().generate(result, profile="promptshop")

    assert data["testing_overview"]["mode"] == "adaptive"
    assert data["testing_overview"]["specialist_count"] == 2
    assert data["testing_overview"]["specialist_probes_sent"] == 3
    assert data["testing_overview"]["specialist_findings"] == 1
    assert data["run_snapshot"]["headline"] == (
        "Adaptive probing materially changed this run by adding specialist-planned runtime probes."
    )
    assert "AgentGate used adaptive hosted probing with 2 specialist(s), sent 3 specialist probe(s), and surfaced 1 specialist finding(s)." in html
    assert "Compared with a static run: this run sent additional specialist-generated probes tailored to the agent." in html
    assert "tool_exerciser" in html
    assert "data_boundary" in html
    assert "Raised 1 finding(s) after 1 probe(s)." in html


def test_combined_review_reports_use_security_and_trust_title() -> None:
    result = _sample_result()
    security = _sample_security_scorecard()

    data = TrustJSONReport().generate(
        result,
        profile="standard",
        security_scorecard=security,
        security_duration=12.5,
    )
    html = TrustHTMLReport().generate(
        result,
        profile="standard",
        security_scorecard=security,
        security_duration=12.5,
    )

    assert data["scan_type"] == "review"
    assert data["security_scorecard"]["grade"] == "C"
    assert data["security_duration_seconds"] == 12.5
    assert data["presentation"]["report_title"] == "AgentGate Security + Trust Review Report"
    assert "AgentGate Security + Trust Review Report" in html
    assert "Security Scan" in html
