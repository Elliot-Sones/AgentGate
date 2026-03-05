"""Tests for SARIF report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentgate.models.agent import AgentConfig
from agentgate.models.score import (
    DetectorSummary,
    FailedTest,
    LetterGrade,
    ScoreCard,
)
from agentgate.reports.sarif import SARIFReport


@pytest.fixture
def sample_scorecard() -> ScoreCard:
    return ScoreCard(
        grade=LetterGrade.D,
        total_tests_run=10,
        total_tests_passed=7,
        total_tests_failed=3,
        pass_rate=0.7,
        detectors=[
            DetectorSummary(
                name="prompt_injection",
                tests_run=5,
                tests_passed=3,
                tests_failed=2,
                failed_tests=[
                    FailedTest(
                        test_name="DAN jailbreak #1",
                        test_case_id="abc123",
                        evidence="Compliance indicators found",
                        confidence=0.9,
                        runs_failed=2,
                        runs_total=3,
                    ),
                    FailedTest(
                        test_name="Role-play injection #1",
                        test_case_id="def456",
                        evidence="Agent adopted persona",
                        confidence=0.85,
                        runs_failed=1,
                        runs_total=3,
                    ),
                ],
            ),
            DetectorSummary(
                name="hallucination",
                tests_run=5,
                tests_passed=4,
                tests_failed=1,
                failed_tests=[
                    FailedTest(
                        test_name="Fabricated data #1",
                        test_case_id="ghi789",
                        evidence="Agent fabricated order data",
                        confidence=0.8,
                        runs_failed=1,
                        runs_total=3,
                    ),
                ],
            ),
        ],
    )


@pytest.fixture
def sample_agent_config() -> AgentConfig:
    return AgentConfig(url="http://localhost:8000/api", name="Test Agent")


def test_sarif_structure(
    sample_scorecard: ScoreCard, sample_agent_config: AgentConfig
) -> None:
    report = SARIFReport()
    data = report.generate(sample_scorecard, sample_agent_config, 5.0)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "AgentGate"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 3  # 2 + 1 failed tests

    # Check properties
    props = run["properties"]
    assert props["grade"] == "D"
    assert props["passRate"] == 0.7
    assert props["totalTestsRun"] == 10


def test_sarif_result_fields(
    sample_scorecard: ScoreCard, sample_agent_config: AgentConfig
) -> None:
    report = SARIFReport()
    data = report.generate(sample_scorecard, sample_agent_config, 5.0)

    results = data["runs"][0]["results"]
    first = results[0]

    assert first["ruleId"] == "PI001"
    assert first["level"] == "error"
    assert "DAN jailbreak" in first["message"]["text"]
    assert first["properties"]["confidence"] == 0.9


def test_sarif_save(
    tmp_path: Path, sample_scorecard: ScoreCard, sample_agent_config: AgentConfig
) -> None:
    report = SARIFReport()
    report.generate(sample_scorecard, sample_agent_config, 5.0)

    out = tmp_path / "test.sarif"
    report.save(out)

    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
