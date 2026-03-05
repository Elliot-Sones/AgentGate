from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class LetterGrade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @classmethod
    def from_pass_rate(cls, pass_rate: float) -> LetterGrade:
        """Grade based on simple pass rate (0.0 to 1.0)."""
        if pass_rate >= 1.0:
            return cls.A
        elif pass_rate >= 0.95:
            return cls.B
        elif pass_rate >= 0.85:
            return cls.C
        elif pass_rate >= 0.70:
            return cls.D
        else:
            return cls.F

    @classmethod
    def from_score(cls, score: float) -> LetterGrade:
        """Grade from a 0-100 score (kept for backwards compat)."""
        return cls.from_pass_rate(score / 100.0)

    @property
    def label(self) -> str:
        labels = {
            "A": "All tests passed",
            "B": "Nearly all tests passed",
            "C": "Most tests passed",
            "D": "Significant failures",
            "F": "Critical failures",
        }
        return labels[self.value]


class FailedTest(BaseModel):
    """Detail about a single test that failed."""

    test_name: str
    test_case_id: str
    input_payload: str = ""
    output_response: str = ""
    evidence: str = ""
    confidence: float = 0.95
    evaluation_method: str = "heuristic"
    runs_failed: int = 0
    runs_total: int = 0


class DetectorSummary(BaseModel):
    """Per-detector results with full transparency."""

    name: str
    tests_run: int
    tests_passed: int
    tests_failed: int
    failed_tests: list[FailedTest] = []


class CategoryScore(BaseModel):
    """Score for a single category — kept for report grouping only."""

    name: str
    score: float
    weight: float
    tests_run: int = 0
    tests_failed: int = 0
    detectors: list[str] = []


class ScoreCard(BaseModel):
    """Overall scan scorecard — transparent pass/fail, no hidden math."""

    grade: LetterGrade
    total_tests_run: int
    total_tests_passed: int
    total_tests_failed: int
    pass_rate: float
    detectors: list[DetectorSummary]

    # Kept for backwards compat with reports that reference these
    overall_score: float = 0.0
    categories: list[CategoryScore] = []
    total_errors: int = 0
