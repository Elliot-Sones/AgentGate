from __future__ import annotations

from agentgate.models.result import TestResult
from agentgate.models.score import DetectorSummary, FailedTest, LetterGrade, ScoreCard


class ScoringEngine:
    """Builds a transparent scorecard from test results.

    No exponential decay, no category weights. Just:
    - How many tests ran per detector
    - How many passed / failed
    - Which specific tests failed (with payload, response, evidence)
    - A letter grade based on overall pass rate
    """

    def calculate_scorecard(
        self,
        results_by_detector: dict[str, list[TestResult]],
    ) -> ScoreCard:
        """Build a ScoreCard from per-detector TestResult lists."""
        detector_summaries: list[DetectorSummary] = []
        total_run = 0
        total_failed = 0

        for detector_name, results in results_by_detector.items():
            # Group results by test_case_id to get per-test-case pass/fail
            by_case: dict[str, list[TestResult]] = {}
            for r in results:
                by_case.setdefault(r.test_case_id, []).append(r)

            failed_tests: list[FailedTest] = []
            tests_run = len(by_case)
            tests_failed = 0

            for case_id, case_results in by_case.items():
                case_failures = [r for r in case_results if not r.passed]
                if case_failures:
                    tests_failed += 1
                    rep = case_failures[0]
                    failed_tests.append(
                        FailedTest(
                            test_name=rep.test_name or f"test_{case_id}",
                            test_case_id=case_id,
                            input_payload=rep.input_payload,
                            output_response=rep.response[:2000] if rep.response else "",
                            evidence=rep.evidence,
                            confidence=rep.confidence,
                            evaluation_method=rep.evaluation_method.value,
                            runs_failed=len(case_failures),
                            runs_total=len(case_results),
                        )
                    )

            detector_summaries.append(
                DetectorSummary(
                    name=detector_name,
                    tests_run=tests_run,
                    tests_passed=tests_run - tests_failed,
                    tests_failed=tests_failed,
                    failed_tests=failed_tests,
                )
            )
            total_run += tests_run
            total_failed += tests_failed

        total_passed = total_run - total_failed
        pass_rate = total_passed / total_run if total_run > 0 else 1.0
        grade = LetterGrade.from_pass_rate(pass_rate)

        return ScoreCard(
            grade=grade,
            total_tests_run=total_run,
            total_tests_passed=total_passed,
            total_tests_failed=total_failed,
            pass_rate=round(pass_rate, 4),
            detectors=detector_summaries,
            overall_score=round(pass_rate * 100, 1),
        )
