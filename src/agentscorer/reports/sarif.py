"""SARIF 2.1.0 report generator for CI/CD integration."""

from __future__ import annotations

import json
from pathlib import Path

from agentscorer.models.agent import AgentConfig
from agentscorer.models.score import ScoreCard


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_DETECTOR_RULE_MAP = {
    "prompt_injection": ("PI001", "Prompt Injection", "error"),
    "system_prompt_leak": ("SPL001", "System Prompt Leak", "error"),
    "data_exfiltration": ("DE001", "Data Exfiltration", "error"),
    "hallucination": ("HAL001", "Hallucination", "warning"),
    "input_validation": ("IV001", "Input Validation", "warning"),
    "tool_misuse": ("TM001", "Tool Misuse", "error"),
    "goal_hijacking": ("GH001", "Goal Hijacking", "error"),
    "xpia": ("XPIA001", "Cross-domain Prompt Injection", "error"),
}


class SARIFReport:
    """Generates SARIF 2.1.0 JSON output."""

    def __init__(self) -> None:
        self._data: dict | None = None

    def generate(
        self,
        scorecard: ScoreCard,
        agent_config: AgentConfig,
        duration: float,
        budget_info: dict | None = None,
    ) -> dict:
        rules = []
        results = []

        for detector in scorecard.detectors:
            rule_id, rule_name, default_level = _DETECTOR_RULE_MAP.get(
                detector.name, (detector.name, detector.name, "warning")
            )

            rules.append(
                {
                    "id": rule_id,
                    "name": rule_name,
                    "shortDescription": {"text": f"{rule_name} security test"},
                    "defaultConfiguration": {"level": default_level},
                }
            )

            for failed_test in detector.failed_tests:
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": default_level,
                        "message": {
                            "text": (
                                f"{failed_test.test_name}: {failed_test.evidence}"
                                if failed_test.evidence
                                else failed_test.test_name
                            ),
                        },
                        "properties": {
                            "confidence": failed_test.confidence,
                            "evaluationMethod": failed_test.evaluation_method,
                            "runsFailed": failed_test.runs_failed,
                            "runsTotal": failed_test.runs_total,
                        },
                    }
                )

        self._data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentScorer",
                            "informationUri": "https://github.com/agentscorer",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "grade": scorecard.grade.value,
                        "passRate": scorecard.pass_rate,
                        "totalTestsRun": scorecard.total_tests_run,
                        "totalTestsFailed": scorecard.total_tests_failed,
                        "durationSeconds": round(duration, 2),
                        "targetUrl": agent_config.url,
                        "targetName": agent_config.name,
                    },
                }
            ],
        }
        return self._data

    def save(self, path: Path) -> None:
        if self._data is None:
            raise RuntimeError("Call generate() before save()")
        path.write_text(json.dumps(self._data, indent=2))
