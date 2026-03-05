from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agentscorer.models.agent import AgentConfig
from agentscorer.models.score import ScoreCard


class JSONReport:
    """Generates a machine-readable JSON scan report — transparent pass/fail."""

    def __init__(self) -> None:
        self._data: dict | None = None

    def generate(
        self,
        scorecard: ScoreCard,
        agent_config: AgentConfig,
        duration: float,
        budget: dict | None = None,
    ) -> str:
        self._data = {
            "agent": {
                "name": agent_config.name,
                "url": agent_config.url,
                "description": agent_config.description,
                "type": agent_config.agent_type,
            },
            "summary": {
                "grade": scorecard.grade.value,
                "grade_label": scorecard.grade.label,
                "total_tests_run": scorecard.total_tests_run,
                "total_tests_passed": scorecard.total_tests_passed,
                "total_tests_failed": scorecard.total_tests_failed,
                "pass_rate": scorecard.pass_rate,
            },
            "detectors": [
                {
                    "name": det.name,
                    "tests_run": det.tests_run,
                    "tests_passed": det.tests_passed,
                    "tests_failed": det.tests_failed,
                    "failed_tests": [
                        {
                            "test_name": ft.test_name,
                            "test_case_id": ft.test_case_id,
                            "input_payload": ft.input_payload,
                            "output_response": ft.output_response,
                            "evidence": ft.evidence,
                            "confidence": ft.confidence,
                            "evaluation_method": ft.evaluation_method,
                            "runs_failed": ft.runs_failed,
                            "runs_total": ft.runs_total,
                        }
                        for ft in det.failed_tests
                    ],
                }
                for det in scorecard.detectors
            ],
            "metadata": {
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(duration, 2),
                "budget": budget or {},
                "version": "1.0.0",
            },
        }
        return json.dumps(self._data, indent=2)

    def save(self, path: str | Path) -> None:
        if self._data is None:
            raise RuntimeError("Call generate() before save()")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), errors="surrogatepass")
