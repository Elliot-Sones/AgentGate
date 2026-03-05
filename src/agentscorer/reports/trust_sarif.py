from __future__ import annotations

import json
from pathlib import Path

from agentscorer.trust.models import TrustScanResult


LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class TrustSARIFReport:
    def __init__(self) -> None:
        self._data: dict | None = None

    def generate(self, result: TrustScanResult) -> dict:
        rules: dict[str, dict] = {}
        sarif_results: list[dict] = []

        for finding in result.findings:
            if finding.passed:
                continue
            rule_id = f"TS-{finding.check_id.upper()}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "defaultConfiguration": {
                        "level": LEVEL_MAP.get(finding.severity.value, "warning")
                    },
                }

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": LEVEL_MAP.get(finding.severity.value, "warning"),
                    "message": {"text": f"{finding.title}: {finding.summary}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.location_path or "submission"},
                                "region": {"startLine": max(finding.location_line, 1)},
                            }
                        }
                    ],
                    "properties": {
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                        "checkId": finding.check_id,
                        "confidence": finding.confidence,
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
                            "name": "AgentScorer Trust",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                    "properties": {
                        "verdict": result.scorecard.verdict.value,
                        "checksRun": result.scorecard.checks_run,
                        "findingsTotal": result.scorecard.findings_total,
                    },
                }
            ],
        }
        return self._data

    def save(self, path: str | Path) -> None:
        if self._data is None:
            raise RuntimeError("Call generate() before save()")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._data, indent=2), errors="surrogatepass")
