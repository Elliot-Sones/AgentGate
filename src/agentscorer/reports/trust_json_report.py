from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agentscorer.trust.models import TrustScanResult


class TrustJSONReport:
    def __init__(self) -> None:
        self._data: dict | None = None

    def generate(self, result: TrustScanResult) -> str:
        self._data = {
            "summary": {
                "verdict": result.scorecard.verdict.value,
                "checks_run": result.scorecard.checks_run,
                "checks_failed": result.scorecard.checks_failed,
                "checks_passed": result.scorecard.checks_passed,
                "findings_total": result.scorecard.findings_total,
                "findings_by_severity": result.scorecard.findings_by_severity,
                "duration_seconds": result.scorecard.duration_seconds,
                "policy_version": result.scorecard.policy_version,
            },
            "findings": [
                {
                    "id": f.id,
                    "check_id": f.check_id,
                    "title": f.title,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "passed": f.passed,
                    "confidence": f.confidence,
                    "summary": f.summary,
                    "recommendation": f.recommendation,
                    "location_path": f.location_path,
                    "location_line": f.location_line,
                    "expected": f.expected,
                    "observed": f.observed,
                    "evidence": [e.model_dump() for e in f.evidence],
                }
                for f in result.findings
            ],
            "metadata": {
                "scan_date": datetime.now(timezone.utc).isoformat(),
                **result.metadata,
            },
            "artifacts_manifest": [a.model_dump() for a in result.artifacts_manifest],
        }
        return json.dumps(self._data, indent=2)

    def save(self, path: str | Path) -> None:
        if self._data is None:
            raise RuntimeError("Call generate() before save()")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), errors="surrogatepass")
