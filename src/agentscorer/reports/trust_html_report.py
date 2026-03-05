from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from agentscorer.trust.models import TrustScanResult


class TrustHTMLReport:
    def __init__(self) -> None:
        self._html: str | None = None

    def generate(self, result: TrustScanResult) -> str:
        score = result.scorecard
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        rows = ""
        for finding in result.findings:
            status = "PASS" if finding.passed else "FAIL"
            rows += (
                "<tr>"
                f"<td>{html.escape(finding.check_id)}</td>"
                f"<td>{html.escape(finding.category.value)}</td>"
                f"<td>{html.escape(finding.severity.value)}</td>"
                f"<td>{status}</td>"
                f"<td>{html.escape(finding.title)}</td>"
                f"<td>{html.escape(finding.summary)}</td>"
                "</tr>"
            )

        self._html = f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
<title>Trust Scan Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
.card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #e2e8f0; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f1f5f9; }}
</style>
</head>
<body>
<div class=\"card\">
<h1>AgentScorer Trust Scan</h1>
<p><strong>Verdict:</strong> {html.escape(score.verdict.value)} &middot; <strong>Checks:</strong> {score.checks_run} &middot; <strong>Findings:</strong> {score.findings_total} &middot; <strong>Generated:</strong> {now}</p>
</div>
<div class=\"card\">
<h2>Findings by Severity</h2>
<ul>
<li>critical: {score.findings_by_severity.get('critical', 0)}</li>
<li>high: {score.findings_by_severity.get('high', 0)}</li>
<li>medium: {score.findings_by_severity.get('medium', 0)}</li>
<li>low: {score.findings_by_severity.get('low', 0)}</li>
<li>info: {score.findings_by_severity.get('info', 0)}</li>
</ul>
</div>
<div class=\"card\">
<h2>Detailed Findings</h2>
<table>
<thead><tr><th>Check</th><th>Category</th><th>Severity</th><th>Status</th><th>Title</th><th>Summary</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</body></html>
"""
        return self._html

    def save(self, path: str | Path) -> None:
        if self._html is None:
            raise RuntimeError("Call generate() before save()")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self._html, errors="surrogatepass")
