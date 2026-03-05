from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from agentscorer.models.agent import AgentConfig
from agentscorer.models.score import LetterGrade, ScoreCard

GRADE_COLORS_HEX = {
    LetterGrade.A: "#22c55e",
    LetterGrade.B: "#3b82f6",
    LetterGrade.C: "#eab308",
    LetterGrade.D: "#f97316",
    LetterGrade.F: "#ef4444",
}


class HTMLReport:
    """Generates a self-contained HTML report — transparent pass/fail per detector."""

    def __init__(self) -> None:
        self._html: str | None = None

    def generate(
        self,
        scorecard: ScoreCard,
        agent_config: AgentConfig,
        duration: float,
        budget: dict | None = None,
    ) -> str:
        grade_color = GRADE_COLORS_HEX.get(scorecard.grade, "#9ca3af")
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        esc = html.escape

        # Detector summary table
        detector_rows = ""
        for det in scorecard.detectors:
            status_color = "#ef4444" if det.tests_failed > 0 else "#22c55e"
            status_text = "FAIL" if det.tests_failed > 0 else "PASS"
            fail_style = f'style="color:#ef4444;font-weight:600"' if det.tests_failed > 0 else ""
            detector_rows += f"""
            <tr>
                <td>{esc(det.name)}</td>
                <td>{det.tests_run}</td>
                <td>{det.tests_passed}</td>
                <td {fail_style}>{det.tests_failed}</td>
                <td><span class="status-badge" style="background:{status_color}">{status_text}</span></td>
            </tr>"""

        # Failed tests — grouped by detector
        failed_sections = ""
        total_failures = 0
        for det in scorecard.detectors:
            if not det.failed_tests:
                continue
            total_failures += len(det.failed_tests)

            cards = ""
            for ft in det.failed_tests:
                cards += f"""
                <div class="finding-card">
                    <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
                        <span class="finding-name">{esc(ft.test_name)}</span>
                        <span class="finding-runs">{ft.runs_failed}/{ft.runs_total} failed</span>
                        <span class="chevron">&#9660;</span>
                    </div>
                    <div class="finding-body">
                        <div class="code-section">
                            <p><strong>Sent:</strong></p>
                            <pre><code>{esc(ft.input_payload)}</code></pre>
                        </div>
                        <div class="code-section">
                            <p><strong>Got back:</strong></p>
                            <pre><code>{esc(ft.output_response[:2000])}</code></pre>
                        </div>
                        <div class="code-section">
                            <p><strong>Why it failed:</strong></p>
                            <pre><code>{esc(ft.evidence)}</code></pre>
                        </div>
                        <p class="meta-line">Confidence: {ft.confidence:.0%} &middot; Method: {esc(ft.evaluation_method)}</p>
                    </div>
                </div>"""

            failed_sections += f"""
            <div class="detector-failures">
                <h3>{esc(det.name)} — {det.tests_failed} failed</h3>
                {cards}
            </div>"""

        if not failed_sections:
            failed_sections = '<p class="all-pass">All tests passed.</p>'

        budget_html = ""
        if budget:
            budget_html = f"""
            <div class="meta-section">
                <h3>Budget</h3>
                <p>Agent calls: {budget.get('agent_calls_used', 0)} / {budget.get('max_agent_calls', 'N/A')}</p>
                <p>LLM judge calls: {budget.get('llm_judge_calls_used', 0)} / {budget.get('max_llm_judge_calls', 'N/A')}</p>
            </div>"""

        self._html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentScorer Report — {esc(agent_config.name)}</title>
<style>
:root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --text-dim: #94a3b8; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 960px; margin: 0 auto; }}
h2, h3 {{ margin-bottom: 0.5rem; }}
.header {{ display: flex; align-items: center; gap: 1.5rem; margin-bottom: 2rem; padding: 1.5rem; background: var(--surface); border-radius: 12px; border: 1px solid var(--border); }}
.grade-badge {{ font-size: 3rem; font-weight: 900; width: 5rem; height: 5rem; display: flex; align-items: center; justify-content: center; border-radius: 12px; color: #fff; }}
.header-info h1 {{ font-size: 1.5rem; }}
.header-info p {{ color: var(--text-dim); font-size: 0.9rem; }}
.summary-stats {{ font-size: 1.1rem; margin-top: 0.5rem; }}
.summary-stats .failed {{ color: #ef4444; font-weight: 700; }}
.summary-stats .passed {{ color: #22c55e; font-weight: 700; }}
.section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; }}
.status-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; color: #fff; font-size: 0.75rem; font-weight: 700; }}
.detector-failures {{ margin-bottom: 1.5rem; }}
.detector-failures h3 {{ color: #ef4444; margin-bottom: 0.5rem; }}
.finding-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 0.5rem; overflow: hidden; }}
.finding-header {{ display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; cursor: pointer; }}
.finding-header:hover {{ background: rgba(255,255,255,0.03); }}
.finding-name {{ font-weight: 600; flex: 1; }}
.finding-runs {{ color: #ef4444; font-size: 0.85rem; font-weight: 600; }}
.chevron {{ color: var(--text-dim); font-size: 0.7rem; transition: transform 0.2s; }}
.finding-card.open .chevron {{ transform: rotate(180deg); }}
.finding-body {{ display: none; padding: 1rem; border-top: 1px solid var(--border); }}
.finding-card.open .finding-body {{ display: block; }}
.code-section {{ margin: 0.75rem 0; }}
pre {{ background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word; }}
.meta-line {{ color: var(--text-dim); font-size: 0.8rem; margin-top: 0.5rem; }}
.meta-section p {{ color: var(--text-dim); font-size: 0.9rem; }}
.all-pass {{ color: #22c55e; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="grade-badge" style="background:{grade_color}">{scorecard.grade.value}</div>
        <div class="header-info">
            <h1>{esc(agent_config.name)}</h1>
            <p>{esc(agent_config.url)} &middot; {scan_date} &middot; {duration:.1f}s</p>
            <div class="summary-stats">
                <span>{scorecard.total_tests_run} tests ran</span> &middot;
                <span class="passed">{scorecard.total_tests_passed} passed</span> &middot;
                <span class="{'failed' if scorecard.total_tests_failed > 0 else 'passed'}">{scorecard.total_tests_failed} failed</span>
                &middot; {scorecard.pass_rate:.0%} pass rate
            </div>
            <p>{esc(scorecard.grade.label)}</p>
        </div>
    </div>

    <div class="section">
        <h2>Results by Detector</h2>
        <table>
            <thead><tr><th>Detector</th><th>Ran</th><th>Passed</th><th>Failed</th><th>Status</th></tr></thead>
            <tbody>{detector_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>Failed Tests ({total_failures})</h2>
        {failed_sections}
    </div>

    <div class="section">
        <div class="meta-section">
            <h3>Scan Metadata</h3>
            <p>Duration: {duration:.1f}s &middot; Grade: {scorecard.grade.value} ({scorecard.grade.label})</p>
        </div>
        {budget_html}
    </div>
</div>
<script>
</script>
</body>
</html>"""
        return self._html

    def save(self, path: str | Path) -> None:
        if self._html is None:
            raise RuntimeError("Call generate() before save()")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._html, errors="surrogatepass")
