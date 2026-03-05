from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentscorer.trust.models import TrustScanResult, TrustVerdict


VERDICT_COLOR = {
    TrustVerdict.ALLOW_CLEAN: "green",
    TrustVerdict.ALLOW_WITH_WARNINGS: "yellow",
    TrustVerdict.MANUAL_REVIEW: "dark_orange",
    TrustVerdict.BLOCK: "red",
}


class TrustTerminalReport:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: TrustScanResult, report_paths: dict[str, str] | None = None) -> None:
        score = result.scorecard
        color = VERDICT_COLOR.get(score.verdict, "white")

        header = (
            f"[bold]AgentScorer Trust Scan[/bold]\n"
            f"Verdict: [{color}]{score.verdict.value}[/{color}]\n"
            f"Checks: {score.checks_run}  Failed checks: {score.checks_failed}\n"
            f"Findings: {score.findings_total}  Duration: {score.duration_seconds:.1f}s"
        )
        self.console.print(Panel(header, border_style=color))

        sev_table = Table(title="Findings by Severity", show_header=True, header_style="bold")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for sev, count in score.findings_by_severity.items():
            sev_table.add_row(sev, str(count))
        self.console.print(sev_table)

        failed = [f for f in result.findings if not f.passed]
        if failed:
            table = Table(title=f"Failed Findings ({len(failed)})", show_header=True, header_style="bold")
            table.add_column("Check", min_width=18)
            table.add_column("Severity", min_width=8)
            table.add_column("Title", min_width=30)
            table.add_column("Summary", min_width=35)
            for finding in failed[:25]:
                table.add_row(
                    finding.check_id,
                    finding.severity.value,
                    finding.title,
                    finding.summary[:180],
                )
            self.console.print(table)
        else:
            self.console.print(Panel("[green]No failed findings.[/green]", border_style="green"))

        if report_paths:
            lines = ["[bold]Reports[/bold]"]
            for fmt, path in report_paths.items():
                lines.append(f"{fmt.upper():>5}: {path}")
            self.console.print(Panel("\n".join(lines), border_style="dim"))
