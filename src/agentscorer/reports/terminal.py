from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentscorer.models.agent import AgentConfig
from agentscorer.models.score import DetectorSummary, LetterGrade, ScoreCard

GRADE_COLORS = {
    LetterGrade.A: "green",
    LetterGrade.B: "blue",
    LetterGrade.C: "yellow",
    LetterGrade.D: "dark_orange",
    LetterGrade.F: "red",
}


class TerminalReport:
    """Renders a transparent scan report to the terminal using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(
        self,
        scorecard: ScoreCard,
        agent_config: AgentConfig,
        duration: float,
        report_paths: dict[str, str] | None = None,
    ) -> None:
        self.console.print()
        self._render_header(agent_config, scorecard, duration)
        self._render_detector_table(scorecard)
        self._render_failed_tests(scorecard)
        if report_paths:
            self._render_report_paths(report_paths)
        self.console.print()

    def _render_header(
        self, agent_config: AgentConfig, scorecard: ScoreCard, duration: float
    ) -> None:
        grade_color = GRADE_COLORS.get(scorecard.grade, "white")

        header = Text()
        header.append("AgentScorer", style="bold")
        header.append(f" — {agent_config.name}\n", style="")
        header.append(f"{agent_config.url}\n\n", style="dim")

        header.append(f"  {scorecard.grade.value}  ", style=f"bold {grade_color} reverse")
        header.append(f"  {scorecard.grade.label}\n\n", style=grade_color)

        header.append(f"{scorecard.total_tests_run}", style="bold")
        header.append(" tests ran  ")
        if scorecard.total_tests_failed > 0:
            header.append(f"{scorecard.total_tests_failed} failed", style="bold red")
        else:
            header.append("0 failed", style="bold green")
        header.append(f"  {scorecard.total_tests_passed} passed", style="")
        header.append(f"  ({scorecard.pass_rate:.0%} pass rate)", style="dim")
        header.append(f"  {duration:.1f}s", style="dim")

        self.console.print(Panel(header, border_style=grade_color))

    def _render_detector_table(self, scorecard: ScoreCard) -> None:
        table = Table(show_header=True, header_style="bold", title="Results by Detector")
        table.add_column("Detector", min_width=22)
        table.add_column("Ran", justify="right")
        table.add_column("Passed", justify="right")
        table.add_column("Failed", justify="right")
        table.add_column("Status", min_width=8)

        for det in scorecard.detectors:
            if det.tests_failed > 0:
                status = Text("FAIL", style="bold red")
                fail_text = Text(str(det.tests_failed), style="red")
            else:
                status = Text("PASS", style="bold green")
                fail_text = Text("0", style="green")

            table.add_row(
                det.name,
                str(det.tests_run),
                str(det.tests_passed),
                fail_text,
                status,
            )

        self.console.print(table)

    def _render_failed_tests(self, scorecard: ScoreCard) -> None:
        all_failures = []
        for det in scorecard.detectors:
            for ft in det.failed_tests:
                all_failures.append((det.name, ft))

        if not all_failures:
            self.console.print(
                Panel("[green]All tests passed.[/green]", title="Failed Tests")
            )
            return

        table = Table(
            show_header=True,
            header_style="bold",
            title=f"Failed Tests ({len(all_failures)})",
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Detector", min_width=18)
        table.add_column("Test", min_width=28)
        table.add_column("Runs", justify="center", width=6)
        table.add_column("Evidence", min_width=30)

        for i, (det_name, ft) in enumerate(all_failures, 1):
            table.add_row(
                str(i),
                det_name,
                ft.test_name,
                f"{ft.runs_failed}/{ft.runs_total}",
                ft.evidence[:80],
            )

        self.console.print(table)

        # Show details of top failures
        self.console.print()
        shown = min(5, len(all_failures))
        for i, (det_name, ft) in enumerate(all_failures[:shown], 1):
            detail = Text()
            detail.append(f"[{i}] ", style="dim")
            detail.append(f"{det_name}", style="bold")
            detail.append(f" / {ft.test_name}\n")
            detail.append("Sent: ", style="bold dim")
            payload_preview = ft.input_payload[:200]
            if len(ft.input_payload) > 200:
                payload_preview += "..."
            detail.append(f"{payload_preview}\n", style="")
            detail.append("Got:  ", style="bold dim")
            response_preview = ft.output_response[:200]
            if len(ft.output_response) > 200:
                response_preview += "..."
            detail.append(f"{response_preview}\n", style="")
            detail.append("Why:  ", style="bold dim")
            detail.append(f"{ft.evidence}", style="yellow")
            self.console.print(Panel(detail, border_style="red"))

        if len(all_failures) > shown:
            self.console.print(
                f"  [dim]... and {len(all_failures) - shown} more. See full report for details.[/dim]"
            )

    def _render_report_paths(self, paths: dict[str, str]) -> None:
        report_text = Text()
        report_text.append("Reports:\n", style="bold")
        for fmt, path in paths.items():
            report_text.append(f"  {fmt.upper():>5}: ", style="dim")
            report_text.append(f"{path}\n", style="underline")
        self.console.print(Panel(report_text, border_style="dim"))
