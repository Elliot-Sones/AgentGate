from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agentscorer.adapters.openai_chat import OpenAIChatAdapter
from agentscorer.config import ScanBudget, ScanConfig
from agentscorer.detectors import DETECTOR_REGISTRY
from agentscorer.models.agent import AgentConfig
from agentscorer.reports.html_report import HTMLReport
from agentscorer.reports.json_report import JSONReport
from agentscorer.reports.sarif import SARIFReport
from agentscorer.reports.terminal import TerminalReport
from agentscorer.reports.trust_html_report import TrustHTMLReport
from agentscorer.reports.trust_json_report import TrustJSONReport
from agentscorer.reports.trust_sarif import TrustSARIFReport
from agentscorer.reports.trust_terminal import TrustTerminalReport
from agentscorer.scanner import ProbeError, Scanner
from agentscorer.trust.config import TrustScanConfig
from agentscorer.trust.policy import TrustPolicy
from agentscorer.trust.scanner import TrustScanner

console = Console()


@click.group()
@click.version_option(package_name="agentscorer")
def cli() -> None:
    """AgentScorer — Autonomous AI Agent Stress-Tester."""


@cli.command()
@click.argument("url")
@click.option("--name", default="Unnamed Agent", help="Name for the target agent.")
@click.option("--auth-header", default=None, help="Auth header as 'Key: Value'.")
@click.option(
    "--format",
    "output_format",
    default="all",
    type=click.Choice(["terminal", "json", "html", "sarif", "all"], case_sensitive=False),
    help="Report format(s) to generate.",
)
@click.option("--output", default=".", help="Output directory for report files.")
@click.option("--budget", default=500, type=int, help="Max agent calls budget.")
@click.option("--only", default=None, help="Comma-separated detector names to run.")
@click.option("--description", default="", help="Description of the target agent.")
@click.option("--request-field", default="question", help="JSON field for request payload.")
@click.option("--response-field", default="answer", help="JSON field in agent response.")
@click.option(
    "--adapter",
    default="http",
    type=click.Choice(["http", "openai"], case_sensitive=False),
    help="Adapter type for communicating with the agent.",
)
@click.option("--model", default="gpt-4", help="Model name for OpenAI-format adapters.")
@click.option("--converters/--no-converters", default=False, help="Apply payload encoding/obfuscation.")
@click.option("--fail-below", default=None, type=float, help="Exit code 1 if pass rate below threshold (0.0-1.0).")
@click.option("--quiet", is_flag=True, help="Suppress terminal output, only return exit code.")
@click.option("--adaptive/--no-adaptive", default=False, help="Enable PAIR-style adaptive attacks (requires ANTHROPIC_API_KEY).")
@click.option("--adaptive-turns", default=5, type=int, help="Max turns per adaptive attack.")
@click.option(
    "--attack-strategy",
    default="pair",
    type=click.Choice(["pair", "crescendo", "tap"], case_sensitive=False),
    help="Attack strategy for adaptive attacks.",
)
@click.option(
    "--eval-mode",
    default="heuristic",
    type=click.Choice(["heuristic", "judge"], case_sensitive=False),
    help="Evaluation method. 'judge' uses LLM for all results (requires ANTHROPIC_API_KEY).",
)
def scan(
    url: str,
    name: str,
    auth_header: str | None,
    output_format: str,
    output: str,
    budget: int,
    only: str | None,
    description: str,
    request_field: str,
    response_field: str,
    adapter: str,
    model: str,
    fail_below: float | None,
    quiet: bool,
    converters: bool,
    adaptive: bool,
    adaptive_turns: int,
    attack_strategy: str,
    eval_mode: str,
) -> None:
    """Scan an AI agent at URL for security vulnerabilities."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    agent_config = AgentConfig(
        url=url,
        name=name,
        description=description,
        auth_header=auth_header,
        request_field=request_field,
        response_field=response_field,
    )

    detectors_list = [d.strip() for d in only.split(",")] if only else None

    scan_config = ScanConfig(
        budget=ScanBudget(max_agent_calls=budget),
        detectors=detectors_list,
        evaluation_mode=eval_mode,
        enable_converters=converters,
        enable_adaptive_attacks=adaptive,
        adaptive_max_turns=adaptive_turns,
        attack_strategy=attack_strategy,
    )

    # Build adapter based on --adapter choice
    agent_adapter = None
    if adapter == "openai":
        agent_adapter = OpenAIChatAdapter(
            config=agent_config,
            model=model,
            timeout=scan_config.timeout_seconds,
            max_retries=scan_config.max_retries,
        )

    scanner = Scanner(
        agent_config=agent_config,
        scan_config=scan_config,
        adapter=agent_adapter,
    )

    if not quiet:
        console.print(f"\n[bold]AgentScorer[/bold] scanning [cyan]{url}[/cyan] ...\n")

    try:
        result = asyncio.run(scanner.run())
    except ProbeError as exc:
        console.print(f"\n[red]Probe failed:[/red] {exc}")
        console.print("[dim]Tip: verify the URL is correct and the service is running.[/dim]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Scan failed:[/red] {exc}")
        sys.exit(1)

    budget_info = {
        "max_agent_calls": scan_config.budget.max_agent_calls,
        "agent_calls_used": scan_config.budget.agent_calls_used,
        "max_llm_judge_calls": scan_config.budget.max_llm_judge_calls,
        "llm_judge_calls_used": scan_config.budget.llm_judge_calls_used,
    }

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_paths: dict[str, str] = {}

    formats = (
        ["terminal", "json", "html", "sarif"] if output_format == "all" else [output_format]
    )

    if "json" in formats:
        jr = JSONReport()
        jr.generate(result.scorecard, agent_config, result.duration, budget_info)
        json_path = output_dir / f"{_safe_name(name)}_report.json"
        jr.save(json_path)
        report_paths["json"] = str(json_path)

    if "html" in formats:
        hr = HTMLReport()
        hr.generate(result.scorecard, agent_config, result.duration, budget_info)
        html_path = output_dir / f"{_safe_name(name)}_report.html"
        hr.save(html_path)
        report_paths["html"] = str(html_path)

    if "sarif" in formats:
        sr = SARIFReport()
        sr.generate(result.scorecard, agent_config, result.duration, budget_info)
        sarif_path = output_dir / f"{_safe_name(name)}_report.sarif"
        sr.save(sarif_path)
        report_paths["sarif"] = str(sarif_path)

    if "terminal" in formats and not quiet:
        tr = TerminalReport(console=console)
        tr.render(result.scorecard, agent_config, result.duration, report_paths)

    # CI/CD gate: exit with code 1 if pass rate is below threshold
    if fail_below is not None and result.scorecard.pass_rate < fail_below:
        if not quiet:
            console.print(
                f"\n[red]FAIL:[/red] Pass rate {result.scorecard.pass_rate:.1%} "
                f"is below threshold {fail_below:.1%}"
            )
        sys.exit(1)


@cli.command("trust-scan")
@click.option(
    "--source-dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Source directory for static trust checks.",
)
@click.option("--image", required=True, help="Container image reference to analyze.")
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to trust manifest (JSON/YAML). Defaults to <source-dir>/trust_manifest.yaml.",
)
@click.option(
    "--format",
    "output_format",
    default="all",
    type=click.Choice(["terminal", "json", "html", "sarif", "all"], case_sensitive=False),
    help="Report format(s) to generate.",
)
@click.option("--output", default=".", help="Output directory for report files.")
@click.option(
    "--profile",
    default="both",
    type=click.Choice(["review", "prodlike", "both"], case_sensitive=False),
    help="Runtime profile(s) to execute.",
)
@click.option("--runtime-seconds", default=180, type=int, help="Max runtime per profile.")
@click.option(
    "--egress-allowlist",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="File containing allowlisted domains (one per line).",
)
@click.option(
    "--canary-profile",
    default="standard",
    type=click.Choice(["minimal", "standard", "strict"], case_sensitive=False),
    help="Canary token profile to seed in runtime checks.",
)
@click.option(
    "--fail-on",
    default="manual_review",
    type=click.Choice(["allow_with_warnings", "manual_review", "block"], case_sensitive=False),
    help="Exit code 1 when verdict is at or above this threshold.",
)
@click.option(
    "--agentdojo-suite",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help="Optional AgentDojo suite path for trust scenario integration.",
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output, only return exit code.")
def trust_scan(
    source_dir: Path | None,
    image: str,
    manifest: Path | None,
    output_format: str,
    output: str,
    profile: str,
    runtime_seconds: int,
    egress_allowlist: Path | None,
    canary_profile: str,
    fail_on: str,
    agentdojo_suite: Path | None,
    quiet: bool,
) -> None:
    """Run Phase 2 trust and malware-style analysis for marketplace submissions."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if manifest is None and source_dir is not None:
        manifest = source_dir / "trust_manifest.yaml"

    config = TrustScanConfig(
        source_dir=source_dir,
        image_ref=image,
        manifest_path=manifest,
        output_dir=output_dir,
        profile=profile,
        runtime_seconds=runtime_seconds,
        egress_allowlist_path=egress_allowlist,
        canary_profile=canary_profile,
        fail_on=fail_on,
        quiet=quiet,
        agentdojo_suite=agentdojo_suite,
    )

    if not quiet:
        console.print(
            f"\n[bold]AgentScorer[/bold] trust-scanning image [cyan]{image}[/cyan] ...\n"
        )

    scanner = TrustScanner(config=config)
    try:
        result = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Trust scan interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Trust scan failed:[/red] {exc}")
        sys.exit(1)

    report_paths: dict[str, str] = {}
    formats = (
        ["terminal", "json", "html", "sarif"] if output_format == "all" else [output_format]
    )

    if "json" in formats:
        jr = TrustJSONReport()
        jr.generate(result)
        json_path = output_dir / "trust_scan_report.json"
        jr.save(json_path)
        report_paths["json"] = str(json_path)

    if "html" in formats:
        hr = TrustHTMLReport()
        hr.generate(result)
        html_path = output_dir / "trust_scan_report.html"
        hr.save(html_path)
        report_paths["html"] = str(html_path)

    if "sarif" in formats:
        sr = TrustSARIFReport()
        sr.generate(result)
        sarif_path = output_dir / "trust_scan_report.sarif"
        sr.save(sarif_path)
        report_paths["sarif"] = str(sarif_path)

    if "terminal" in formats and not quiet:
        tr = TrustTerminalReport(console=console)
        tr.render(result, report_paths)

    policy = TrustPolicy(version=config.policy_version)
    if policy.should_fail(result.scorecard.verdict, fail_on):
        if not quiet:
            console.print(
                f"\n[red]FAIL:[/red] Trust verdict {result.scorecard.verdict.value} "
                f"meets/exceeds fail-on threshold {fail_on}"
            )
        sys.exit(1)


@cli.command("list-detectors")
def list_detectors() -> None:
    """List all available security detectors."""
    table = Table(title="Available Detectors", show_header=True, header_style="bold")
    table.add_column("Name", min_width=22)
    table.add_column("Class")
    table.add_column("Module")

    for name, cls in sorted(DETECTOR_REGISTRY.items()):
        table.add_row(name, cls.__name__, cls.__module__)

    console.print(table)


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name).lower()
