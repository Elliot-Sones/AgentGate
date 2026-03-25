from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from agentgate.adapters.openai_chat import OpenAIChatAdapter
from agentgate.config import ScanBudget, ScanConfig
from agentgate.detectors import DETECTOR_REGISTRY
from agentgate.models.agent import AgentConfig
from agentgate.progress import ScanProgressDisplay
from agentgate.reports.html_report import HTMLReport
from agentgate.reports.json_report import JSONReport
from agentgate.reports.report_enricher import ReportEnricher
from agentgate.reports.sarif import SARIFReport
from agentgate.reports.terminal import TerminalReport
from agentgate.reports.trust_html_report import TrustHTMLReport
from agentgate.reports.trust_json_report import TrustJSONReport
from agentgate.reports.trust_sarif import TrustSARIFReport
from agentgate.reports.trust_terminal import TrustTerminalReport
from agentgate.scanner import ProbeError, Scanner
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.runtime.railway_discovery import (
    RailwayDiscoveryError,
    build_manifest_from_railway,
    discover_railway_runtime,
    dump_manifest_yaml,
    load_manifest_file,
)
from agentgate.trust.scanner import TrustScanner

console = Console()


@click.group()
@click.version_option(package_name="agentgate")
def cli() -> None:
    """AgentGate — Autonomous AI Agent Stress-Tester."""


@cli.command("security-scan")
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
def security_scan(
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
    """Run only the red-team security scan (no trust analysis)."""
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

    # Build progress display
    detector_names = detectors_list or list(DETECTOR_REGISTRY.keys())
    progress = ScanProgressDisplay(detector_names, mode="scan") if not quiet else None

    scanner = Scanner(
        agent_config=agent_config,
        scan_config=scan_config,
        adapter=agent_adapter,
        progress=progress,
    )

    if not quiet:
        console.print(f"\n[bold]AgentGate[/bold] scanning [cyan]{url}[/cyan] ...\n")

    try:
        if progress is not None:
            # Suppress logging while Live display is active — log messages
            # break Rich's cursor positioning, causing duplicated rows.
            _prev_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with Live(progress, console=console, refresh_per_second=8):
                    result = asyncio.run(scanner.run())
            finally:
                logging.disable(_prev_disable)
        else:
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
@click.option("--url", default="", help="Live hosted agent URL for hosted trust runtime checks.")
@click.option(
    "--source-dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Source directory for static trust checks.",
)
@click.option(
    "--railway-discover/--no-railway-discover",
    default=False,
    help="Discover dependencies and runtime env from a linked Railway workspace.",
)
@click.option("--railway-service", default=None, help="Target Railway service name.")
@click.option("--railway-environment", default=None, help="Target Railway environment name.")
@click.option(
    "--railway-workspace-id",
    default="",
    help="Optional Railway workspace ID for temporary project creation.",
)
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
@click.option(
    "--report-profile",
    default="standard",
    type=click.Choice(["standard", "promptshop"], case_sensitive=False),
    help="Presentation profile for trust reports.",
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
@click.option(
    "--strict-production-contract/--no-strict-production-contract",
    default=False,
    help="Fail fast when source submissions do not meet the Dockerfile + HTTP production contract.",
)
@click.option(
    "--keep-environment-on-failure/--cleanup-environment-on-failure",
    default=False,
    help="Keep the temporary Railway environment for debugging when deployment or runtime checks fail.",
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output, only return exit code.")
def trust_scan(
    url: str,
    source_dir: Path | None,
    railway_discover: bool,
    railway_service: str | None,
    railway_environment: str | None,
    railway_workspace_id: str,
    manifest: Path | None,
    output_format: str,
    output: str,
    profile: str,
    report_profile: str,
    runtime_seconds: int,
    egress_allowlist: Path | None,
    canary_profile: str,
    fail_on: str,
    agentdojo_suite: Path | None,
    strict_production_contract: bool,
    keep_environment_on_failure: bool,
    quiet: bool,
) -> None:
    """Run Phase 2 trust and malware-style analysis for marketplace submissions."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not url.strip() and source_dir is None:
        console.print(
            "\n[red]Trust scan requires either --url for an already hosted agent "
            "or --source-dir for a deployable source submission.[/red]"
        )
        sys.exit(1)

    if manifest is None and source_dir is not None:
        manifest = source_dir / "trust_manifest.yaml"

    if railway_discover:
        workspace_dir = source_dir or Path.cwd()
        try:
            manifest = _prepare_railway_manifest(
                workspace_dir=workspace_dir,
                source_dir=source_dir,
                output_dir=output_dir,
                manifest_path=manifest,
                service=railway_service,
                environment=railway_environment,
            )
        except RailwayDiscoveryError as exc:
            console.print(f"\n[red]Railway discovery failed:[/red] {exc}")
            sys.exit(1)
        if not quiet:
            console.print(
                f"[dim]Using Railway-enriched manifest: {manifest}[/dim]\n"
            )

    config = TrustScanConfig(
        source_dir=source_dir,
        image_ref="",
        manifest_path=manifest,
        output_dir=output_dir,
        profile=profile,
        report_profile=report_profile,
        runtime_seconds=runtime_seconds,
        egress_allowlist_path=egress_allowlist,
        canary_profile=canary_profile,
        fail_on=fail_on,
        quiet=quiet,
        agentdojo_suite=agentdojo_suite,
        hosted_url=url.strip(),
        railway_workspace_dir=(source_dir or Path.cwd()) if railway_discover else None,
        railway_workspace_id=railway_workspace_id.strip(),
        railway_service=railway_service or "",
        railway_environment=railway_environment or "",
        strict_production_contract=strict_production_contract,
        keep_environment_on_failure=keep_environment_on_failure,
    )

    if not quiet:
        if url.strip():
            console.print(
                f"\n[bold]AgentGate[/bold] trust-scanning "
                f"[cyan]{url.strip()}[/cyan] ...\n"
            )
        else:
            console.print(
                "\n[bold]AgentGate[/bold] preflighting, deploying, and trust-scanning "
                f"submission source at [cyan]{source_dir}[/cyan] ...\n"
            )

    # Build trust progress display from default checks
    from agentgate.trust.checks import default_trust_checks as _default_trust_checks

    trust_checks = _default_trust_checks()
    trust_progress = (
        ScanProgressDisplay([c.check_id for c in trust_checks], mode="trust")
        if not quiet
        else None
    )

    scanner = TrustScanner(config=config, checks=trust_checks, progress=trust_progress)
    try:
        if trust_progress is not None:
            _prev_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with Live(trust_progress, console=console, refresh_per_second=8):
                    result = asyncio.run(scanner.run())
            finally:
                logging.disable(_prev_disable)
        else:
            result = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Trust scan interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Trust scan failed:[/red] {exc}")
        sys.exit(1)

    result = ReportEnricher(
        api_key=config.anthropic_api_key,
        model=config.report_enrichment_model,
        enabled=config.enable_report_enrichment,
    ).enrich(result)

    report_paths: dict[str, str] = {}
    formats = (
        ["terminal", "json", "html", "sarif"] if output_format == "all" else [output_format]
    )

    if "json" in formats:
        jr = TrustJSONReport()
        jr.generate(result, profile=config.report_profile)
        json_path = output_dir / "trust_scan_report.json"
        jr.save(json_path)
        report_paths["json"] = str(json_path)

    if "html" in formats:
        hr = TrustHTMLReport()
        hr.generate(result, profile=config.report_profile)
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


@cli.command()
@click.argument("url")
@click.option(
    "--railway-discover/--no-railway-discover",
    default=False,
    help="Discover dependencies and runtime env from a linked Railway workspace.",
)
@click.option("--railway-service", default=None, help="Target Railway service name.")
@click.option("--railway-environment", default=None, help="Target Railway environment name.")
@click.option(
    "--source-dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Source directory for static trust checks.",
)
@click.option(
    "--manifest",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to trust manifest (JSON/YAML). Defaults to <source-dir>/trust_manifest.yaml.",
)
@click.option("--name", default="Unnamed Agent", help="Name for the target agent.")
@click.option("--auth-header", default=None, help="Auth header as 'Key: Value'.")
@click.option(
    "--format",
    "output_format",
    default="all",
    type=click.Choice(["terminal", "json", "html", "all"], case_sensitive=False),
    help="Report format(s) to generate.",
)
@click.option("--output", default=".", help="Output directory for report files.")
@click.option("--budget", default=500, type=int, help="Max agent calls budget.")
@click.option("--only", default=None, help="Comma-separated detector names to run (security scan).")
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
@click.option("--adaptive/--no-adaptive", default=False, help="Enable PAIR-style adaptive attacks.")
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
    help="Evaluation method for security scan.",
)
@click.option(
    "--report-profile",
    default="promptshop",
    type=click.Choice(["standard", "promptshop"], case_sensitive=False),
    help="Presentation profile for the unified report.",
)
@click.option(
    "--profile",
    default="both",
    type=click.Choice(["review", "prodlike", "both"], case_sensitive=False),
    help="Runtime profile(s) for trust scan.",
)
@click.option("--runtime-seconds", default=180, type=int, help="Max runtime per trust profile.")
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
    help="Canary token profile for trust runtime checks.",
)
@click.option(
    "--fail-on",
    default="manual_review",
    type=click.Choice(["allow_with_warnings", "manual_review", "block"], case_sensitive=False),
    help="Exit code 1 when trust verdict meets/exceeds this threshold.",
)
@click.option("--fail-below", default=None, type=float, help="Exit code 1 if security pass rate below threshold (0.0-1.0).")
@click.option("--quiet", is_flag=True, help="Suppress terminal output.")
def scan(
    url: str,
    railway_discover: bool,
    railway_service: str | None,
    railway_environment: str | None,
    source_dir: Path | None,
    manifest: Path | None,
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
    converters: bool,
    adaptive: bool,
    adaptive_turns: int,
    attack_strategy: str,
    eval_mode: str,
    report_profile: str,
    profile: str,
    runtime_seconds: int,
    egress_allowlist: Path | None,
    canary_profile: str,
    fail_on: str,
    fail_below: float | None,
    quiet: bool,
) -> None:
    """Scan an AI agent — runs security + trust analysis and produces a unified report."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ---- Phase 1: Red-team security scan ----
    if not quiet:
        console.print(f"\n[bold]AgentGate[/bold] review — Phase 1: security scan on [cyan]{url}[/cyan] ...\n")

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

    agent_adapter = None
    if adapter == "openai":
        agent_adapter = OpenAIChatAdapter(
            config=agent_config,
            model=model,
            timeout=scan_config.timeout_seconds,
            max_retries=scan_config.max_retries,
        )

    detector_names = detectors_list or list(DETECTOR_REGISTRY.keys())
    sec_progress = ScanProgressDisplay(detector_names, mode="scan") if not quiet else None

    scanner = Scanner(
        agent_config=agent_config,
        scan_config=scan_config,
        adapter=agent_adapter,
        progress=sec_progress,
    )

    try:
        if sec_progress is not None:
            _prev_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with Live(sec_progress, console=console, refresh_per_second=8):
                    scan_result = asyncio.run(scanner.run())
            finally:
                logging.disable(_prev_disable)
        else:
            scan_result = asyncio.run(scanner.run())
    except ProbeError as exc:
        console.print(f"\n[red]Security scan probe failed:[/red] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Review interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Security scan failed:[/red] {exc}")
        sys.exit(1)

    if not quiet:
        console.print("[green]Phase 1 complete.[/green]\n")

    # ---- Phase 2: Trust scan ----
    if not quiet:
        console.print(f"[bold]AgentGate[/bold] review — Phase 2: trust scan on [cyan]{url}[/cyan] ...\n")

    if manifest is None and source_dir is not None:
        manifest = source_dir / "trust_manifest.yaml"

    if railway_discover:
        workspace_dir = source_dir or Path.cwd()
        try:
            manifest = _prepare_railway_manifest(
                workspace_dir=workspace_dir,
                source_dir=source_dir,
                output_dir=output_dir,
                manifest_path=manifest,
                service=railway_service,
                environment=railway_environment,
            )
        except RailwayDiscoveryError as exc:
            console.print(f"\n[red]Railway discovery failed:[/red] {exc}")
            sys.exit(1)
        if not quiet:
            console.print(
                f"[dim]Using Railway-enriched manifest: {manifest}[/dim]\n"
            )

    trust_config = TrustScanConfig(
        source_dir=source_dir,
        image_ref="",
        manifest_path=manifest,
        output_dir=output_dir,
        profile=profile,
        report_profile=report_profile,
        runtime_seconds=runtime_seconds,
        egress_allowlist_path=egress_allowlist,
        canary_profile=canary_profile,
        fail_on=fail_on,
        quiet=quiet,
        hosted_url=url.strip(),
        railway_workspace_dir=(source_dir or Path.cwd()) if railway_discover else None,
        railway_service=railway_service or "",
        railway_environment=railway_environment or "",
    )

    from agentgate.trust.checks import default_trust_checks as _default_trust_checks

    trust_checks = _default_trust_checks()
    trust_progress = (
        ScanProgressDisplay([c.check_id for c in trust_checks], mode="trust")
        if not quiet
        else None
    )

    trust_scanner = TrustScanner(config=trust_config, checks=trust_checks, progress=trust_progress)
    try:
        if trust_progress is not None:
            _prev_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with Live(trust_progress, console=console, refresh_per_second=8):
                    trust_result = asyncio.run(trust_scanner.run())
            finally:
                logging.disable(_prev_disable)
        else:
            trust_result = asyncio.run(trust_scanner.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Review interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Trust scan failed:[/red] {exc}")
        sys.exit(1)

    trust_result = ReportEnricher(
        api_key=trust_config.anthropic_api_key,
        model=trust_config.report_enrichment_model,
        enabled=trust_config.enable_report_enrichment,
    ).enrich(trust_result)

    if not quiet:
        console.print("[green]Phase 2 complete.[/green]\n")

    # ---- Phase 3: Generate unified reports ----
    report_paths: dict[str, str] = {}
    formats = (
        ["terminal", "json", "html"] if output_format == "all" else [output_format]
    )
    safe = _safe_name(name)

    if "json" in formats:
        jr = TrustJSONReport()
        jr.generate(trust_result, profile=trust_config.report_profile)
        json_path = output_dir / f"{safe}_review_report.json"
        jr.save(json_path)
        report_paths["json"] = str(json_path)

    if "html" in formats:
        hr = TrustHTMLReport()
        hr.generate(
            trust_result,
            profile=trust_config.report_profile,
            security_scorecard=scan_result.scorecard,
            security_duration=scan_result.duration,
        )
        html_path = output_dir / f"{safe}_review_report.html"
        hr.save(html_path)
        report_paths["html"] = str(html_path)

    if "terminal" in formats and not quiet:
        tr = TrustTerminalReport(console=console)
        tr.render(trust_result, report_paths)

    # CI/CD gates
    failed = False
    policy = TrustPolicy(version=trust_config.policy_version)
    if policy.should_fail(trust_result.scorecard.verdict, fail_on):
        if not quiet:
            console.print(
                f"\n[red]FAIL:[/red] Trust verdict {trust_result.scorecard.verdict.value} "
                f"meets/exceeds fail-on threshold {fail_on}"
            )
        failed = True

    if fail_below is not None and scan_result.scorecard.pass_rate < fail_below:
        if not quiet:
            console.print(
                f"\n[red]FAIL:[/red] Security pass rate {scan_result.scorecard.pass_rate:.1%} "
                f"is below threshold {fail_below:.1%}"
            )
        failed = True

    if failed:
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


@cli.command("railway-manifest")
@click.option(
    "--workspace",
    default=Path("."),
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Railway-linked workspace to inspect.",
)
@click.option(
    "--source-dir",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Optional source directory to refine dependency inference.",
)
@click.option("--service", default=None, help="Target Railway service name.")
@click.option("--environment", default=None, help="Target Railway environment name.")
@click.option(
    "--output",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Destination manifest path. Defaults to <workspace>/trust_manifest.railway.yaml.",
)
@click.option(
    "--stdout/--no-stdout",
    "print_stdout",
    default=False,
    help="Print generated YAML to stdout after writing the file.",
)
def railway_manifest(
    workspace: Path,
    source_dir: Path | None,
    service: str | None,
    environment: str | None,
    output: Path | None,
    print_stdout: bool,
) -> None:
    """Generate a sanitized trust manifest skeleton from a linked Railway workspace."""
    workspace_dir = workspace.resolve()
    output_path = output or (workspace_dir / "trust_manifest.railway.yaml")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base_manifest = load_manifest_file((source_dir or workspace_dir) / "trust_manifest.yaml")
    try:
        discovery = discover_railway_runtime(
            workspace_dir=workspace_dir,
            service=service,
            environment=environment,
            source_dir=source_dir,
        )
    except RailwayDiscoveryError as exc:
        console.print(f"\n[red]Railway discovery failed:[/red] {exc}")
        sys.exit(1)

    manifest = build_manifest_from_railway(discovery, existing_manifest=base_manifest)
    yaml_text = dump_manifest_yaml(manifest)
    output_path.write_text(yaml_text)

    console.print(f"[green]Wrote Railway manifest:[/green] {output_path}")
    if print_stdout:
        console.print(yaml_text)


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name).lower()


def _prepare_railway_manifest(
    workspace_dir: Path,
    source_dir: Path | None,
    output_dir: Path,
    manifest_path: Path | None,
    service: str | None,
    environment: str | None,
) -> Path:
    refine_source_dir = source_dir if _supports_railway_source_refinement(source_dir) else None
    discovery = discover_railway_runtime(
        workspace_dir=workspace_dir,
        service=service,
        environment=environment,
        source_dir=refine_source_dir,
    )
    existing_manifest = load_manifest_file(manifest_path)
    manifest = build_manifest_from_railway(discovery, existing_manifest=existing_manifest)

    generated_manifest = output_dir / "railway_discovered_manifest.yaml"
    generated_manifest.write_text(dump_manifest_yaml(manifest))
    return generated_manifest


def _supports_railway_source_refinement(source_dir: Path | None) -> bool:
    if source_dir is None:
        return False
    markers = (
        "Dockerfile",
        "railway.toml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "requirements.txt",
        "package.json",
    )
    return any((source_dir / marker).exists() for marker in markers)
