from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import click
import httpx
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
from agentgate.trust.config import DependencySpec, TrustScanConfig
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import DeploymentSummary
from agentgate.trust.policy import TrustPolicy
from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES
from agentgate.trust.runtime.railway_discovery import (
    RailwayDiscoveryError,
    build_manifest_from_railway,
    discover_railway_runtime,
    dump_manifest_yaml,
    load_manifest_file,
)
from agentgate.trust.runtime.railway_executor import (
    RailwayExecutionError,
    RailwayExecutionResult,
    RailwayExecutor,
)
from agentgate.trust.runtime.submission_profile import (
    GeneratedRuntimeProfile as GeneratedSubmissionRuntimeProfile,
    build_submission_profile as build_generated_runtime_profile,
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
@click.option("--budget", default=500, type=click.IntRange(min=1), help="Max agent calls budget.")
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
@click.option(
    "--converters/--no-converters", default=False, help="Apply payload encoding/obfuscation."
)
@click.option(
    "--fail-below",
    default=None,
    type=click.FloatRange(min=0.0, max=1.0),
    help="Exit code 1 if pass rate below threshold (0.0-1.0).",
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output, only return exit code.")
@click.option(
    "--adaptive/--no-adaptive",
    default=False,
    help="Enable PAIR-style adaptive attacks (requires ANTHROPIC_API_KEY).",
)
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
    if detectors_list:
        unknown = [d for d in detectors_list if d not in DETECTOR_REGISTRY]
        if unknown:
            console.print(
                f"[red]Unknown detector(s): {', '.join(unknown)}[/red]\n"
                f"Available: {', '.join(sorted(DETECTOR_REGISTRY))}"
            )
            sys.exit(1)

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

    formats = ["terminal", "json", "html", "sarif"] if output_format == "all" else [output_format]

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
    "--railway-project-token",
    default="",
    envvar=["AGENTGATE_RAILWAY_PROJECT_TOKEN", "RAILWAY_TOKEN"],
    help="Railway project token for scoped project/environment access.",
)
@click.option(
    "--railway-pool-workspace",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Linked Railway workspace directory for a reusable warm test pool.",
)
@click.option(
    "--railway-pool-environment",
    default="",
    help="Environment name inside the reusable Railway pool.",
)
@click.option(
    "--railway-pool-service",
    default="submission-agent",
    help="App service name to reuse inside the Railway pool.",
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
@click.option(
    "--adaptive-trust/--no-adaptive-trust",
    default=False,
    help=(
        "Opt in to Anthropic-powered adaptive per-agent probing. "
        "This sends source/runtime context to Anthropic if ANTHROPIC_API_KEY is set."
    ),
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output, only return exit code.")
def trust_scan(
    url: str,
    source_dir: Path | None,
    railway_discover: bool,
    railway_service: str | None,
    railway_environment: str | None,
    railway_workspace_id: str,
    railway_project_token: str,
    railway_pool_workspace: Path | None,
    railway_pool_environment: str,
    railway_pool_service: str,
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
    adaptive_trust: bool,
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
                railway_project_token=railway_project_token.strip(),
            )
        except RailwayDiscoveryError as exc:
            console.print(f"\n[red]Railway discovery failed:[/red] {exc}")
            sys.exit(1)
        if not quiet:
            console.print(f"[dim]Using Railway-enriched manifest: {manifest}[/dim]\n")

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
        adaptive_trust=adaptive_trust,
        hosted_url=url.strip(),
        railway_workspace_dir=(source_dir or Path.cwd()) if railway_discover else None,
        railway_workspace_id=railway_workspace_id.strip(),
        railway_service=railway_service or "",
        railway_environment=railway_environment or "",
        railway_project_token=railway_project_token.strip(),
        railway_pool_workspace_dir=railway_pool_workspace,
        railway_pool_environment=railway_pool_environment.strip(),
        railway_pool_service=railway_pool_service.strip() or "submission-agent",
        strict_production_contract=strict_production_contract,
        keep_environment_on_failure=keep_environment_on_failure,
    )

    if not quiet:
        if url.strip():
            console.print(
                f"\n[bold]AgentGate[/bold] trust-scanning [cyan]{url.strip()}[/cyan] ...\n"
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
        ScanProgressDisplay([c.check_id for c in trust_checks], mode="trust") if not quiet else None
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
    formats = ["terminal", "json", "html", "sarif"] if output_format == "all" else [output_format]

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
@click.argument("url", required=False)
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
    "--railway-project-token",
    default="",
    envvar=["AGENTGATE_RAILWAY_PROJECT_TOKEN", "RAILWAY_TOKEN"],
    help="Railway project token for scoped project/environment access.",
)
@click.option(
    "--railway-pool-workspace",
    default=None,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Linked Railway workspace directory for a reusable warm test pool.",
)
@click.option(
    "--railway-pool-environment",
    default="",
    help="Environment name inside the reusable Railway pool.",
)
@click.option(
    "--railway-pool-service",
    default="submission-agent",
    help="App service name to reuse inside the Railway pool.",
)
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
@click.option("--budget", default=500, type=click.IntRange(min=1), help="Max agent calls budget.")
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
@click.option(
    "--converters/--no-converters", default=False, help="Apply payload encoding/obfuscation."
)
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
@click.option(
    "--strict-production-contract/--no-strict-production-contract",
    default=True,
    help="Require the Dockerfile + HTTP submission contract when deploying source submissions.",
)
@click.option(
    "--keep-environment-on-failure/--cleanup-environment-on-failure",
    default=False,
    help="Keep the temporary Railway environment for debugging when deployment or scans fail.",
)
@click.option(
    "--fail-below",
    default=None,
    type=click.FloatRange(min=0.0, max=1.0),
    help="Exit code 1 if security pass rate below threshold (0.0-1.0).",
)
@click.option(
    "--adaptive-trust/--no-adaptive-trust",
    default=False,
    help=(
        "Opt in to Anthropic-powered adaptive per-agent probing. "
        "This sends source/runtime context to Anthropic if ANTHROPIC_API_KEY is set."
    ),
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output.")
def scan(
    url: str | None,
    railway_discover: bool,
    railway_service: str | None,
    railway_environment: str | None,
    railway_workspace_id: str,
    railway_project_token: str,
    railway_pool_workspace: Path | None,
    railway_pool_environment: str,
    railway_pool_service: str,
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
    strict_production_contract: bool,
    keep_environment_on_failure: bool,
    fail_below: float | None,
    adaptive_trust: bool,
    quiet: bool,
) -> None:
    """Scan an AI agent — runs security + trust analysis and produces a unified report."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved_url = (url or "").strip()
    deployment_result: RailwayExecutionResult | None = None
    generated_runtime_profile: GeneratedSubmissionRuntimeProfile | None = None
    security_target_url = resolved_url
    security_request_field = request_field
    security_response_field = response_field

    if not resolved_url and source_dir is None:
        console.print(
            "\n[red]Combined scan requires either a live URL or --source-dir for a deployable submission.[/red]"
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
                railway_project_token=railway_project_token.strip(),
            )
        except RailwayDiscoveryError as exc:
            console.print(f"\n[red]Railway discovery failed:[/red] {exc}")
            sys.exit(1)
        if not quiet:
            console.print(f"[dim]Using Railway-enriched manifest: {manifest}[/dim]\n")

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
        adaptive_trust=adaptive_trust,
        hosted_url=resolved_url,
        railway_workspace_dir=(source_dir or Path.cwd())
        if railway_discover and resolved_url
        else None,
        railway_workspace_id=railway_workspace_id.strip(),
        railway_service=railway_service or "",
        railway_environment=railway_environment or "",
        railway_project_token=railway_project_token.strip(),
        railway_pool_workspace_dir=railway_pool_workspace,
        railway_pool_environment=railway_pool_environment.strip(),
        railway_pool_service=railway_pool_service.strip() or "submission-agent",
        strict_production_contract=strict_production_contract,
        keep_environment_on_failure=keep_environment_on_failure,
    )

    try:
        if resolved_url and source_dir is not None:
            try:
                generated_runtime_profile = _prepare_submission_profile_for_scan(trust_config)
            except RailwayExecutionError as exc:
                console.print(f"\n[red]Source preflight failed:[/red] {exc}")
                sys.exit(1)
            security_target_url, security_request_field = _resolve_security_target(
                resolved_url,
                generated_runtime_profile,
                request_field,
            )
            security_response_field = _resolve_security_response_field(
                security_target_url,
                response_field,
            )

        if not resolved_url and source_dir is not None:
            if not quiet:
                console.print(
                    "\n[bold]AgentGate[/bold] preflighting and deploying "
                    f"[cyan]{source_dir}[/cyan] to a temporary Railway environment ...\n"
                )
            try:
                deployment_result, generated_runtime_profile = _deploy_submission_for_scan(
                    trust_config
                )
            except RailwayExecutionError as exc:
                console.print(f"\n[red]Deployment failed:[/red] {exc}")
                sys.exit(1)

            resolved_url = deployment_result.public_url
            trust_config.hosted_url = resolved_url
            trust_config.railway_workspace_dir = deployment_result.workspace_dir
            trust_config.railway_service = deployment_result.service_name
            trust_config.railway_environment = deployment_result.environment_name
            security_target_url, security_request_field = _resolve_security_target(
                resolved_url,
                generated_runtime_profile,
                request_field,
            )
            security_response_field = _resolve_security_response_field(
                security_target_url,
                response_field,
            )

            if not quiet:
                console.print(f"[dim]Temporary Railway URL:[/dim] {resolved_url}")
                if security_target_url != resolved_url:
                    console.print(
                        f"[dim]Security scan target:[/dim] {security_target_url} "
                        f"(request field: {security_request_field})\n"
                    )
            _wait_for_review_target(
                base_url=resolved_url,
                security_target_url=security_target_url,
                request_field=security_request_field,
            )

        # ---- Phase 1: Red-team security scan ----
        if not quiet:
            console.print(
                f"\n[bold]AgentGate[/bold] review — Phase 1: security scan on "
                f"[cyan]{security_target_url}[/cyan] ...\n"
            )

        agent_config = AgentConfig(
            url=security_target_url,
            name=name,
            description=description,
            auth_header=auth_header,
            request_field=security_request_field,
            response_field=security_response_field,
            request_defaults=_security_request_defaults(security_target_url),
        )

        detectors_list = [d.strip() for d in only.split(",")] if only else None
        if detectors_list:
            unknown = [d for d in detectors_list if d not in DETECTOR_REGISTRY]
            if unknown:
                console.print(
                    f"[red]Unknown detector(s): {', '.join(unknown)}[/red]\n"
                    f"Available: {', '.join(sorted(DETECTOR_REGISTRY))}"
                )
                sys.exit(1)

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
            console.print(
                f"[bold]AgentGate[/bold] review — Phase 2: trust scan on "
                f"[cyan]{resolved_url}[/cyan] ...\n"
            )

        trust_config.hosted_url = resolved_url
        if deployment_result is not None:
            trust_config.railway_workspace_dir = deployment_result.workspace_dir
            trust_config.railway_service = deployment_result.service_name
            trust_config.railway_environment = deployment_result.environment_name

        from agentgate.trust.checks import default_trust_checks as _default_trust_checks

        trust_checks = _default_trust_checks()
        trust_progress = (
            ScanProgressDisplay([c.check_id for c in trust_checks], mode="trust")
            if not quiet
            else None
        )

        trust_scanner = TrustScanner(
            config=trust_config, checks=trust_checks, progress=trust_progress
        )
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

        if deployment_result is not None and trust_result.deployment_summary is None:
            trust_result.deployment_summary = DeploymentSummary(
                platform="railway",
                build_status="ready",
                deployment_status="ready" if deployment_result.public_url else "failed",
                project_id=deployment_result.project_id,
                project_name=deployment_result.project_name,
                environment_name=deployment_result.environment_name,
                service_name=deployment_result.service_name,
                public_url=deployment_result.public_url,
                dependency_services=list(deployment_result.dependency_services),
                issued_integrations=list(deployment_result.issued_integrations),
                integration_sandboxes=(
                    list(trust_result.generated_runtime_profile.integration_sandboxes)
                    if trust_result.generated_runtime_profile is not None
                    else []
                ),
                notes=list(deployment_result.notes),
            )

        trust_result = ReportEnricher(
            api_key=trust_config.anthropic_api_key,
            model=trust_config.report_enrichment_model,
            enabled=trust_config.enable_report_enrichment,
        ).enrich(trust_result)

        if not quiet:
            console.print("[green]Phase 2 complete.[/green]\n")

        # ---- Phase 3: Generate unified reports ----
        report_paths: dict[str, str] = {}
        formats = ["terminal", "json", "html"] if output_format == "all" else [output_format]
        safe = _safe_name(name)

        if "json" in formats:
            jr = TrustJSONReport()
            jr.generate(
                trust_result,
                profile=trust_config.report_profile,
                security_scorecard=scan_result.scorecard,
                security_duration=scan_result.duration,
            )
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
    finally:
        if deployment_result is not None and not keep_environment_on_failure:
            try:
                RailwayExecutor(
                    workspace_id=railway_workspace_id.strip(),
                    project_token=railway_project_token.strip(),
                    pool_workspace_dir=railway_pool_workspace,
                    pool_environment=railway_pool_environment.strip(),
                    pool_service_name=railway_pool_service.strip() or "submission-agent",
                ).cleanup(deployment_result)
            except Exception:
                logging.getLogger(__name__).exception(
                    "Failed to cleanup temporary Railway deployment after combined scan."
                )


@cli.command("ci-setup")
@click.option(
    "--platform",
    default="github-actions",
    type=click.Choice(["github-actions"], case_sensitive=False),
    help="CI platform to generate configuration for.",
)
@click.option(
    "--scan-type",
    default="both",
    type=click.Choice(["trust", "security", "both"], case_sensitive=False),
    help="Which scan(s) to include in the generated workflow.",
)
@click.option(
    "--fail-on",
    default="manual_review",
    type=click.Choice(["allow_with_warnings", "manual_review", "block"], case_sensitive=False),
    help="Trust verdict threshold that fails the CI step.",
)
@click.option("--source-dir", default=".", help="Agent source directory path.")
@click.option("--manifest", default="trust_manifest.yaml", help="Trust manifest file path.")
@click.option(
    "--output",
    default=".github/workflows/agentgate.yml",
    help="Destination path for the generated workflow file.",
)
def ci_setup(
    platform: str,
    scan_type: str,
    fail_on: str,
    source_dir: str,
    manifest: str,
    output: str,
) -> None:
    """Generate a CI/CD workflow configuration for AgentGate scans.

    Creates a ready-to-use workflow file for your CI platform.  Currently
    supports GitHub Actions.
    """
    from agentgate.ci import generate_github_action_config

    if platform == "github-actions":
        workflow_yaml = generate_github_action_config(
            scan_type=scan_type,
            fail_on=fail_on,
            source_dir=source_dir,
            manifest=manifest,
        )

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(workflow_yaml)

        console.print(f"\n[green]Generated GitHub Actions workflow:[/green] {output_path}\n")
        console.print("[bold]Next steps:[/bold]")
        console.print(
            "  1. Add [cyan]ANTHROPIC_API_KEY[/cyan] to your repository secrets "
            "(Settings → Secrets → Actions)."
        )
        console.print(
            f"  2. Edit [cyan]{output_path}[/cyan] to adjust source-dir, manifest, "
            "and agent-url as needed."
        )
        console.print(
            "  3. Commit and push — AgentGate will run automatically on your next "
            "PR or push to main."
        )
        console.print(
            "\n[dim]Full documentation:[/dim] https://github.com/Elliot-Sones/AgentGate"
            "/blob/main/docs/ci_integration.md\n"
        )


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
    "--railway-project-token",
    default="",
    envvar=["AGENTGATE_RAILWAY_PROJECT_TOKEN", "RAILWAY_TOKEN"],
    help="Railway project token for scoped project/environment access.",
)
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
    railway_project_token: str,
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
            project_token=railway_project_token.strip(),
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


@cli.command("railway-pool-init")
@click.option(
    "--workspace",
    default=Path.cwd(),
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Linked Railway workspace directory for the reusable test pool.",
)
@click.option(
    "--environment", default="agentgate-pool", help="Environment name to reuse for warm scans."
)
@click.option(
    "--agent-service",
    default="submission-agent",
    help="App service name reserved for deployed submissions.",
)
@click.option(
    "--dependencies",
    default="pgvector,neo4j,redis",
    help="Comma-separated dependency services to prewarm in the pool.",
)
@click.option(
    "--railway-project-token",
    default="",
    envvar=["AGENTGATE_RAILWAY_PROJECT_TOKEN", "RAILWAY_TOKEN"],
    help="Railway project token for scoped project/environment access.",
)
@click.option(
    "--ensure-domain/--no-ensure-domain",
    default=True,
    help="Ensure the pooled app service has a Railway domain.",
)
@click.option("--quiet", is_flag=True, help="Suppress terminal output.")
def railway_pool_init(
    workspace: Path,
    environment: str,
    agent_service: str,
    dependencies: str,
    railway_project_token: str,
    ensure_domain: bool,
    quiet: bool,
) -> None:
    """Prepare a reusable Railway test pool with warm dependency services."""
    dependency_specs = _parse_pool_dependencies(dependencies)
    if not quiet:
        console.print(
            "\n[bold]AgentGate[/bold] warming a reusable Railway pool in "
            f"[cyan]{workspace}[/cyan] ({environment}) ...\n"
        )
    try:
        result = RailwayExecutor(
            project_token=railway_project_token.strip(),
            pool_workspace_dir=workspace,
            pool_environment=environment,
            pool_service_name=agent_service,
        ).ensure_pool(
            dependencies=dependency_specs,
            ensure_domain=ensure_domain,
        )
    except RailwayExecutionError as exc:
        console.print(f"\n[red]Railway pool init failed:[/red] {exc}")
        sys.exit(1)

    if quiet:
        return

    console.print("[green]Reusable Railway pool is ready.[/green]")
    console.print(f"[dim]Project:[/dim] {result.project_name} ({result.project_id})")
    console.print(f"[dim]Environment:[/dim] {result.environment_name}")
    console.print(f"[dim]Agent service:[/dim] {result.service_name}")
    if result.public_url:
        console.print(f"[dim]Agent domain:[/dim] {result.public_url}")
    console.print(
        f"[dim]Dependency services:[/dim] {', '.join(result.dependency_services) or 'none'}"
    )
    for note in result.notes:
        console.print(f"[dim]- {note}[/dim]")


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name).lower()


def _prepare_railway_manifest(
    workspace_dir: Path,
    source_dir: Path | None,
    output_dir: Path,
    manifest_path: Path | None,
    service: str | None,
    environment: str | None,
    railway_project_token: str = "",
) -> Path:
    refine_source_dir = source_dir if _supports_railway_source_refinement(source_dir) else None
    discovery = discover_railway_runtime(
        workspace_dir=workspace_dir,
        service=service,
        environment=environment,
        source_dir=refine_source_dir,
        project_token=railway_project_token,
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
        "Dockerfile.api",
        "railway.toml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "requirements.txt",
        "package.json",
    )
    return any((source_dir / marker).exists() for marker in markers)


def _deploy_submission_for_scan(
    config: TrustScanConfig,
) -> tuple[RailwayExecutionResult, GeneratedSubmissionRuntimeProfile | None]:
    runtime_profile = _prepare_submission_profile_for_scan(config)
    if config.source_dir is None:
        raise RailwayExecutionError("Combined deployment flow requires a source directory.")

    runtime_env = dict(config.runtime_env)
    if runtime_profile is not None:
        runtime_env.update(runtime_profile.issued_runtime_env)

    deployment = _build_railway_executor_from_config(config).deploy_submission(
        source_dir=config.source_dir,
        dockerfile_path=(
            Path(runtime_profile.dockerfile_path)
            if runtime_profile is not None and runtime_profile.dockerfile_path
            else config.dockerfile_path
        ),
        dependencies=config.dependencies,
        runtime_env=runtime_env,
        issued_integrations=(
            list(runtime_profile.issued_integrations) if runtime_profile is not None else []
        ),
    )
    return deployment, runtime_profile


def _build_railway_executor_from_config(config: TrustScanConfig) -> RailwayExecutor:
    return RailwayExecutor(
        workspace_id=config.railway_workspace_id,
        project_token=config.railway_project_token,
        pool_workspace_dir=config.railway_pool_workspace_dir,
        pool_environment=config.railway_pool_environment,
        pool_service_name=config.railway_pool_service or "submission-agent",
    )


def _prepare_submission_profile_for_scan(
    config: TrustScanConfig,
) -> GeneratedSubmissionRuntimeProfile | None:
    ctx = TrustScanContext(config=config)
    ctx.load_manifest()

    if ctx.source_dir is None:
        raise RailwayExecutionError("Combined scan source profiling requires a source directory.")

    if ctx.config.dependency_validation_errors:
        raise RailwayExecutionError(" ".join(ctx.config.dependency_validation_errors))

    ctx.infer_runtime_config_from_source()
    assessment, runtime_profile = build_generated_runtime_profile(
        source_dir=ctx.source_dir,
        manifest=ctx.manifest,
        dependencies=ctx.config.dependencies,
        runtime_env=ctx.config.runtime_env,
        dockerfile_path=ctx.config.dockerfile_path,
        enforce_production_contract=config.strict_production_contract,
    )

    if runtime_profile is not None:
        config.egress_allowlist.update(runtime_profile.allow_domains)
        for key, value in runtime_profile.issued_runtime_env.items():
            config.runtime_env.setdefault(key, value)

    if not assessment.supported:
        raise RailwayExecutionError(assessment.detail or assessment.reason or assessment.status)
    return runtime_profile


def _resolve_security_target(
    base_url: str,
    runtime_profile: GeneratedSubmissionRuntimeProfile | None,
    request_field: str,
) -> tuple[str, str]:
    normalized_base = base_url.rstrip("/")
    if runtime_profile is None:
        return normalized_base, request_field

    candidates = [
        path
        for path in runtime_profile.probe_paths
        if path.startswith("/")
        and path not in {"/", "/docs", "/openapi.json", "/health", "/healthz"}
    ]
    preferred_tokens = ("/api/v1/chat", "/chat", "/query", "/search")
    chosen_path = ""
    for token in preferred_tokens:
        chosen_path = next((path for path in candidates if token in path.lower()), "")
        if chosen_path:
            break

    if not chosen_path:
        return normalized_base, request_field

    resolved_request_field = request_field
    if request_field == "question":
        lowered = chosen_path.lower()
        if "/chat" in lowered:
            resolved_request_field = "message"
        elif "/query" in lowered or "/search" in lowered:
            resolved_request_field = "query"

    return f"{normalized_base}{chosen_path}", resolved_request_field


def _wait_for_review_target(
    *,
    base_url: str,
    security_target_url: str,
    request_field: str,
    timeout_seconds: int = 90,
) -> None:
    deadline = time.time() + timeout_seconds
    normalized_base = base_url.rstrip("/")
    docs_url = f"{normalized_base}/docs"

    with httpx.Client(timeout=10, follow_redirects=True) as client:
        while time.time() < deadline:
            base_ready = False
            security_ready = False

            for candidate in (normalized_base, docs_url):
                try:
                    response = client.get(candidate)
                except Exception:
                    continue
                if 200 <= response.status_code < 400:
                    base_ready = True
                    break

            if security_target_url:
                try:
                    if security_target_url.rstrip("/") == normalized_base:
                        response = client.get(normalized_base)
                    else:
                        response = client.post(
                            security_target_url,
                            json={request_field: "AgentGate readiness probe"},
                        )
                    if response.status_code < 500 and response.status_code != 404:
                        security_ready = True
                except Exception:
                    pass

            if base_ready and (not security_target_url or security_ready):
                return

            time.sleep(3)


def _security_request_defaults(target_url: str) -> dict[str, object]:
    path = urlparse(target_url).path.lower()
    defaults: dict[str, object] = {}
    if path.endswith("/search") or path.endswith("/query"):
        defaults["user_id"] = "agentgate-security-scan"
    return defaults


@cli.command("owasp-coverage")
def owasp_coverage_cmd() -> None:
    """Print the OWASP LLM Top 10 (2025) coverage table for AgentGate."""
    from agentgate.trust.owasp_mapping import get_owasp_coverage

    LEVEL_COLOUR = {
        "full": "green",
        "partial": "yellow",
        "minimal": "orange3",
        "none": "red",
    }

    table = Table(title="AgentGate — OWASP LLM Top 10 (2025) Coverage", show_lines=True)
    table.add_column("ID", style="bold", no_wrap=True, width=7)
    table.add_column("Category", no_wrap=False, min_width=28)
    table.add_column("Level", no_wrap=True, width=9)
    table.add_column("Components", no_wrap=False, min_width=30)
    table.add_column("Key Gaps", no_wrap=False, min_width=40)

    for mapping in get_owasp_coverage():
        colour = LEVEL_COLOUR.get(mapping.coverage_level, "white")
        level_str = f"[{colour}]{mapping.coverage_level}[/{colour}]"
        components_str = "\n".join(f"• {c}" for c in mapping.components) if mapping.components else "(none)"
        gaps_str = "\n".join(f"• {g}" for g in mapping.gaps[:2])
        if len(mapping.gaps) > 2:
            gaps_str += f"\n  …and {len(mapping.gaps) - 2} more"
        table.add_row(
            mapping.owasp_id,
            mapping.name,
            level_str,
            components_str,
            gaps_str,
        )

    console.print(table)

    from agentgate.trust.owasp_mapping import owasp_coverage_summary
    summary = owasp_coverage_summary()
    console.print(
        f"\n[bold]Coverage summary:[/bold] "
        f"{summary['covered_count']}/{summary['total']} categories with partial or full coverage "
        f"(aggregate: [bold]{summary['coverage_level']}[/bold])\n"
    )


def _resolve_security_response_field(target_url: str, response_field: str) -> str:
    path = urlparse(target_url).path.lower()
    if response_field == "answer" and (path.endswith("/search") or path.endswith("/query")):
        return "results"
    return response_field


def _parse_pool_dependencies(raw_dependencies: str) -> list[DependencySpec]:
    dependency_specs: list[DependencySpec] = []
    invalid: list[str] = []
    for raw in raw_dependencies.split(","):
        service = raw.strip().lower()
        if not service:
            continue
        if service not in ALLOWED_SERVICES:
            invalid.append(service)
            continue
        dependency_specs.append(DependencySpec(service=service))
    if invalid:
        raise click.ClickException("Unsupported pool dependencies: " + ", ".join(sorted(invalid)))
    return dependency_specs


@cli.group("api-key")
def api_key_group():
    """Manage API keys for the hosted scanning service."""
    pass


@api_key_group.command("create")
@click.option("--name", required=True, help="Name for this API key (e.g. 'PromptShop Production')")
@click.option("--database-url", envvar="DATABASE_URL", required=True, help="Postgres connection URL")
def api_key_create(name: str, database_url: str):
    """Create a new API key."""
    from agentgate.server.auth import generate_api_key
    from agentgate.server.db import Database

    async def _create():
        db = Database(dsn=database_url)
        await db.connect()
        await db.run_migrations()
        key_id, raw_key, secret_hash = generate_api_key()
        await db.create_api_key(key_id=key_id, key_hash=secret_hash, name=name)
        await db.disconnect()
        return raw_key

    raw_key = asyncio.run(_create())
    console = Console()
    console.print(f"\n[bold green]Created API key:[/bold green] {raw_key}")
    console.print("[yellow]Store this key securely. It cannot be retrieved again.[/yellow]\n")
