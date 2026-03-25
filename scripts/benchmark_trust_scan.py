from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
from pathlib import Path

from agentgate.benchmarking.trust_benchmark import (
    BenchmarkRun,
    benchmark_summary_to_dict,
    build_default_scenarios,
    load_runs_from_artifacts,
    load_benchmark_suite,
    render_markdown_summary,
    summarize_runs,
)
from agentgate.reports.trust_json_report import TrustJSONReport
from agentgate.trust.config import TrustScanConfig
from agentgate.trust.scanner import TrustScanner


def main() -> None:
    args = parse_args()
    suite_path = args.suite.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.summarize_existing:
        runs = load_runs_from_artifacts(output_dir)
        _write_summaries(output_dir, runs)
        return

    cases = load_benchmark_suite(suite_path)
    scenarios = [scenario for scenario in build_default_scenarios() if scenario.name in args.scenarios]

    if args.build_images:
        for case in cases:
            if case.build_context is None:
                continue
            subprocess.run(
                ["docker", "build", "-t", case.image_ref, str(case.build_context), "--quiet"],
                check=True,
            )

    runs: list[BenchmarkRun] = asyncio.run(
        _run_benchmarks(
            cases=cases,
            scenarios=scenarios,
            output_dir=output_dir,
            runtime_seconds=args.runtime_seconds,
        )
    )

    _write_summaries(output_dir, runs)


async def _run_benchmarks(
    *,
    cases,
    scenarios,
    output_dir: Path,
    runtime_seconds: int,
) -> list[BenchmarkRun]:
    runs: list[BenchmarkRun] = []
    for scenario in scenarios:
        for case in cases:
            case_output_dir = output_dir / scenario.name / case.case_id
            case_output_dir.mkdir(parents=True, exist_ok=True)
            config = TrustScanConfig(
                source_dir=case.source_dir,
                image_ref=case.image_ref,
                manifest_path=case.manifest_path,
                output_dir=case_output_dir,
                profile="both",
                report_profile=scenario.report_profile,
                runtime_seconds=runtime_seconds,
                quiet=True,
            )
            scanner = TrustScanner(config=config, checks=scenario.check_factory())
            result = await scanner.run()

            report = TrustJSONReport()
            report.generate(result, profile=scenario.report_profile)
            report.save(case_output_dir / "trust_scan_report.json")

            runs.append(
                BenchmarkRun(
                    scenario=scenario.name,
                    case_id=case.case_id,
                    label=case.label,
                    verdict=result.scorecard.verdict.value,
                    duration_seconds=result.scorecard.duration_seconds,
                    findings_total=result.scorecard.findings_total,
                    checks_failed=result.scorecard.checks_failed,
                )
            )
            _write_summaries(output_dir, runs)
    return runs


def _write_summaries(output_dir: Path, runs: list[BenchmarkRun]) -> None:
    summaries = summarize_runs(runs)
    summary_json = benchmark_summary_to_dict(summaries, runs)
    summary_md = render_markdown_summary(summaries, runs)

    (output_dir / "benchmark_summary.json").write_text(json.dumps(summary_json, indent=2))
    (output_dir / "benchmark_summary.md").write_text(summary_md)
    print(summary_md)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run trust-scan benchmarks over a corpus.")
    parser.add_argument(
        "--suite",
        type=Path,
        default=Path("benchmarks/promptshop_demo_suite.yaml"),
        help="Path to benchmark suite YAML.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark_output/trust"),
        help="Directory for benchmark artifacts.",
    )
    parser.add_argument(
        "--runtime-seconds",
        type=int,
        default=60,
        help="Max runtime per profile for runtime scenarios.",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=["full", "static_only"],
        choices=["full", "static_only"],
        help="Benchmark scenarios to execute.",
    )
    parser.add_argument(
        "--build-images",
        action="store_true",
        help="Build Docker images from each case's build_context before scanning.",
    )
    parser.add_argument(
        "--summarize-existing",
        action="store_true",
        help="Rebuild benchmark summaries from existing per-case artifacts in the output directory.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
