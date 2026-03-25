from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
from statistics import mean
from typing import Any

import yaml

from agentgate.trust.checks import (
    BaseTrustCheck,
    StaticCodeSignalsCheck,
    StaticDependencyRiskCheck,
    StaticManifestCheck,
    StaticPromptToolInspectionCheck,
    StaticProvenanceCheck,
    default_trust_checks,
)
from agentgate.trust.models import TrustVerdict, verdict_rank

DETECTION_THRESHOLD = TrustVerdict.MANUAL_REVIEW


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    label: str
    description: str
    image_ref: str
    source_dir: Path
    manifest_path: Path
    build_context: Path | None = None


@dataclass(frozen=True)
class BenchmarkScenario:
    name: str
    description: str
    report_profile: str
    check_factory: Callable[[], list[BaseTrustCheck]]


@dataclass(frozen=True)
class BenchmarkRun:
    scenario: str
    case_id: str
    label: str
    verdict: str
    duration_seconds: float
    findings_total: int
    checks_failed: int


@dataclass(frozen=True)
class BenchmarkSummary:
    scenario: str
    cases_total: int
    clean_total: int
    malicious_total: int
    malicious_caught: int
    malicious_missed: int
    clean_escalated: int
    manual_review_or_block_rate: float
    clean_auto_approve_rate: float
    malicious_detection_rate: float
    average_duration_seconds: float
    verdicts: dict[str, int]
    missed_case_ids: list[str]
    escalated_clean_case_ids: list[str]


def build_default_scenarios() -> list[BenchmarkScenario]:
    return [
        BenchmarkScenario(
            name="full",
            description="Full trust scan with static and runtime checks.",
            report_profile="promptshop",
            check_factory=default_trust_checks,
        ),
        BenchmarkScenario(
            name="static_only",
            description="Baseline static-only trust scan without runtime detonation.",
            report_profile="standard",
            check_factory=_static_only_checks,
        ),
    ]


def load_benchmark_suite(path: Path) -> list[BenchmarkCase]:
    suite = yaml.safe_load(path.read_text())
    if not isinstance(suite, dict) or not isinstance(suite.get("cases"), list):
        raise ValueError("Benchmark suite must define a top-level 'cases' list.")

    suite_dir = path.parent
    cases: list[BenchmarkCase] = []
    for raw_case in suite["cases"]:
        if not isinstance(raw_case, dict):
            raise ValueError("Each benchmark case must be a mapping.")

        case_id = _required_str(raw_case, "id")
        label = _required_str(raw_case, "label").lower()
        if label not in {"clean", "malicious"}:
            raise ValueError(f"Benchmark case '{case_id}' must use label clean|malicious.")

        image_ref = _required_str(raw_case, "image_ref")
        description = str(raw_case.get("description", "")).strip()
        source_dir = _resolve_path(suite_dir, _required_str(raw_case, "source_dir"))
        manifest_path = _resolve_path(suite_dir, _required_str(raw_case, "manifest_path"))
        build_context = raw_case.get("build_context")

        cases.append(
            BenchmarkCase(
                case_id=case_id,
                label=label,
                description=description,
                image_ref=image_ref,
                source_dir=source_dir,
                manifest_path=manifest_path,
                build_context=_resolve_path(suite_dir, build_context) if build_context else None,
            )
        )
    return cases


def load_runs_from_artifacts(output_dir: Path) -> list[BenchmarkRun]:
    runs: list[BenchmarkRun] = []
    for report_path in sorted(output_dir.glob("*/*/trust_scan_report.json")):
        scenario = report_path.parent.parent.name
        case_id = report_path.parent.name
        data = json.loads(report_path.read_text())
        label = _infer_label(case_id, data)
        scorecard = data["scorecard"]
        runs.append(
            BenchmarkRun(
                scenario=scenario,
                case_id=case_id,
                label=label,
                verdict=scorecard["verdict"],
                duration_seconds=float(scorecard["duration_seconds"]),
                findings_total=int(scorecard["findings_total"]),
                checks_failed=int(scorecard["checks_failed"]),
            )
        )
    return runs


def summarize_runs(runs: list[BenchmarkRun]) -> list[BenchmarkSummary]:
    by_scenario: dict[str, list[BenchmarkRun]] = defaultdict(list)
    for run in runs:
        by_scenario[run.scenario].append(run)

    summaries: list[BenchmarkSummary] = []
    for scenario, scenario_runs in by_scenario.items():
        clean_runs = [run for run in scenario_runs if run.label == "clean"]
        malicious_runs = [run for run in scenario_runs if run.label == "malicious"]
        malicious_caught_runs = [run for run in malicious_runs if _is_detected(run.verdict)]
        malicious_missed_runs = [run for run in malicious_runs if not _is_detected(run.verdict)]
        clean_escalated_runs = [run for run in clean_runs if _is_detected(run.verdict)]
        clean_auto_approved_runs = [
            run for run in clean_runs if verdict_rank(TrustVerdict(run.verdict)) <= verdict_rank(TrustVerdict.ALLOW_WITH_WARNINGS)
        ]

        verdict_counts: dict[str, int] = defaultdict(int)
        for run in scenario_runs:
            verdict_counts[run.verdict] += 1

        summaries.append(
            BenchmarkSummary(
                scenario=scenario,
                cases_total=len(scenario_runs),
                clean_total=len(clean_runs),
                malicious_total=len(malicious_runs),
                malicious_caught=len(malicious_caught_runs),
                malicious_missed=len(malicious_missed_runs),
                clean_escalated=len(clean_escalated_runs),
                manual_review_or_block_rate=_ratio(
                    sum(1 for run in scenario_runs if _is_detected(run.verdict)),
                    len(scenario_runs),
                ),
                clean_auto_approve_rate=_ratio(len(clean_auto_approved_runs), len(clean_runs)),
                malicious_detection_rate=_ratio(len(malicious_caught_runs), len(malicious_runs)),
                average_duration_seconds=round(mean(run.duration_seconds for run in scenario_runs), 3),
                verdicts=dict(sorted(verdict_counts.items())),
                missed_case_ids=[run.case_id for run in malicious_missed_runs],
                escalated_clean_case_ids=[run.case_id for run in clean_escalated_runs],
            )
        )

    return sorted(summaries, key=lambda summary: summary.scenario)


def render_markdown_summary(
    summaries: list[BenchmarkSummary],
    runs: list[BenchmarkRun],
) -> str:
    lines = [
        "# Trust Benchmark Summary",
        "",
        "This benchmark compares AgentGate scenarios on a small seller-submission corpus.",
        "",
        "| Scenario | Cases | Malicious detection | Clean auto-approve | Clean escalations | Avg scan time |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for summary in summaries:
        lines.append(
            "| "
            f"{summary.scenario} | "
            f"{summary.cases_total} | "
            f"{summary.malicious_detection_rate:.0%} | "
            f"{summary.clean_auto_approve_rate:.0%} | "
            f"{summary.clean_escalated} | "
            f"{_format_duration(summary.average_duration_seconds)} |"
        )

    lines.extend(["", "## Per-case Results", ""])
    lines.append("| Scenario | Case | Label | Verdict | Findings | Duration |")
    lines.append("|---|---|---|---|---:|---:|")
    for run in sorted(runs, key=lambda item: (item.scenario, item.case_id)):
        lines.append(
            "| "
            f"{run.scenario} | {run.case_id} | {run.label} | {run.verdict} | "
            f"{run.findings_total} | {_format_duration(run.duration_seconds)} |"
        )

    lines.extend(["", "## Notable Takeaways", ""])
    for summary in summaries:
        takeaway = (
            f"- `{summary.scenario}` caught {summary.malicious_caught}/{summary.malicious_total} malicious cases"
        )
        if summary.missed_case_ids:
            takeaway += f" and missed {', '.join(summary.missed_case_ids)}"
        if summary.escalated_clean_case_ids:
            takeaway += (
                f"; it escalated clean cases {', '.join(summary.escalated_clean_case_ids)}"
            )
        lines.append(takeaway + ".")

    return "\n".join(lines) + "\n"


def benchmark_summary_to_dict(summaries: list[BenchmarkSummary], runs: list[BenchmarkRun]) -> dict[str, Any]:
    return {
        "summaries": [
            {
                "scenario": summary.scenario,
                "cases_total": summary.cases_total,
                "clean_total": summary.clean_total,
                "malicious_total": summary.malicious_total,
                "malicious_caught": summary.malicious_caught,
                "malicious_missed": summary.malicious_missed,
                "clean_escalated": summary.clean_escalated,
                "manual_review_or_block_rate": summary.manual_review_or_block_rate,
                "clean_auto_approve_rate": summary.clean_auto_approve_rate,
                "malicious_detection_rate": summary.malicious_detection_rate,
                "average_duration_seconds": summary.average_duration_seconds,
                "verdicts": summary.verdicts,
                "missed_case_ids": summary.missed_case_ids,
                "escalated_clean_case_ids": summary.escalated_clean_case_ids,
            }
            for summary in summaries
        ],
        "runs": [
            {
                "scenario": run.scenario,
                "case_id": run.case_id,
                "label": run.label,
                "verdict": run.verdict,
                "duration_seconds": run.duration_seconds,
                "findings_total": run.findings_total,
                "checks_failed": run.checks_failed,
            }
            for run in runs
        ],
    }


def _static_only_checks() -> list[BaseTrustCheck]:
    return [
        StaticManifestCheck(),
        StaticPromptToolInspectionCheck(),
        StaticDependencyRiskCheck(),
        StaticProvenanceCheck(),
        StaticCodeSignalsCheck(),
    ]


def _required_str(raw_case: dict[str, Any], key: str) -> str:
    value = str(raw_case.get(key, "")).strip()
    if not value:
        raise ValueError(f"Benchmark case is missing required field '{key}'.")
    return value


def _resolve_path(base_dir: Path, raw_path: str | Path) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else (base_dir / path).resolve()


def _is_detected(verdict: str) -> bool:
    return verdict_rank(TrustVerdict(verdict)) >= verdict_rank(DETECTION_THRESHOLD)


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    return f"{seconds:.2f}s"


def _infer_label(case_id: str, data: dict[str, Any]) -> str:
    metadata = data.get("metadata", {})
    if isinstance(metadata, dict):
        submission = metadata.get("submission_profile")
        if isinstance(submission, dict) and submission.get("benchmark_label") in {"clean", "malicious"}:
            return str(submission["benchmark_label"])

    if "clean" in case_id:
        return "clean"
    return "malicious"
