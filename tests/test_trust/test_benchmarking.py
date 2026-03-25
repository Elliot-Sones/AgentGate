from __future__ import annotations

from pathlib import Path

from agentgate.benchmarking.trust_benchmark import (
    BenchmarkRun,
    load_benchmark_suite,
    render_markdown_summary,
    summarize_runs,
)


def test_load_benchmark_suite_resolves_paths(tmp_path: Path) -> None:
    suite = tmp_path / "suite.yaml"
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest = case_dir / "trust_manifest.yaml"
    manifest.write_text("submission_id: demo\nagent_name: demo\nentrypoint: server.py\n")

    suite.write_text(
        "\n".join(
            [
                "cases:",
                "  - id: clean_case",
                "    label: clean",
                "    image_ref: demo:latest",
                "    source_dir: ./case",
                "    manifest_path: ./case/trust_manifest.yaml",
                "    build_context: ./case",
            ]
        )
    )

    cases = load_benchmark_suite(suite)

    assert len(cases) == 1
    assert cases[0].source_dir == case_dir.resolve()
    assert cases[0].manifest_path == manifest.resolve()
    assert cases[0].build_context == case_dir.resolve()


def test_summarize_runs_and_render_markdown() -> None:
    runs = [
        BenchmarkRun(
            scenario="full",
            case_id="clean",
            label="clean",
            verdict="allow_clean",
            duration_seconds=1.0,
            findings_total=0,
            checks_failed=0,
        ),
        BenchmarkRun(
            scenario="full",
            case_id="malicious",
            label="malicious",
            verdict="block",
            duration_seconds=2.0,
            findings_total=2,
            checks_failed=2,
        ),
        BenchmarkRun(
            scenario="static_only",
            case_id="clean",
            label="clean",
            verdict="allow_clean",
            duration_seconds=0.5,
            findings_total=0,
            checks_failed=0,
        ),
        BenchmarkRun(
            scenario="static_only",
            case_id="malicious",
            label="malicious",
            verdict="allow_with_warnings",
            duration_seconds=0.6,
            findings_total=1,
            checks_failed=1,
        ),
    ]

    summaries = summarize_runs(runs)
    markdown = render_markdown_summary(summaries, runs)

    full = next(summary for summary in summaries if summary.scenario == "full")
    static_only = next(summary for summary in summaries if summary.scenario == "static_only")

    assert full.malicious_detection_rate == 1.0
    assert static_only.malicious_detection_rate == 0.0
    assert static_only.missed_case_ids == ["malicious"]
    assert "| full | 2 | 100% | 100% | 0 | 1.50s |" in markdown
