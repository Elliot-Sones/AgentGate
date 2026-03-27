"""Helpers for generating CI/CD configuration for AgentGate scans."""

from __future__ import annotations

import textwrap
from typing import Any


_VALID_SCAN_TYPES = {"trust", "security", "both"}
_VALID_FAIL_ON = {"allow_with_warnings", "manual_review", "block"}


def generate_github_action_config(
    scan_type: str = "both",
    fail_on: str = "manual_review",
    source_dir: str = ".",
    manifest: str = "trust_manifest.yaml",
) -> str:
    """Return a YAML string for a GitHub Actions workflow that runs AgentGate scans.

    Args:
        scan_type: One of "trust", "security", or "both".
        fail_on: Trust verdict threshold that causes the step to fail.
            One of "allow_with_warnings", "manual_review", or "block".
        source_dir: Path to the agent source directory relative to the repo root.
        manifest: Path to the trust manifest file relative to the repo root.

    Returns:
        A YAML string suitable for saving as a ``.github/workflows/agentgate.yml`` file.
    """
    _validate_scan_type(scan_type)
    _validate_fail_on(fail_on)

    if scan_type == "trust":
        scan_run = _trust_scan_run(source_dir, manifest, fail_on)
        report_path_expr = "agentgate-reports/trust_scan_report.json"
    elif scan_type == "security":
        scan_run = _security_scan_run()
        report_path_expr = "agentgate-reports"
    else:
        scan_run = _both_scan_run(source_dir, manifest, fail_on)
        report_path_expr = "agentgate-reports/trust_scan_report.json"

    read_results_run = _read_results_run(report_path_expr, scan_type)

    steps: list[dict[str, Any]] = [
        {
            "name": "Checkout code",
            "uses": "actions/checkout@v4",
        },
        {
            "name": "Set up Python",
            "uses": "actions/setup-python@v5",
            "with": {"python-version": "3.11"},
        },
        {
            "name": "Install AgentGate",
            "run": "pip install agentgate",
        },
        {
            "name": f"Run AgentGate {scan_type} scan",
            "id": "agentgate",
            "env": {"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"},
            "run": scan_run,
        },
        {
            "name": "Read scan results",
            "id": "read-results",
            "if": "always()",
            "run": read_results_run,
        },
        {
            "name": "Upload scan report",
            "if": "always()",
            "uses": "actions/upload-artifact@v4",
            "with": {
                "name": "agentgate-report",
                "path": "agentgate-reports/",
                "retention-days": 30,
            },
        },
    ]

    workflow: dict[str, Any] = {
        "name": "AgentGate Security & Trust Scan",
        "on": {
            "push": {"branches": ["main", "master"]},
            "pull_request": {"branches": ["main", "master"]},
        },
        "jobs": {
            "agentgate-scan": {
                "name": "AgentGate Scan",
                "runs-on": "ubuntu-latest",
                "permissions": {
                    "contents": "read",
                    "pull-requests": "write",
                },
                "steps": steps,
            }
        },
    }

    # Render to YAML manually to preserve key order and produce readable output.
    return _render_workflow(workflow)


def _validate_scan_type(scan_type: str) -> None:
    if scan_type not in _VALID_SCAN_TYPES:
        raise ValueError(f"scan_type must be one of {_VALID_SCAN_TYPES}, got {scan_type!r}")


def _validate_fail_on(fail_on: str) -> None:
    if fail_on not in _VALID_FAIL_ON:
        raise ValueError(f"fail_on must be one of {_VALID_FAIL_ON}, got {fail_on!r}")


def _trust_scan_run(source_dir: str, manifest: str, fail_on: str) -> str:
    return textwrap.dedent(f"""\
        mkdir -p agentgate-reports
        agentgate trust-scan \\
          --source-dir {source_dir} \\
          --manifest {manifest} \\
          --fail-on {fail_on} \\
          --format all \\
          --output agentgate-reports
    """)


def _security_scan_run() -> str:
    return textwrap.dedent("""\
        mkdir -p agentgate-reports
        # Set AGENT_URL to the URL of your running agent
        agentgate security-scan "$AGENT_URL" \\
          --format all \\
          --output agentgate-reports
    """)


def _both_scan_run(source_dir: str, manifest: str, fail_on: str) -> str:
    return textwrap.dedent(f"""\
        mkdir -p agentgate-reports
        agentgate trust-scan \\
          --source-dir {source_dir} \\
          --manifest {manifest} \\
          --fail-on {fail_on} \\
          --format all \\
          --output agentgate-reports
    """)


def _read_results_run(report_path: str, scan_type: str) -> str:
    if scan_type == "security":
        return textwrap.dedent("""\
            REPORT=$(ls agentgate-reports/*.json 2>/dev/null | head -1)
            if [ -n "$REPORT" ]; then
              VERDICT=$(python3 -c "import json; d=json.load(open('$REPORT')); print(d.get('pass_rate', 'unknown'))")
              FINDINGS=$(python3 -c "import json; d=json.load(open('$REPORT')); print(len(d.get('results', [])))")
            else
              VERDICT="unknown"
              FINDINGS="0"
              REPORT=""
            fi
            echo "verdict=$VERDICT" >> "$GITHUB_OUTPUT"
            echo "findings-count=$FINDINGS" >> "$GITHUB_OUTPUT"
            echo "report-path=$REPORT" >> "$GITHUB_OUTPUT"
        """)
    return textwrap.dedent(f"""\
        REPORT="{report_path}"
        if [ -f "$REPORT" ]; then
          VERDICT=$(python3 -c "import json; d=json.load(open('$REPORT')); sc=d.get('scorecard', {{}}); print(sc.get('verdict', 'unknown'))")
          FINDINGS=$(python3 -c "import json; d=json.load(open('$REPORT')); print(len(d.get('findings', [])))")
        else
          VERDICT="unknown"
          FINDINGS="0"
        fi
        echo "verdict=$VERDICT" >> "$GITHUB_OUTPUT"
        echo "findings-count=$FINDINGS" >> "$GITHUB_OUTPUT"
        echo "report-path=$REPORT" >> "$GITHUB_OUTPUT"
    """)


def _render_workflow(workflow: dict[str, Any]) -> str:
    """Render the workflow dict to a YAML string using PyYAML."""
    import yaml

    class _LiteralStr(str):
        """Marker class to force block scalar style for multiline strings."""

    def _literal_representer(dumper: yaml.Dumper, data: str) -> yaml.Node:
        if "\n" in data:
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    class _WorkflowDumper(yaml.Dumper):
        pass

    _WorkflowDumper.add_representer(str, _literal_representer)
    _WorkflowDumper.add_representer(_LiteralStr, _literal_representer)

    return yaml.dump(
        workflow,
        Dumper=_WorkflowDumper,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
