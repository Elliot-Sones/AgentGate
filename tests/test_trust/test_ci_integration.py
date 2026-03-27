from __future__ import annotations

from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# ci.py unit tests
# ---------------------------------------------------------------------------


def test_generate_github_action_config_returns_valid_yaml():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config()
    # Must be parseable YAML
    parsed = yaml.safe_load(result)
    assert isinstance(parsed, dict)


def test_generate_github_action_config_default_fields():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config()
    parsed = yaml.safe_load(result)

    assert "on" in parsed
    assert "jobs" in parsed

    # There should be at least one job
    jobs = parsed["jobs"]
    assert len(jobs) >= 1


def test_generate_github_action_config_includes_scan_type():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config(scan_type="trust")
    assert "trust" in result

    result_sec = generate_github_action_config(scan_type="security")
    assert "security" in result_sec


def test_generate_github_action_config_custom_fail_on():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config(fail_on="block")
    assert "block" in result


def test_generate_github_action_config_custom_source_dir():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config(source_dir="./agents/my-agent")
    assert "my-agent" in result


def test_generate_github_action_config_custom_manifest():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config(manifest="custom_manifest.yaml")
    assert "custom_manifest.yaml" in result


def test_generate_github_action_config_both_scan_type():
    from agentgate.ci import generate_github_action_config

    result = generate_github_action_config(scan_type="both")
    parsed = yaml.safe_load(result)
    assert isinstance(parsed, dict)
    # For "both", the workflow should reference both trust and security concepts
    assert "agentgate" in result.lower() or "scan" in result.lower()


# ---------------------------------------------------------------------------
# action.yml structural tests
# ---------------------------------------------------------------------------


def test_action_yml_is_valid_yaml():
    action_path = Path(__file__).parents[2] / "action.yml"
    assert action_path.exists(), "action.yml must exist at the repo root"
    parsed = yaml.safe_load(action_path.read_text())
    assert isinstance(parsed, dict)


def test_action_yml_has_required_top_level_keys():
    action_path = Path(__file__).parents[2] / "action.yml"
    parsed = yaml.safe_load(action_path.read_text())

    assert "name" in parsed
    assert "description" in parsed
    assert "inputs" in parsed
    assert "outputs" in parsed
    assert "runs" in parsed


def test_action_yml_inputs_include_expected_fields():
    action_path = Path(__file__).parents[2] / "action.yml"
    parsed = yaml.safe_load(action_path.read_text())

    inputs = parsed["inputs"]
    assert "scan-type" in inputs
    assert "source-dir" in inputs
    assert "manifest" in inputs
    assert "fail-on" in inputs
    assert "anthropic-api-key" in inputs


def test_action_yml_outputs_include_expected_fields():
    action_path = Path(__file__).parents[2] / "action.yml"
    parsed = yaml.safe_load(action_path.read_text())

    outputs = parsed["outputs"]
    assert "verdict" in outputs
    assert "findings-count" in outputs
    assert "report-path" in outputs


def test_action_yml_is_composite_action():
    action_path = Path(__file__).parents[2] / "action.yml"
    parsed = yaml.safe_load(action_path.read_text())

    runs = parsed["runs"]
    assert runs.get("using") == "composite"
    assert "steps" in runs
    assert len(runs["steps"]) > 0


def test_action_yml_installs_agentgate():
    action_path = Path(__file__).parents[2] / "action.yml"
    content = action_path.read_text()
    assert "agentgate" in content.lower()
    assert "pip" in content.lower() or "install" in content.lower()
