# CI/CD Integration

AgentGate can be dropped into any GitHub Actions workflow to automatically run
security and trust scans on your AI agents before they reach production.

## Quick start

### 1. Add the action to a workflow

Create `.github/workflows/agentgate.yml` (or copy from
[`examples/github-action-workflow.yml`](../examples/github-action-workflow.yml)):

```yaml
name: AgentGate Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  agentgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - uses: Elliot-Sones/AgentGate@main
        with:
          scan-type: trust
          source-dir: ./my-agent
          manifest: ./my-agent/trust_manifest.yaml
          fail-on: manual_review
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. Add your API key as a secret

Go to **Settings → Secrets and variables → Actions → New repository secret** and
add `ANTHROPIC_API_KEY`.

### 3. Push and watch

On the next PR or push to `main` the workflow will run, upload a scan report as
an artifact, and fail the step if the verdict meets or exceeds the configured
threshold.

---

## Using `agentgate ci-setup`

The CLI can generate the workflow file for you:

```bash
agentgate ci-setup \
  --platform github-actions \
  --scan-type both \
  --fail-on manual_review \
  --source-dir ./my-agent \
  --manifest ./my-agent/trust_manifest.yaml
```

This writes `.github/workflows/agentgate.yml` and prints next-step instructions.

---

## Action inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `scan-type` | No | `trust` | Which scan to run: `trust`, `security`, or `both`. |
| `source-dir` | No | `.` | Path to the agent source directory. |
| `manifest` | No | `trust_manifest.yaml` | Path to the trust manifest file. |
| `fail-on` | No | `manual_review` | Verdict threshold that causes the step to fail. |
| `agent-url` | No | *(empty)* | Live agent URL — required for `security` scans. |
| `output-dir` | No | `agentgate-reports` | Directory where reports are written. |
| `agentgate-version` | No | *(latest)* | Pin to a specific AgentGate release. |
| `anthropic-api-key` | No | *(empty)* | Anthropic API key for LLM-powered features. |

### `fail-on` thresholds

The `fail-on` value controls when the step returns a non-zero exit code:

| Value | Meaning |
|---|---|
| `allow_with_warnings` | Fail on any warning or higher. |
| `manual_review` | Fail when human review is recommended *(default)*. |
| `block` | Only fail when the verdict is an outright block. |

### `scan-type` values

| Value | What runs |
|---|---|
| `trust` | Static code signals, manifest checks, dependency risk, and runtime canary/egress checks. |
| `security` | Red-team probing with prompt-injection, goal-hijacking, and other detectors. |
| `both` | Trust scan followed by security scan. |

---

## Action outputs

The action sets the following step outputs, accessible as
`${{ steps.<step-id>.outputs.<name> }}`:

| Output | Description |
|---|---|
| `verdict` | Trust verdict string or security pass rate. |
| `findings-count` | Number of findings returned by the scan. |
| `report-path` | Path to the primary JSON report inside the runner workspace. |

### Example: use outputs in a later step

```yaml
- name: Run AgentGate
  id: agentgate
  uses: Elliot-Sones/AgentGate@main
  with:
    scan-type: trust
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Print verdict
  run: |
    echo "Verdict: ${{ steps.agentgate.outputs.verdict }}"
    echo "Findings: ${{ steps.agentgate.outputs.findings-count }}"
```

---

## Posting a PR comment

```yaml
- name: Run AgentGate
  id: agentgate
  uses: Elliot-Sones/AgentGate@main
  with:
    scan-type: trust
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Comment on PR
  if: github.event_name == 'pull_request' && always()
  uses: actions/github-script@v7
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    script: |
      const verdict = '${{ steps.agentgate.outputs.verdict }}';
      const count   = '${{ steps.agentgate.outputs.findings-count }}';
      await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo:  context.repo.repo,
        issue_number: context.issue.number,
        body: `**AgentGate verdict:** \`${verdict}\` — ${count} finding(s).`,
      });
```

---

## Report artifacts

The action always uploads scan reports as a workflow artifact named
`agentgate-report` (retained for 30 days). You can download the artifact from
the **Summary** tab of any workflow run to inspect HTML, JSON, and SARIF
reports.

To consume the SARIF report in GitHub Code Scanning:

```yaml
- name: Upload SARIF to Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentgate-reports/trust_scan_report.sarif
```

---

## Generating the workflow programmatically

You can generate a workflow YAML string from Python:

```python
from agentgate.ci import generate_github_action_config

yaml_str = generate_github_action_config(
    scan_type="trust",
    fail_on="manual_review",
    source_dir="./my-agent",
    manifest="./my-agent/trust_manifest.yaml",
)

with open(".github/workflows/agentgate.yml", "w") as f:
    f.write(yaml_str)
```

---

## Full example workflow

See [`examples/github-action-workflow.yml`](../examples/github-action-workflow.yml)
for a complete workflow that demonstrates:

- Trust scan on every PR with a comment summary
- Full security + trust scan on pushes to `main`
- Nightly scan with a stricter threshold
