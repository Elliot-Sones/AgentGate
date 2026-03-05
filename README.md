# AgentScorer

**Trust verification for AI agents before they reach production.**

AgentScorer is a security scanner built for AI agent marketplaces. It answers one question: *should this agent be allowed to run?* It inspects the agent's code, runs it in a locked-down sandbox, monitors what it actually does at the kernel level, and returns a clear verdict — ALLOW or BLOCK — with evidence.

```
                  ┌─────────────┐
  Agent Submission │  AgentScorer │    ALLOW  ✓
  ────────────────►│             ├───────────────►  Published
                  │  Static     │
  Source Code      │  Sandbox    │    BLOCK  ✗
  Docker Image     │  Kernel     ├───────────────►  Rejected
  Manifest         │  Verdict    │
                  └─────────────┘
```

---

## The Problem

Agent marketplaces let third-party developers publish AI agents that interact with real systems — databases, APIs, user data. A malicious or poorly built agent could:

- **Steal data** — quietly send customer records, API keys, or credentials to an external server
- **Hide its behavior** — suppress logs so traditional monitoring sees nothing
- **Lie about what it does** — declare three tools in its manifest but secretly use five
- **Act differently when watched** — behave perfectly in review, then turn malicious in production

Log-based scanners can't catch agents that hide their logs. AgentScorer reads directly from the operating system kernel, so it catches connections even when the agent tries to cover its tracks.

---

## How It Works

AgentScorer runs four layers of analysis on every submission:

### 1. Static Analysis

Reads the agent's source code and configuration without running it. Looks for:
- Suspicious code patterns (dynamic `exec()`, shell commands, outbound HTTP calls)
- Hidden instructions buried in prompts ("ignore all previous instructions", "exfiltrate")
- Typosquatted or malicious dependencies
- Missing or invalid manifest fields
- Unsigned container images

### 2. Sandbox Testing

Runs the agent twice in Docker containers:
- **Review profile** — completely isolated, no network access
- **Production-like profile** — network enabled, mimicking real deployment

Then compares what happened. A trustworthy agent behaves the same in both. A malicious agent that detects isolation and waits for production to act will show differences between the two runs.

### 3. Kernel-Level Detection

While the agent runs, AgentScorer reads `/proc/net/tcp` directly from the container's kernel. This is the key differentiator:

- Traditional scanners parse application logs — if the agent suppresses `stdout`/`stderr`, those scanners see nothing
- AgentScorer reads the operating system's socket table, which the agent cannot hide from
- Every TCP connection is captured regardless of what the agent does to its own logs

AgentScorer also seeds fake credentials (canary tokens) into the environment. If the agent touches or exfiltrates them, it's caught.

### 4. Automatic Verdict

All findings are scored by severity and rolled up into a single verdict:

| Verdict | Meaning |
|---|---|
| **ALLOW_CLEAN** | No issues found |
| **ALLOW_WITH_WARNINGS** | Minor issues (low/medium severity) — acceptable |
| **MANUAL_REVIEW** | Serious concerns (high severity) — needs human review |
| **BLOCK** | Critical issue found — do not publish |

---

## What It Catches

| Issue | How It's Detected |
|---|---|
| Undeclared network connections | Kernel socket inspection + egress monitoring |
| Data theft / credential exfiltration | Canary tokens seeded into the environment |
| Undeclared tool usage | Runtime tool audit vs. manifest declarations |
| Sandbox evasion (behaves differently in production) | Behavioral diff between review and production profiles |
| Suspicious code patterns | Static analysis of source files |
| Hidden prompt instructions | Prompt and tool inspection |
| Bad or typosquatted dependencies | Dependency risk analysis |
| Unsigned or mutable container images | Cosign signature verification |

---

## See It In Action

The repo includes three demo agents that demonstrate different security outcomes.

### Prerequisites

- **Docker** (running)
- **Python 3.11+**

### Install

```bash
cd agentscorer
pip install -e .
```

### Run the Demo

```bash
cd demo_agents
./run_demo.sh
```

### What You'll See

The demo builds and scans three agents:

| Agent | What It Does | Expected Verdict |
|---|---|---|
| **Clean Support Agent** | Legitimate customer support bot. Declares its tools, no hidden behavior. | ALLOW |
| **Trojanized Support Agent** | Looks like a support bot but secretly exfiltrates data to an external server. | BLOCK |
| **Stealth Exfil Agent** | Exfiltrates data *and* suppresses all logs to hide its activity. | BLOCK |

**The stealth agent is the differentiator.** It redirects `stdout` and `stderr` to `/dev/null` — log-based scanners would see a perfectly quiet, well-behaved agent. AgentScorer catches it anyway by reading `/proc/net/tcp` at the kernel level and detecting the undeclared outbound connection.

The demo generates HTML, JSON, and SARIF reports in the `demo_output/` directory.

---

## Scan Your Own Agent

```bash
agentscorer trust-scan \
  --source-dir ./my-agent-src \
  --image my-agent:latest \
  --manifest ./my-agent-src/trust_manifest.yaml \
  --profile both \
  --format all
```

### Trust Manifest

Every agent submission needs a `trust_manifest.yaml` that declares what the agent does:

```yaml
submission_id: my-agent-v1
agent_name: My Support Agent
version: "1.0.0"
entrypoint: server.py
description: Customer support agent for order lookups

declared_tools:
  - lookup_order
  - search_products
  - check_return_policy

declared_external_domains: []

permissions:
  - read_orders
  - read_products
```

AgentScorer compares what the agent *declares* against what it *actually does* at runtime.

### Output

The scan produces reports in four formats:

- **Terminal** — colored summary with finding details
- **HTML** — self-contained web page to share with reviewers
- **JSON** — machine-readable for dashboards and automation
- **SARIF** — plugs into GitHub Advanced Security and code editors

---

## Understanding the Report

### Verdicts

| Verdict | Action | Triggered By |
|---|---|---|
| `ALLOW_CLEAN` | Publish automatically | All checks passed |
| `ALLOW_WITH_WARNINGS` | Publish with notes | Low or medium severity findings |
| `MANUAL_REVIEW` | Send to human reviewer | High severity findings |
| `BLOCK` | Reject submission | Critical severity findings |

### Severity Levels

| Severity | Meaning | Example |
|---|---|---|
| **CRITICAL** | Immediate block | Undeclared network egress, canary token exfiltration |
| **HIGH** | Requires review | Hidden prompt instructions, undeclared tools, unsigned image |
| **MEDIUM** | Worth noting | Outbound HTTP calls in code, missing lockfile |
| **LOW** | Minor concern | Base64 decode usage |
| **INFO** | Informational | Check passed successfully |

### Finding Categories

Each finding is tagged with a category: `SUPPLY_CHAIN`, `PROVENANCE`, `HIDDEN_BEHAVIOR`, `EGRESS`, `CANARY`, `TOOL_INTEGRITY`, `SANDBOX_EVASION`, or `DECLARATION`.

---

## CI/CD Integration

Add a trust scan to your pipeline with a single command:

```bash
agentscorer trust-scan \
  --image $AGENT_IMAGE \
  --source-dir ./src \
  --manifest ./trust_manifest.yaml \
  --profile both \
  --fail-on block \
  --quiet \
  --format sarif
```

The `--fail-on` flag sets the verdict threshold. If the scan produces a verdict at or above that level, the command exits with code 1 and your pipeline fails.

| `--fail-on` value | Pipeline fails when verdict is... |
|---|---|
| `block` | BLOCK |
| `manual_review` | MANUAL_REVIEW or BLOCK |
| `allow_with_warnings` | ALLOW_WITH_WARNINGS, MANUAL_REVIEW, or BLOCK |

---

## Red Team Testing (Phase 1)

AgentScorer also includes a `scan` command for adversarial prompt-injection testing against live agents. This is separate from the trust scan — it tests how well an agent resists manipulation attempts rather than whether the agent itself is malicious.

```bash
agentscorer scan http://localhost:8000/api \
  --name "My Agent" \
  --budget 500 \
  --format all
```

It throws ~130 attack payloads across 12 categories (prompt injection, data exfiltration, tool misuse, goal hijacking, and more), grades each response as pass or fail, and generates a scorecard. Optional features include LLM-generated attacks tailored to your specific agent, multi-turn adaptive strategies, and payload obfuscation.

Run `agentscorer scan --help` for all options.

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python 3.11+** | Required |
| **Docker** | Required for trust-scan (sandbox execution) |
| **cosign** | Optional — for container image signature verification |
| **syft** | Optional — for SBOM generation |
| **trivy** | Optional — for vulnerability scanning |
| **Anthropic API key** | Optional — enables LLM-generated attacks and judge evaluation in Phase 1 scans |
