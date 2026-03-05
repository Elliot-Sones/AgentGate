<div align="center">

<h1>AgentGate</h1>

<p><strong>Trust verification for AI agents before they reach production.</strong></p>

<p>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/docker-required-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker Required"></a>
  <a href="https://github.com/Elliot-Sones/Agent_Malware_Tester"><img src="https://img.shields.io/badge/version-2.0.0-green?style=flat-square" alt="Version 2.0.0"></a>
</p>

<p>
  AgentGate is a security scanner built for AI agent marketplaces.<br>
  It inspects agent code, runs it in a locked-down sandbox, monitors behavior at the kernel level,<br>
  and returns a clear verdict — <strong>ALLOW</strong> or <strong>BLOCK</strong> — with evidence.
</p>

<br>

```
  Agent Submission                                ALLOW  ✓
  ───────────────►  ┌─────────────────┐  ───────────────►  Published
                    │   AgentGate   │
  Source Code       │                 │
  Docker Image      │  Static         │   BLOCK  ✗
  Trust Manifest    │  Sandbox        │  ───────────────►  Rejected
                    │  Kernel         │
                    │  Verdict        │
                    └─────────────────┘
```

</div>

---

## :rocket: Quick Start

**1. Install**

```bash
pip install -e .
```

**2. Run the demo** (requires Docker)

```bash
cd demo_agents && ./run_demo.sh
```

**3. Scan your own agent**

```bash
agentgate trust-scan \
  --image my-agent:latest \
  --source-dir ./my-agent-src \
  --manifest ./my-agent-src/trust_manifest.yaml \
  --profile both \
  --format all
```

---

## :warning: The Problem

Agent marketplaces let third-party developers publish AI agents that interact with real systems — databases, APIs, user data. A malicious or poorly built agent could:

- **Steal data** — quietly send customer records, API keys, or credentials to an external server
- **Hide its behavior** — suppress logs so traditional monitoring sees nothing
- **Lie about what it does** — declare three tools in its manifest but secretly use five
- **Act differently when watched** — behave perfectly in review, then turn malicious in production

Log-based scanners can't catch agents that hide their logs. AgentGate reads directly from the operating system kernel — it catches connections even when the agent covers its tracks.

---

## :mag: How It Works

AgentGate runs four layers of analysis on every submission:

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

Then compares what happened. A trustworthy agent behaves the same in both. A malicious agent that detects isolation and waits for production will show differences between the two runs.

### 3. Kernel-Level Detection

While the agent runs, AgentGate reads `/proc/net/tcp` directly from the container's kernel. This is the key differentiator:

- Traditional scanners parse application logs — if the agent suppresses `stdout`/`stderr`, those scanners see nothing
- AgentGate reads the operating system's socket table, which the agent **cannot** hide from
- Every TCP connection is captured regardless of what the agent does to its own logs

AgentGate also seeds fake credentials (canary tokens) into the environment. If the agent touches or exfiltrates them, it's caught.

### 4. Automatic Verdict

All findings are scored by severity and rolled up into a single verdict:

| Verdict | Meaning |
|---|---|
| `ALLOW_CLEAN` | No issues found |
| `ALLOW_WITH_WARNINGS` | Minor issues — acceptable |
| `MANUAL_REVIEW` | Serious concerns — needs human review |
| `BLOCK` | Critical issue — do not publish |

---

## :shield: What It Catches

| Issue | Detection Method |
|---|---|
| Undeclared network connections | Kernel socket inspection + egress monitoring |
| Data theft / credential exfiltration | Canary tokens seeded into the environment |
| Undeclared tool usage | Runtime tool audit vs. manifest declarations |
| Sandbox evasion | Behavioral diff between review and production profiles |
| Suspicious code patterns | Static analysis of source files |
| Hidden prompt instructions | Prompt and tool inspection |
| Typosquatted dependencies | Dependency risk analysis |
| Unsigned container images | Cosign signature verification |

---

## :test_tube: See It In Action

The repo includes three demo agents that demonstrate different security outcomes.

| | Agent | Behavior | Expected Verdict |
|---|---|---|---|
| :white_check_mark: | **Clean Support Agent** | Legitimate support bot. Declares its tools, no hidden behavior. | `ALLOW` |
| :x: | **Trojanized Support Agent** | Looks like a support bot but secretly exfiltrates data. | `BLOCK` |
| :x: | **Stealth Exfil Agent** | Exfiltrates data *and* suppresses all logs to hide it. | `BLOCK` |

> **The stealth agent is the differentiator.** It redirects `stdout` and `stderr` to `/dev/null` — log-based scanners would see a perfectly quiet, well-behaved agent. AgentGate catches it anyway by reading `/proc/net/tcp` at the kernel level.

Reports (HTML, JSON, SARIF) are saved to `demo_output/`.

---

## :page_facing_up: Trust Manifest

Every agent submission needs a `trust_manifest.yaml` declaring what the agent does. AgentGate compares declarations against actual runtime behavior.

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

---

## :gear: CI/CD Integration

Add a trust scan gate to your pipeline:

```bash
agentgate trust-scan \
  --image $AGENT_IMAGE \
  --source-dir ./src \
  --manifest ./trust_manifest.yaml \
  --profile both \
  --fail-on block \
  --quiet \
  --format sarif
```

The `--fail-on` flag sets the verdict threshold. If the scan produces a verdict at or above that level, the command exits with code 1 and your pipeline fails.

| `--fail-on` value | Pipeline fails on |
|---|---|
| `block` | `BLOCK` |
| `manual_review` | `MANUAL_REVIEW` or higher |
| `allow_with_warnings` | `ALLOW_WITH_WARNINGS` or higher |

---

## :crossed_swords: Red Team Testing

AgentGate also includes a `scan` command for adversarial prompt-injection testing against live agents. This tests how well an agent **resists manipulation** rather than whether the agent itself is malicious.

```bash
agentgate scan http://localhost:8000/api \
  --name "My Agent" \
  --budget 500 \
  --format all
```

Throws ~130 attack payloads across 12 categories (prompt injection, data exfiltration, tool misuse, goal hijacking, and more), grades each response, and generates a scorecard. Optional features include LLM-generated attacks tailored to your agent, multi-turn adaptive strategies (PAIR, Crescendo, TAP), and payload obfuscation.

Run `agentgate scan --help` for all options.

---

<details>
<summary><strong>:bar_chart: Understanding the Report</strong></summary>

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

### Report Formats

| Format | Use Case |
|---|---|
| **Terminal** | Colored summary with finding details |
| **HTML** | Self-contained web page to share with reviewers |
| **JSON** | Machine-readable for dashboards and automation |
| **SARIF** | Plugs into GitHub Advanced Security and code editors |

</details>

---

## :package: Requirements

| Requirement | | Notes |
|---|---|---|
| Python 3.11+ | Required | Runtime |
| Docker | Required | Sandbox execution for trust-scan |
| cosign | Optional | Container image signature verification |
| syft | Optional | SBOM generation |
| trivy | Optional | Vulnerability scanning |
| Anthropic API key | Optional | LLM-generated attacks and judge evaluation in Phase 1 |
