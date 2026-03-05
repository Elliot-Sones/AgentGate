# AgentGate

AgentGate scans AI agent submissions for a marketplace and decides whether to allow or block them. You give it the agent's source code, Docker image, and a manifest (what the agent claims it does). It runs the agent in a sandbox, watches what it actually does, and flags anything that doesn't match.

The main thing it does differently: it reads network connections from `/proc/net/tcp` inside the container instead of relying on application logs. So even if an agent suppresses all its stdout/stderr to hide what it's doing, we still see every TCP connection it makes.

## Install

```
pip install -e .
```

Needs Python 3.11+ and Docker.

## Usage

```
agentgate trust-scan \
  --image my-agent:latest \
  --source-dir ./src \
  --manifest ./trust_manifest.yaml \
  --profile both \
  --format all
```

This runs 10 checks against the agent and outputs a verdict: `allow_clean`, `allow_with_warnings`, `manual_review`, or `block`.

Reports come out as terminal output + JSON + HTML + SARIF.

## What it checks

It runs 5 static checks (just reads files, no Docker) and 5 runtime checks (runs the container).

**Static:**
- Is the manifest valid? Does it have the required fields?
- Does the source code have sketchy patterns? (`exec()`, `eval()`, `subprocess` with `shell=True`, outbound HTTP calls)
- Are there hidden instructions in prompts? ("ignore previous instructions", "exfiltrate", etc.)
- Are the dependencies legit? (checks for known typosquat packages like `request` vs `requests`)
- Is the container image signed? (optional, needs cosign)

**Runtime:**
- Runs the agent in Docker with two profiles — once with no network (`--network none`) and once with network (`--network bridge`). Both are locked down: read-only filesystem, all capabilities dropped, 512MB memory limit, unprivileged user.
- Reads `/proc/net/tcp` and `/proc/net/udp` from inside the container to see what it's connecting to. This is the part that catches agents that hide their logs.
- Compares observed connections against `declared_external_domains` in the manifest. Anything not declared = critical finding = block.
- Plants fake credentials (canary tokens) as env vars. If the agent tries to exfiltrate them, we see it.
- Compares behavior between the two profiles. If the agent only makes connections when it has network access (and does nothing in the isolated run), that's a sign it's detecting the sandbox.

## Verdicts

Worst finding wins:
- Any `critical` finding → `block`
- Any `high` finding → `manual_review`
- `medium` or `low` → `allow_with_warnings`
- Nothing failed → `allow_clean`

## Demo

There are 3 demo agents in `demo_agents/`. One is clean, one is trojanized (makes undeclared connections), one is stealth (exfiltrates data but suppresses all logs).

```
cd demo_agents && ./run_demo.sh
```

Results from an actual run:

```
Clean agent:       allow_with_warnings  — 0 critical, 0 high, 4 medium
Trojanized agent:  block                — 2 critical, 1 high, 4 medium
Stealth agent:     block                — 1 critical, 1 high, 4 medium
```

The stealth agent is the one worth looking at. It redirects stdout/stderr to `/dev/null` — `docker logs` returns nothing. We still caught it because the undeclared connection to `8.8.8.8` showed up in `/proc/net/tcp`.

## Trust manifest

Agents ship with a `trust_manifest.yaml`:

```yaml
submission_id: my-agent-v1
agent_name: My Support Agent
version: "1.0.0"
entrypoint: server.py

declared_tools:
  - lookup_order
  - search_products

declared_external_domains: []
```

If your agent calls external APIs, declare them. Undeclared connections get flagged as critical.

## CI/CD

```
agentgate trust-scan \
  --image $AGENT_IMAGE \
  --source-dir ./src \
  --manifest ./trust_manifest.yaml \
  --fail-on block \
  --quiet \
  --format sarif
```

Exits with code 1 if the verdict hits the `--fail-on` threshold. SARIF works with GitHub Advanced Security.

## Red team testing

There's also a `scan` command that tests a live agent against adversarial prompts (prompt injection, data exfiltration, tool misuse, etc). Separate from trust scanning.

```
agentgate scan http://localhost:8000/api --name "My Agent" --format all
```

## Limitations

- procfs is sampled 3 times at 400ms intervals, not continuously. Very short-lived connections could be missed.
- Static analysis is regex. Obfuscated code like `getattr(__builtins__, 'ex'+'ec')` won't get caught statically — that's what the runtime checks are for.
- Canary detection is string matching. If the agent encodes the token before sending it, the log scan misses it (but the network connection is still caught by procfs).
- On macOS Docker runs in a VM. Works fine for dev, but production should be native Linux.
