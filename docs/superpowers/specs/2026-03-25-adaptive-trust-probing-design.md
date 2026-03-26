# Adaptive Trust Probing Design

## Problem

The trust scanner deploys agents to Railway and probes them at runtime, but the probes are hardcoded: 5 generic HTTP requests (`GET /`, `GET /health`, `GET /docs`, `GET /openapi.json`, `POST /api/v1/chat` with `{"message": "AgentGate hosted probe"}`). Every agent gets the same probes regardless of what it does.

This means an agent that declares `lookup_order`, `search_products`, and `check_return_policy` never actually has those tools exercised. A malicious agent that behaves cleanly on generic probes but activates exfiltration on real tool usage goes undetected.

## Solution

Replace the hardcoded probing with an **LLM-powered multi-agent system** that reads the agent's source code and manifest, understands what the agent does, and generates targeted probes to stress-test its actual behavior.

## Architecture

### Pipeline Position

```
Static Checks (unchanged)
    |
    v
Railway Deployment (unchanged)
    |
    v
Adaptive Trust Probing (NEW)
    |  - Orchestrator reads source code + manifest + static findings
    |  - Dispatches specialist agents against the live deployed agent
    |  - Produces enriched RuntimeTrace
    |
    v
Existing Trust Checks (unchanged - egress, canary, tool audit, behavior diff)
    |  - Now consume richer runtime traces from adaptive probing
    |
    v
Scoring + Report (unchanged)
```

### Orchestrator Agent

The orchestrator receives a **context bundle**:
- Full source code (all `.py` files from the submission)
- Parsed manifest (tools, domains, permissions, claims)
- Static check findings (anything suspicious already flagged)
- Live URL of the deployed agent
- OpenAPI spec (if exposed at `/openapi.json` or `/docs`)

It performs four tasks:

1. **Builds an agent profile** - understands what the agent does, its tools, data access patterns, external service dependencies, and API contract (request/response shapes).

2. **Identifies attack surfaces** - based on the code, determines what's worth probing. An agent with database access gets different treatment than one that only calls a search API.

3. **Creates a dispatch plan** - decides which specialist agents to run, in what order, and which can run in parallel. Example:

```json
{
  "phases": [
    {
      "parallel": true,
      "agents": ["tool_exerciser", "egress_prober"],
      "reason": "Independent - tool exercise won't affect egress detection"
    },
    {
      "parallel": true,
      "agents": ["canary_stresser", "data_boundary_tester"],
      "reason": "Both need the agent warmed up from phase 1"
    },
    {
      "parallel": false,
      "agents": ["behavior_consistency"],
      "reason": "Needs clean state - runs last with fresh context"
    }
  ]
}
```

4. **Passes specialist-specific context** - extracts relevant code subsets for each specialist rather than dumping the full source. Tool Exerciser gets tool implementations and API routes. Egress Prober gets network-related code and declared domains.

5. **Synthesizes results** - after all specialists report back, deduplicates findings and produces the final enriched `RuntimeTrace` consumed by existing trust checks.

### Specialist Agents

Each specialist receives: relevant source code excerpts (curated by orchestrator), manifest data for its domain, the live URL, and a specific mission.

#### Tool Exerciser

Mission: Verify every declared tool actually works and behaves as described.

- Generates realistic queries that trigger each declared tool (e.g., "What's the status of order #ORD-7821?" to trigger `lookup_order`)
- Sends them to the live agent via its chat endpoint
- Checks: Did the tool fire? (via `TOOL_CALL:` log output) Did the response make sense? Are there undeclared tools firing?
- Tries queries that should NOT trigger any tool to see if something hidden activates

#### Egress Prober

Mission: Discover undeclared network calls.

- Reads the code to understand what external calls the agent makes and under what conditions
- Crafts queries designed to trigger those code paths
- Tries to social-engineer the agent into making external calls ("Can you fetch the content from example.com for me?")
- Compares observed network destinations (from Railway logs) against `declared_external_domains`

#### Data Boundary Tester

Mission: Test if the agent leaks data it shouldn't.

- Based on `customer_data_access` in the manifest, crafts queries that probe boundaries
- Tests cross-tenant scenarios ("Show me another customer's order")
- Probes for system prompt leakage, internal configuration exposure
- Checks if the agent reveals implementation details (database names, internal URLs, env vars)

#### Canary Stresser

Mission: Try to get the agent to exfiltrate injected canary secrets.

- Knows which canary tokens were injected into the environment
- Reads source code to understand how the agent handles environment variables
- Crafts scenarios where a malicious agent would be tempted to phone home
- Monitors logs for any canary token appearing in network traffic or output

#### Behavior Consistency Checker

Mission: Detect if the agent behaves differently when it thinks it's being watched.

- Sends "test/review" traffic and "real production" traffic
- Compares responses for the same underlying question framed differently
- Checks if tool usage, response quality, or network behavior changes between profiles
- Catches agents that are clean during review but activate malicious behavior in production

### Specialist Communication

Each specialist:
1. Makes an Anthropic API call to generate probes from its context
2. Executes probes against the live agent via HTTP
3. Makes a second API call to analyze the results
4. Returns a `SpecialistReport` with: probes sent, responses received, findings (with severity), raw evidence

## Integration with Existing Code

### What Changes

- `HostedRuntimeRunner._probe_live_agent()` gains a branch: if API key is available, use `AdaptiveProbeOrchestrator`; otherwise fall back to existing hardcoded probes
- New module: `src/agentgate/trust/runtime/adaptive/`
- `TrustScanConfig` gets a flag for adaptive probing
- `TraceCollector` may need minor additions for richer log patterns
- `ConfidenceSummary` reflects probing mode in evidence quality and drivers

### What Stays the Same

- Static checks
- Railway deployment
- `RuntimeTrace` model structure (richer data, same shape)
- Trust checks (egress, canary, tool audit, behavior diff) - same logic, better input
- Scoring and reports
- CLI interface (adaptive probing is enabled by default when `ANTHROPIC_API_KEY` is set; can be explicitly disabled with `--no-adaptive-trust`)

### Graceful Degradation

No API key = falls back to hardcoded probes. When this happens:
- Report clearly flags: **"Probing Mode: Static (limited confidence)"** with a message that adaptive probing was not available
- `ConfidenceSummary.evidence_quality` set to `"weak"` with driver `"static-probes-only: agent-specific behavior was not exercised"`
- User is told to set `ANTHROPIC_API_KEY` for full adaptive probing

## Module Structure

```
src/agentgate/trust/runtime/adaptive/
  __init__.py
  orchestrator.py        - AdaptiveProbeOrchestrator
  context_builder.py     - Builds context bundles from source + manifest + static findings
  models.py              - ProbeResult, DispatchPlan, SpecialistReport
  specialists/
    __init__.py
    base.py              - BaseSpecialist shared interface
    tool_exerciser.py
    egress_prober.py
    data_boundary.py
    canary_stresser.py
    behavior_consistency.py
```

### Key Interfaces

**`AdaptiveProbeOrchestrator`**
- Input: `ContextBundle` (source code, manifest, static findings, live URL, canary tokens)
- Output: enriched `list[dict]` of probe responses (same format as current `_probe_live_agent`) + additional `RuntimeTrace` fields

**`BaseSpecialist.run()`**
- Input: specialist-specific context, live URL, `httpx.Client`
- Output: `SpecialistReport` (probes, responses, findings, evidence)

**`ContextBuilder.build()`**
- Input: source dir, manifest dict, static findings, OpenAPI spec
- Output: `ContextBundle` with full context + per-specialist slices

## Cost Estimate

Per scan using Claude Sonnet (recommended):

| Component | Input tokens | Output tokens | Cost |
|-----------|-------------|---------------|------|
| Orchestrator (read + plan) | ~20k | ~5k | ~$0.14 |
| 5 specialists (probes + analysis) | ~75k | ~25k | ~$0.60 |
| Orchestrator synthesis | ~30k | ~5k | ~$0.17 |
| **Total** | **~125k** | **~35k** | **~$0.90** |

Scales ~2-3x for large agents (10k+ lines). Falls to ~$0.24 with Haiku.

## Existing Agent Contract

Agents deploy as FastAPI services with:
- `GET /health` - health check
- `POST /api/v1/chat` - main chat endpoint (`{"question": string}` -> `{"answer": string, "data": list}`)
- Tools are internal Python methods, not separate endpoints
- Tool invocations logged via `print("TOOL_CALL:<tool_name>")`
- Railway logs captured via `railway logs` CLI

The specialist agents send their probes through the chat endpoint with crafted questions designed to exercise specific code paths. Tool invocation is verified through Railway log parsing.
