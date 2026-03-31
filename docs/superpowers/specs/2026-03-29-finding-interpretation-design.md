# Finding Interpretation & Confidence-Aware Verdicts

**Date:** 2026-03-29
**Status:** Approved

## Problem

AgentGate collapses signal extraction, interpretation, and verdicting into one step. Checks emit final risk judgments (`severity=CRITICAL, passed=False`) and policy blindly maps the worst finding to a verdict. This produces false BLOCKs on safe agents:

- A prompt injection test string in `tests/test_security.py` becomes a CRITICAL code signal finding
- Railway internal networking (10.x.x.x) becomes CRITICAL undeclared egress
- Streamlit telemetry (`browser.gatherUsageStats`) becomes CRITICAL undeclared egress
- An agent returning 502 (missing API keys) produces 6 specialist findings that inflate the verdict

The current model in `trust/policy.py` is: any CRITICAL → BLOCK. That is too blunt for a marketplace where blocking a safe agent means a seller can't list their product.

## Design Principle

**BLOCK must be rare and evidence-backed.** Ambiguous or low-coverage cases go to MANUAL_REVIEW. Missing runtime coverage reduces certainty, not truth. Raw observations stay visible, but verdicts require context.

The product promise:

- Very high precision on BLOCK (almost never wrong)
- High recall on MANUAL_REVIEW (ambiguous severe cases don't slip through)
- Raw observations are always preserved for human review

## Architecture

Three-stage pipeline replaces today's single-stage check → verdict flow:

```
Checks (observation)  →  Normalizer (context)  →  Policy (assessment)
                                                        ↑
                                                   LLM Adjudicator
                                                   (boundary cases only)
```

### Stage 1: Checks emit raw signals

Checks no longer carry a final severity or pass/fail judgment. They emit a `TrustSignal` — a raw observation with detection metadata.

```python
@dataclass
class TrustSignal:
    check_id: str
    signal_type: str           # pattern_match, outbound_connection, runtime_unavailable, ...
    title: str
    summary: str
    raw_evidence: str          # the literal match, IP, log line
    detection_method: str      # regex, procfs_socket, dns_log, llm_interpretation
    source_location: str       # file path, line number, log timestamp
    base_severity: str         # check's raw assessment before context
    category: TrustCategory
    recommendation: str
```

`base_severity` is the check's uninformed estimate. The normalizer may override it. Policy never reads `base_severity` directly.

Phase 1 rewrites `static_code_signals` and `runtime_egress` to emit `TrustSignal` natively — these are the two checks where normalization matters most, and wrapping their current output through a converter would be too lossy (they already throw away the raw structure the normalizer needs). Legacy checks that still emit `TrustFinding` are tagged `legacy_interpretation=true`, carry `attribution_confidence=low`, and are ineligible for auto-block unless corroborated.

**Corroboration rule for legacy checks**: A legacy finding can contribute to a BLOCK verdict only when at least one other finding from a *different* check family (e.g. egress vs static_code vs canary vs provenance) also has `severity` >= high and `evidence_strength` in the `strong` policy bucket. A single legacy finding alone, regardless of its `base_severity`, cannot trigger BLOCK.

### Stage 2: Normalizer adds context

The normalizer runs after all checks complete but before policy. It enriches each signal with structured context annotations:

```python
@dataclass
class SignalContext:
    file_class: str             # runtime_code, test, fixture, example, docs, tooling, vendored, generated, unknown
    reachability: str           # on_execution_path, not_reached, unknown
    destination_class: str      # platform_internal_verified, private_unattributed, declared_business,
                                # framework_telemetry, dependency_service, undeclared_known, unknown_external
    evidence_strength: str      # canonical enum — see Evidence Vocabulary below
    runtime_attribution: str    # startup, request_time, background, unknown
    attribution_confidence: str # high, medium, low
```

`SignalContext` is pure context — it does not carry severity. Severity lives exclusively on `TrustFinding`.

### Evidence Vocabulary

One canonical enum for `evidence_strength`, used everywhere:

| Value | Meaning |
|-------|---------|
| `procfs_confirmed` | Observed via procfs socket inspection — direct kernel-level evidence |
| `dns_only` | Observed via DNS resolution log but no socket-level confirmation |
| `log_only` | Observed in application/container logs but no procfs or DNS confirmation |
| `llm_inferred` | Derived from LLM interpretation of probe responses or specialist analysis |
| `heuristic` | Derived from regex or rule-based detection (e.g. static code pattern match) |
| `inconclusive` | Check ran but could not produce usable evidence (e.g. agent returned 502s) |

Policy maps these into two buckets for the decision matrix:

| Policy bucket | Maps from |
|---------------|-----------|
| **strong** | `procfs_confirmed`, or `heuristic` on a reachable execution path with `attribution_confidence` = high |
| **weak** | Everything else: `dns_only`, `log_only`, `llm_inferred`, `heuristic` with low/medium confidence, `inconclusive` |

This mapping is the single source of truth. The decision matrix in Section 4 uses only `strong` and `weak` — never raw enum values.

### Storage Shape

Context annotations are stored as a nested `SignalContext` object on `TrustFinding`, not as top-level fields:

```python
@dataclass
class TrustFinding:
    # ... existing fields (check_id, title, category, summary, recommendation, etc.) ...
    severity: TrustSeverity         # THE severity field — single source of truth
    context: SignalContext | None = None    # None for legacy findings
    base_severity: TrustSeverity | None = None  # diagnostic only — check's raw pre-context assessment
    legacy_interpretation: bool = False     # True for checks not yet emitting TrustSignal
```

**Severity has one home: `TrustFinding.severity`.** There is no separate `final_severity` field. The existing `severity` field is the single source of truth for policy, scorecard, reports, and webhooks.

The normalizer's job is to *overwrite* `severity` on each finding after applying context rules. Before normalization, `severity` holds the check's raw assessment. After normalization, `severity` holds the context-adjusted value. `base_severity` is a separate diagnostic field that preserves the pre-normalization value for transparency in reports — it is never read by policy or scoring.

For legacy checks (`legacy_interpretation=true`), the normalizer copies the existing `severity` to `base_severity`, then leaves `severity` unchanged (since it can't meaningfully re-assess without signal context). Policy applies the corroboration rule to these findings.

This avoids introducing a competing `final_severity` field. Every consumer that reads `severity` today continues to work — they just get better values after normalization.

`context` is `None` for legacy findings that haven't been migrated. Serialization: `context` is included in report JSON as a nested object. Webhook payloads do not include `context` — they use `severity` and `coverage_status` only.

**`file_class` and `reachability` are orthogonal.** A file can be `fixture` + `not_reached`, or `runtime_code` + `on_execution_path`. Policy uses both dimensions independently.

### Stage 3: Policy reads final_severity + evidence + coverage

Policy never reads `base_severity`. It uses `severity`, `evidence_strength`, and the scan's `coverage_status` to compute two separate outputs:

- **Risk verdict**: `allow_clean | allow_with_warnings | manual_review | block`
- **Coverage status**: `full | partial | limited`

These are independent. A scan can return `allow_clean + limited`.

## Section 1: Evidence Normalization Layer

### Signal-to-Finding Conversion

After all checks emit their signals, the normalizer:

1. Loads the file classification map and reachability graph from scan context (built once per scan — see Section 2)
2. Loads the destination taxonomy (see Section 3)
3. For each signal, annotates context fields and computes `severity`
4. Converts to `TrustFinding` with context attached

### Severity Override Rules

The normalizer adjusts `base_severity` → `severity` based on context:

| Condition | Effect |
|-----------|--------|
| `file_class` in (test, fixture, example, docs, tooling, vendored, generated) AND `reachability` = not_reached | Cap `severity` at info |
| `file_class` in (test, fixture, example, docs, tooling, vendored, generated) AND `reachability` = unknown | Lower severity by one band (e.g. critical → high), floor at low |
| `file_class` = test AND `reachability` = on_execution_path | Cap at medium (test code shipped in runtime image) |
| `reachability` = not_reached alone (file_class = runtime_code or unknown) | Lower severity by one band, floor at low — not_reached alone never caps to info |
| `reachability` = unknown | No downgrade — treat conservatively |
| `destination_class` = platform_internal_verified | Default to info, visible in report (not suppressed) |
| `destination_class` = declared_business | Default to info, visible in report (not suppressed) |
| `destination_class` = framework_telemetry | Default to info |
| `destination_class` = dependency_service | Info if declared, low if undeclared |
| `destination_class` = undeclared_known (telemetry) | Info |
| `destination_class` = undeclared_known (model provider / business API) | Medium |
| `destination_class` = unknown_external | Preserve or escalate base_severity |
| `evidence_strength` = llm_inferred AND `attribution_confidence` = low | Cap at medium |

**Adjudicator gate on irreversible downgrades**: Before the normalizer applies any rule that would downgrade a finding by two or more severity bands, or reduce a visible finding to info, it must first confirm `attribution_confidence` = high. If confidence is medium or low, the finding is routed to the LLM adjudicator (Section 7) before the downgrade is applied. This prevents weak-confidence normalization from making one-way decisions that the adjudicator never sees.

**No observation is ever fully suppressed.** All destination classes, including `platform_internal_verified` and `declared_business`, remain visible in the report at their default severity. The suspicious overlay (Section 3) can escalate any class after payload, timing, and attribution analysis.

`not_reached` is assigned only when non-reachability is positively established — the import walker traced from all entry roots and confirmed no import chain reaches the module. Unresolved or dynamic imports (plugin registries, framework discovery, env-driven imports, `importlib`, entry_points) result in `unknown`, not `not_reached`.

## Section 2: Context-Aware Static Checks + Reachability

### File Classification

Built once per scan and stored on `TrustScanContext`. Classification uses path heuristics:

| Class | Path patterns |
|-------|--------------|
| `test` | `test/`, `tests/`, `*_test.py`, `test_*.py`, `spec/` |
| `fixture` | `conftest.py`, `fixtures/`, `factories/` inside test directories |
| `example` | `example/`, `examples/`, `demo/`, `sample/`, `samples/` |
| `docs` | `docs/`, `doc/`, `*.md`, `*.rst` (Python files in doc directories) |
| `tooling` | `setup.py`, `setup.cfg`, `noxfile.py`, `tasks.py`, `fabfile.py`, `Makefile`, CI configs |
| `vendored` | `vendor/`, `third_party/`, `_vendor/` |
| `generated` | `*_pb2.py`, `*_pb2_grpc.py`, `generated/`, files with auto-gen markers |
| `runtime_code` | Everything else in the source tree |
| `unknown` | Can't classify |

### Reachability Analysis

A lightweight import graph walker:

1. Parse the Docker `CMD`/`ENTRYPOINT` to identify the entrypoint module. Recognize common startup forms:
   - `python app.py` → `app`
   - `python -m pkg.module` → `pkg.module`
   - `uvicorn app.main:app` → `app.main`
   - `gunicorn pkg.app:app` → `pkg.app`
2. Support multiple entry roots if the Dockerfile or config suggests them (web + worker + scheduler)
3. Walk `import X` and `from X import Y` statements recursively within the repo (not full AST — just import extraction)
4. Mark each module:
   - `on_execution_path`: reachable from an entry root via confirmed import chains
   - `not_reached`: positively established as unreachable — the walker traced from all entry roots and no import chain reaches this module. Only assigned when non-reachability is confirmed, never by default.
   - `unknown`: import couldn't be resolved, or module is loaded dynamically (plugin registries, `importlib`, `entry_points`, env-driven imports). Treat conservatively — no severity downgrades applied.

Store the classification map and reachability graph on `TrustScanContext` so all checks and the normalizer can use it without rediscovering.

### Impact on Static Code Signals

`static_code_signals.py` continues scanning all `.py` files but emits `TrustSignal` with `source_location` set. The normalizer applies file_class + reachability to determine final_severity. A risky string in `test` + `not_reached` can never produce a BLOCK on its own.

## Section 3: Infrastructure-Aware Egress Interpretation

### Destination Taxonomy

Replace the binary allowed/undeclared classification with a ranked taxonomy. Evaluated in order, first match wins:

| Class | How identified |
|-------|---------------|
| `platform_internal_verified` | Same Railway project's provisioned dependencies, known `.railway.internal` DNS, expected sidecar services. Built from the scan's own deployment context. |
| `private_unattributed` | RFC 1918 / RFC 4193 address that can't be tied to a provisioned service. |
| `declared_business` | In manifest `declared_external_domains` or user-provided allowlist. |
| `framework_telemetry` | Matched against a per-scan registry built from the repo's installed packages. |
| `dependency_service` | Inferred from installed packages or issued integrations but not explicitly declared. |
| `undeclared_known` | Resolves to a recognizable service (model provider, SaaS API) but wasn't declared by the seller. |
| `unknown_external` | Can't be attributed to any known source. |

### Per-Scan Telemetry/Dependency Registry

Built dynamically from the repo's dependency files (`requirements.txt`, `pyproject.toml`, `setup.py`):

| Package | Expected domains |
|---------|-----------------|
| `streamlit` | `browser.gatherUsageStats`, `*.streamlit.io` |
| `langchain`, `langsmith` | `api.langsmith.com`, `api.smith.langchain.com` |
| `sentry-sdk` | `*.ingest.sentry.io` |
| `opentelemetry-*` | configurable collector endpoints |
| `wandb` | `api.wandb.ai` |
| `datadog` | `*.datadoghq.com` |

This is a static lookup table that ships with AgentGate and grows over time.

### Platform Internal Detection

AgentGate already knows the Railway project ID, the dependency services it provisioned, and the internal network layout from `deployment_result`. Use that to automatically build the `platform_internal_verified` set — no manual allowlist needed for infrastructure the scan itself created.

### Suspicious as an Overlay, Not a Class

`suspicious` is not a destination class. It's an assessment overlay computed by policy based on the combination of:

- Destination class
- Evidence strength (procfs_confirmed vs log_only)
- Payload shape (canary tokens, bulk data, credential patterns in request body)
- Timing (startup vs request_time)
- Attribution confidence

A `framework_telemetry` destination can still be suspicious if it carries canary tokens in the payload. A `private_unattributed` destination at startup with no payload is likely benign. Policy makes that call.

### Default Severity by Destination Class

No observation is ever suppressed. All classes default to a visible severity and remain in the report. The suspicious overlay can escalate any class after payload, timing, and attribution analysis.

| Destination class | Default final_severity |
|-------------------|----------------------|
| `platform_internal_verified` | info (visible, not suppressed) |
| `private_unattributed` | medium |
| `declared_business` | info (visible, not suppressed) |
| `framework_telemetry` | info |
| `dependency_service` (declared) | info |
| `dependency_service` (undeclared) | low |
| `undeclared_known` (telemetry) | info |
| `undeclared_known` (model provider / business API) | medium |
| `unknown_external` | high |

### Runtime Timing

Separate startup egress from request-time egress using `runtime_attribution`:

- `startup`: observed during container boot before any probe was sent
- `request_time`: observed during or immediately after a probe
- `background`: observed during idle periods between probes

Startup egress to framework telemetry or dependency services is almost always benign. Request-time egress to unknown destinations is the strongest exfil signal.

## Section 4: Confidence-Aware Verdict Policy

### Two Separate Outputs

- **Risk verdict**: `allow_clean | allow_with_warnings | manual_review | block`
- **Coverage status**: `full | partial | limited`

Reuse the existing `CoverageSummary` model from `trust/models.py`:

- `full`: Static checks ran AND response-dependent runtime specialist families executed with meaningful responses
- `partial`: Runtime ran but only some specialist families executed, or the agent was deployed and reachable but auth-gated or missing third-party credentials AgentGate does not have (valid 401/403/422 responses from discovered routes count as reachability, not unresponsiveness)
- `limited`: Deployment failed, agent completely unresponsive (no transport-level interaction succeeded), or only passive/startup evidence exists

### Decision Matrix

| Final Severity | Evidence Strength | Verdict |
|---|---|---|
| critical | strong (procfs + payload analysis OR strong static on reachable path) | **block** |
| critical | weak (log-only, LLM-inferred, or attribution_confidence = low) | **manual_review** |
| high | strong | **manual_review** |
| high | weak or unknown | **allow_with_warnings** |
| medium | any | **allow_with_warnings** |
| low / info | any | **allow_clean** |

### Key Rules

1. **BLOCK requires strong evidence.** Either procfs-confirmed egress with suspicious payload, OR strong static evidence on a reachable execution path (hardcoded exfil target, obvious backdoor in shipped runtime code). Weak evidence alone cannot BLOCK.

2. **Missing runtime coverage reduces certainty, not truth.** Runtime unavailability lowers `coverage_status`, not `severity` of static findings. Strong static evidence can still BLOCK without runtime confirmation.

3. **Accumulation is diversity-aware.** Multiple findings escalate only when they come from distinct check families (static_code, provenance, egress, canary). Ten medium findings from one noisy rule don't escalate the same way as five independent mediums across different checks.

4. **Coverage gap is transparent with a default consumer contract.** `coverage_status` appears as a separate field in the API response and report. To prevent downstream consumers from ignoring `limited` (e.g. treating `allow_clean` as "passed" without noticing incomplete coverage), the API also returns a `coverage_recommendation` field. When `coverage_status = limited` and `verdict != block`, `coverage_recommendation` defaults to `manual_review` — meaning the consumer should treat it as requiring human review unless they explicitly opt into accepting limited-coverage scans. This makes `limited` hard to ignore in marketplace flows.

## Section 5: Runtime Coverage Handling

### Coverage Status Definition

Single canonical definition (referenced by Section 4 and all other sections):

- **full**: Static checks ran AND response-dependent runtime specialist families executed with meaningful responses (2xx, 4xx with parseable body, or structured error responses that demonstrate the agent processed the request)
- **partial**: Agent was deployed and reachable at the transport level — valid HTTP responses were received (including 401, 403, 422, or other auth/validation errors) — but some specialist families were skipped due to precondition failures (e.g. no memory system, no customer data access declared) or the agent requires third-party credentials AgentGate does not have
- **limited**: Deployment failed, agent completely unresponsive at the transport level (connection refused, timeouts, no TCP handshake), or only passive/startup evidence was collected

**Key distinction**: A 401/403/422 response proves the agent is running and processing requests — that is `partial`, not `limited`. Only transport-level failures (connection refused, timeout, no response) qualify as `limited`.

### Impact on Findings

- Findings from runtime checks where the agent was unresponsive have `evidence_strength` set to `inconclusive`
- Findings from static checks are unaffected by runtime coverage
- Specialist reports with "all 502" observations are preserved in the full report as context, not as grounds for severity escalation

## Section 6: Specialist Dispatch Gating

### Health Gate

Before dispatching the specialist team, the orchestrator runs a health gate:

1. Check deployment readiness status from Railway
2. Discover available routes (OpenAPI spec if available, or generated probe paths from submission profile)
3. Send 2-3 probes to discovered routes, using platform-issued sandbox credentials if available

**Health gate outcomes** (aligned with coverage status definitions from Section 5):

- **passed**: At least one probe received an HTTP response generated by the application (any status code — 200, 401, 403, 422, and application-level 500 all count, as long as the response came from the agent process, not the infrastructure proxy). The test: the response body is JSON, has application-specific headers, or is not a generic Railway/proxy error page. Coverage is `full` or `partial` depending on how many specialist preconditions are met.
- **failed**: All probes received transport-level failures (connection refused, timeout, no TCP handshake), or only infrastructure proxy errors (Railway 502 "Application failed to respond", generic HTML 503 pages with no application-specific content). Coverage is `limited`. Response-dependent specialists are skipped; passive observation continues.

### Preconditions

| Specialist | Precondition | Skip reason |
|---|---|---|
| tool_exerciser | Health gate passed | "Agent unresponsive; tool exercise requires working responses" |
| egress_prober (active stimulation) | Health gate passed | "Agent unresponsive; active egress probing requires working responses" |
| canary_stresser | Health gate passed | "Agent unresponsive; canary testing requires working responses" |
| data_boundary | Health gate passed + manifest declares customer data access | "No customer data access declared or agent unresponsive" |
| behavior_consistency | Health gate passed with 2+ distinct response contents | "Insufficient response diversity for consistency comparison" |
| memory_poisoning | Health gate passed + source shows memory/state persistence | "No memory system detected or agent unresponsive" |

### Passive Observation Always Runs

Even when the health gate fails, passive runtime observation continues:

- Startup egress capture (network traces during container boot)
- Process/network socket monitoring (procfs)
- Dependency sidecar traffic attribution
- Container inspect data (user, capabilities, network mode)

This provides useful evidence without requiring the agent to respond.

### First-Class Skip Reporting

The orchestrator records each specialist's execution status:

```python
@dataclass
class SpecialistDispatchResult:
    specialist: str
    status: str        # executed, skipped, failed
    skip_reason: str   # empty if executed
    precondition: str  # what was checked
```

This feeds directly into coverage reporting. No inference needed.

## Section 7: LLM Adjudicator

### Separate from Existing LLMJudge

The existing `LLMJudge` in `evaluation/llm_judge.py` is built for attack-response scoring in the Phase 1 detector pipeline. Trust adjudication needs a separate component with different prompts and structured outputs.

### When It Runs

The adjudicator runs at two points:

**During normalization** — before any irreversible downgrade. When the normalizer is about to downgrade a finding by two or more severity bands, or reduce a visible finding to info/effectively suppressed, it checks `attribution_confidence` first. If confidence is not high, the finding is routed to the adjudicator before the downgrade is applied. This prevents weak-confidence normalization from making one-way decisions the adjudicator never sees.

**At the policy boundary** — when a normalized finding is about to affect the verdict threshold between BLOCK ↔ MANUAL_REVIEW or MANUAL_REVIEW ↔ ALLOW_WITH_WARNINGS. Specifically:

1. **Ambiguous file classification**: A pattern match in `runtime_code` where the matched line looks like it could be a test string, documentation comment, or example — ask: "Here is the matched line and 10 lines of surrounding context. Is this a security test/example or a live code path?"

2. **Ambiguous egress destination**: A domain that doesn't match the dependency registry or any known telemetry — ask: "Here is the domain, the repo's package list, and the network request context. Is this likely framework/dependency traffic or an unknown external destination?"

3. **Specialist finding validation**: When a specialist flags something at high/critical but the evidence is limited — ask the adjudicator to review the probe/response pair before the finding gets its severity set.

### When It Doesn't Run

- Deterministic cases (test file path, known Railway IP, declared domain) — no adjudicator needed
- Low-severity findings — not worth the cost
- Open-ended repo safety assessment — too broad, unreliable

### Budget

Capped at N adjudicator calls per scan (configurable, default 5). If budget exhausted, remaining ambiguous findings keep their heuristic classification with `attribution_confidence: low`, which prevents them from reaching BLOCK.

### Output

```python
@dataclass
class AdjudicatorResult:
    finding_id: str
    original_severity: str
    adjusted_severity: str
    confidence: float          # 0.0 - 1.0
    rationale: str             # one-sentence explanation
    evidence_cited: list[str]  # specific lines/facts the adjudicator referenced
```

## API / Report Impact

### API Response Changes

`ScanResponse` gains:

```python
coverage_status: str | None          # full, partial, limited
coverage_detail: str | None          # human-readable explanation
coverage_recommendation: str | None  # manual_review when limited + non-block, null otherwise
```

`verdict` and `coverage_status` are independent fields. No change to existing verdict enum values. `coverage_recommendation` provides a default consumer action so that `limited` coverage is hard to ignore in downstream flows.

### Report Changes

The full report (`/v1/scans/{id}/report`) includes:

- Each finding's context annotations (`file_class`, `reachability`, `destination_class`, `evidence_strength`, etc.)
- `base_severity` (diagnostic only) and `severity` (normalizer-adjusted, used for verdicting) visible for transparency
- Specialist dispatch results with skip reasons
- Adjudicator decisions with rationale (when used)
- Coverage summary with clear explanation of what was and wasn't tested

### Score Aggregation

`base_severity` is diagnostic metadata and must never affect the scorecard. All severity counts, verdict computation, and webhook score use `severity` (the normalizer-adjusted value) only. The `TrustScorecard` model counts findings by `severity`, not `base_severity`.

### Webhook Changes

Webhook payload gains `coverage_status` and `coverage_recommendation` fields alongside existing `verdict` and `score`. Both fields are included so that webhook-only consumers get the same `manual_review` guidance for limited-coverage scans that API-polling consumers get. A marketplace relying on webhooks must not be able to miss the coverage signal.

## Migration

### Phase 1: Signal model + normalizer + high-impact check rewrites

- Add `TrustSignal` model and `SignalContext` model
- Rewrite `static_code_signals` to emit `TrustSignal` natively with `source_location`, `detection_method`, and `raw_evidence`
- Rewrite `runtime_egress` to emit `TrustSignal` natively with destination metadata, timing, and evidence provenance
- Build the normalizer: file classification, reachability graph, destination taxonomy, severity override rules
- Build confidence-aware policy reading `severity`
- Legacy checks that still emit `TrustFinding` are tagged `legacy_interpretation=true` with `attribution_confidence=low` and are ineligible for auto-block unless corroborated
- Add `coverage_status`, `coverage_recommendation` to API response
- Add specialist dispatch gating with health gate and preconditions

### Phase 2: Remaining check rewrites + adjudicator

- Migrate remaining checks to emit `TrustSignal` directly, prioritized by false-positive impact
- Build `TrustAdjudicator` component (separate from existing `LLMJudge`)
- Wire adjudicator into normalizer for irreversible-downgrade cases and policy boundary cases
- Add budget tracking
- Remove `legacy_interpretation` flag as checks are migrated

## Language Scope

Phase 1 targets **Python-based agents only**. The concrete mechanics are Python-first:

- Docker entrypoint parsing recognizes Python startup forms (`python`, `uvicorn`, `gunicorn`, `python -m`)
- Reachability analysis walks Python `import` / `from X import Y` statements
- Dependency discovery reads `requirements.txt`, `pyproject.toml`, `setup.py`
- Static code signals scan `*.py` files
- The telemetry/dependency registry maps Python packages to expected domains

Node.js, Go, Java, or other runtime agents are not in scope for Phase 1. The architecture (signals, normalizer, policy) is language-agnostic; only the check implementations and reachability walker are Python-specific. Extending to other languages requires new check implementations and entrypoint parsers, not architectural changes.

## Scope Exclusions

- **Benchmark suite**: Separate effort. Labeled corpus of safe/unsafe repos to validate policy changes.
- **New specialist agents**: The 6 existing specialists are sufficient. Gating and preconditions are in scope; new specialist types are not.
- **Phase 1 detector pipeline changes**: This spec covers the Phase 2 trust scanner only.
- **Per-client policy customization**: Single global policy for now. Per-client overrides are a future extension.
- **Non-Python agent support**: Phase 1 is Python-only. See Language Scope above.
