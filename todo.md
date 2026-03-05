# AgentScorer — Roadmap

Phased build plan organized by dependency order. Each phase builds on the previous.

---

## Completed

- [x] Transparent pass/fail scoring (replaced exponential decay)
- [x] DetectorSummary + FailedTest models
- [x] Terminal, JSON, HTML reports updated
- [x] All 26 tests passing
- [x] Phase 1: Make It Work for Real Agents (43 tests passing)
- [x] Phase 2 & 3: Core Upgrade + Advanced Features (77 tests passing)

---

## ~~Phase 1: Make It Work for Real Agents~~ ✓ DONE

Goal: A developer with any HTTP agent can run `agentscorer scan` and get meaningful results.

### 1.1 OpenAI Messages Adapter ✓
> Blocks scanning most production agents — #1 priority

- [x] New file: `src/agentscorer/adapters/openai_chat.py`
- [x] `OpenAIChatAdapter(AgentAdapter)` — sends `{"messages": [{"role": "user", "content": "..."}], "model": "..."}` format
- [x] CLI gets `--adapter openai` flag (default stays `http`) + `--model` option
- [x] Export from `adapters/__init__.py`
- [x] Tests for OpenAI adapter (7 tests)

### 1.2 Re-integrate AttackerAgent into Scanner ✓
> Blocks domain-specific attacks. AttackerAgent exists and works — just needs calling.

- [x] `Scanner.run()` calls `AttackerAgent.generate_tests()` after detector selection, before execution
- [x] Generated TestCases routed to the right detector based on `attack_vector` via `ATTACK_VECTOR_TO_DETECTOR` map
- [x] Requires `ANTHROPIC_API_KEY`; gracefully skips if not set
- [x] Tests for attacker integration (3 tests)

### 1.3 Wire LLM Judge into Detector Evaluation ✓
> Blocks accurate evaluation. Catches the ~30% of ambiguous cases heuristics miss.

- [x] `BaseDetector._refine_with_judge()`: if heuristic confidence < 0.8, call `LLMJudge.evaluate()`
- [x] LLMJudge already handles budget tracking (`can_call_judge`)
- [x] Requires `ANTHROPIC_API_KEY`; falls back to heuristic-only if not set
- [x] Tests for LLM Judge integration (3 tests)

### 1.4 Probe Endpoint Before Scanning ✓
> Blocks good UX for new users. Fail fast instead of cryptic mid-scan errors.

- [x] Before running detectors, send a simple "hello" to verify agent is reachable
- [x] Check: is it alive? Does it return non-empty response? Is status < 400?
- [x] Helpful error message on failure (`ProbeError` with diagnostic tip in CLI)
- [ ] Optionally auto-detect request/response field names (deferred to Phase 2)

**After Phase 1:**
```
agentscorer scan https://my-agent.com/v1/chat --adapter openai --name "My Bot"

1. Probe: verify agent is alive and responding
2. Static payloads: 6 detectors generate test cases from payloads.py
3. AttackerAgent: Claude generates domain-specific attacks → merged into detectors
4. Execute: send all payloads to agent (3x each)
5. Evaluate: heuristic first → LLM Judge for ambiguous cases
6. Score: transparent pass/fail → letter grade
7. Report: terminal + HTML + JSON
```

---

## ~~Phase 2: Core Upgrade~~ ✓ DONE

### 2.4 Fix False-Positive Heuristics ✓
- [x] Refusal-context filtering in prompt_injection.py and system_prompt_leak.py
- [x] ±100 char window check: if compliance indicator appears near refusal indicator, filter it out

### 2.1 LLM Judge as Primary Evaluator ✓
- [x] `evaluation_mode` config: "heuristic" (default) or "judge"
- [x] In "judge" mode, ALL non-error results sent to LLM judge (budget permitting)
- [x] CLI `--eval-mode` option

### 2.3 Payload Encoding/Obfuscation Converters ✓
- [x] 5 converters: Base64, ROT13, UnicodeHomoglyph, CharSplit, MarkdownEscape
- [x] Converter expansion in BaseDetector.run() multiplies test cases
- [x] CLI `--converters/--no-converters` flag

### 2.2 Multi-Turn Adaptive Attack Engine ✓
- [x] PAIR-style iterative refinement: generate → target → read response → refine → repeat
- [x] AdaptiveAttacker with per-vector attack objectives
- [x] CLI `--adaptive/--no-adaptive`, `--adaptive-turns`

---

## ~~Phase 3: Advanced Features~~ ✓ DONE

### 3.2 Goal Hijacking & XPIA Detectors ✓
- [x] GoalHijackingDetector (OWASP ASI-01): direct, indirect, multi-turn hijacking
- [x] XPIADetector: document injection, code injection, URL injection

### 3.3 CI/CD Integration ✓
- [x] `--fail-below` (0.0-1.0): exit code 1 if pass rate below threshold
- [x] `--quiet`: suppress terminal output
- [x] SARIF 2.1.0 report format for GitHub Advanced Security / VS Code

### 3.1 Advanced Attack Strategies ✓
- [x] Strategy registry: pair, crescendo, tap
- [x] CrescendoStrategy: gradual multi-turn escalation
- [x] TAPStrategy: tree of attacks with pruning (3 candidates/turn)
- [x] CLI `--attack-strategy`

### 3.4 Parallel Detector Execution ✓
- [x] `asyncio.gather()` for concurrent detector runs
- [x] `asyncio.Lock` on ScanBudget for thread-safe budget tracking

---

## Future

### Additional Detectors
- [ ] BOLA: access other users' resources by manipulating IDs
- [ ] BFLA: call unauthorized functions/endpoints
- [ ] SSRF: make agent fetch from internal URLs
- [ ] Content Policy: does agent refuse harmful content generation?

### Detector Selector
- [ ] Claude analyzes agent description + probe response → picks relevant detectors

### Regression Test Export
- [ ] Convert scan findings into reusable test suite JSON
- [ ] `agentscorer retest --suite previous_findings.json`

### Comparison Reports
- [ ] Scan twice, diff the results: what improved, what regressed

### WebSocket + Streaming Adapters
- [ ] WebSocket adapter for real-time agents
- [ ] SSE streaming adapter

### Benchmark Against AgentDojo
- [ ] Test against AgentDojo's 629 security cases
- [ ] Replace circular MockAdapter tests with real recordings

---

## Migration Notes

Items from the old todo and where they went:

| Old Item | New Location | Notes |
|---|---|---|
| Scoring Overhaul | Completed | Done in v1 |
| Detector Selector | Phase 2.1 | Depends on probe (1.4) |
| Multi-Turn Adaptive | Phase 2.2 | Merged with "Better Attacker Agent" — same work |
| Better Attacker Agent | Phase 2.2 | Merged with multi-turn — iterative attacks = adaptive attacks |
| Better Hallucination | Phase 2.4 | Depends on LLM Judge (1.3) |
| Scale to Real Agents | Phase 1.1 + 3.5 | OpenAI adapter is the real blocker; WS/streaming is Phase 3 |
| Additional Detectors | Phase 3.1 | Same, minus DoS (out of scope) and Tool Safety (covered by ToolMisuse detector) |
| MockAdapter Rethink | Phase 3.6 | Benchmark replaces circular tests |
| Report Improvements | Phase 2.3 + 3.2 + 3.3 | Split by dependency: CI flags in 2, regression/comparison in 3 |
| Adapter Improvements | Phase 1.1 + 3.5 | OpenAI pulled to Phase 1; streaming is Phase 3 |
| Testing OpenClaw | Cut | Too niche for general roadmap. Can revisit as a specific adapter later |
| Continuous Monitoring | Cut | v2+ scope. Dashboard/scheduling is a different product |

**New items not in old todo:**
- 1.2 Re-integrate AttackerAgent (orphaned code discovered in audit)
- 1.3 Wire LLM Judge (orphaned code discovered in audit)
- 1.4 Probe Endpoint (UX blocker for new users)
