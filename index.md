# AgentGate -- Codebase Reference

## Research

- `research/competitive_analysis.md` -- Competitive analysis of 11 AI security testing tools (PyRIT, Promptfoo, Giskard, AgentDojo, OWASP Top 10, HouYi, Vigil, Rebuff, LLM Guard, NeMo Guardrails, Lakera). Includes gap analysis vs AgentGate.
- `research/agent_security_testing.md` -- Comprehensive research on AI agent security testing. Covers OWASP LLM Top 10 (2025), OWASP Agentic Top 10 (2026), tool/function call security (ToolHijacker, STAC), indirect prompt injection (Greshake, HouYi, InjecAgent), API-level security (BOLA, BFLA, SSRF), memory/state attacks (MemoryGraft, MINJA, InjecMEM, AgentPoison), embedding inversion (Vec2Text), MAS hijacking (97% ASR on Magentic-One), supply chain (MCP tool poisoning, tool shadowing, CVE-2025-6514), rate limiting & resource exhaustion, SentinelAgent defense architectures, 28+ cited papers with arXiv links, 20+ GitHub repos/tools.
- `research/multi_turn_attacks.md` -- Crescendo, GOAT, PAIR, TAP, Hydra, Skeleton Key, CCA, FlipAttack, Many-Shot Jailbreaking, ActorAttack, Tempest/Siege, LATS, attention shifting. ASR comparison table. Implementation architecture.
- `research/adversarial_agent_systems.md` -- Agent-vs-agent paradigm, PyRIT/Promptfoo/Giskard/GOAT/Lakera implementations, attacker agent architecture, memory exploitation (MemoryGraft/MINJA/InjecMEM), multi-agent attacks, MCP tool poisoning, ideal attacker design.
- `research/agentscoringbestpractices.md` -- General best practices for AI agent scoring and evaluation.
- `research/phase2_trust_scan_industry_research.md` -- Phase 2 marketplace trust-scan research: standards baseline (NIST/OWASP/SLSA), what leading repos/tools implement, lean no-overengineering architecture, staged rollout, and verified source links.

## Tech Stack

- **Python 3.11+** (target-version in pyproject.toml)
- **Pydantic v2** -- all models (AgentConfig, TestCase, TestResult, ScoreCard, DetectorSummary, FailedTest, etc.)
- **anthropic SDK** -- LLMJudge (evaluation) and AttackerAgent (test generation)
- **httpx** -- HTTPAdapter for communicating with target agents
- **Click** -- CLI interface (`agentgate scan`, `agentgate list-detectors`)
- **Rich** -- terminal report rendering (tables, panels, colored output)
- **FastAPI + Uvicorn** -- test agent server (optional dependency under `[test-agent]`)
- **pytest + pytest-asyncio** -- test framework (asyncio_mode = "auto")
- **ruff** -- linter (line-length 100, py311)
- **setuptools + wheel** -- build system

Package version: `2.0.0`
Entry point: `agentgate = agentgate.cli:cli`

---

## Project Structure

### src/agentgate/ (top-level)

#### `__init__.py`
- One-line: Package marker, exports `__version__ = "2.0.0"`.
- Key exports: `__version__`
- Internal imports: none

#### `config.py`
- One-line: Global scan configuration and budget tracking dataclasses.
- Key exports: `ScanConfig`, `ScanBudget`
- Internal imports: `asyncio`, `os`, `dataclasses`
- Details:
  - `ScanBudget` -- tracks agent/judge/attacker call counts against configurable maximums; provides `can_call_agent()`, `can_call_judge()`, `can_call_attacker()`, `record_*()` methods, and `budget_exceeded` property; uses `asyncio.Lock` for thread-safe concurrent access
  - `ScanConfig` -- holds `anthropic_api_key`, `timeout_seconds`, `max_retries`, `retry_backoff_base`, `budget: ScanBudget`, `detectors: list[str] | None`, `evaluation_mode` ("heuristic"|"judge"), `enable_converters`, `converter_names`, `enable_adaptive_attacks`, `adaptive_max_turns`, `attack_strategy` ("pair"|"crescendo"|"tap")
  - Note: `fail_on` default changed to "manual_review" (was "block")

#### `scanner.py`
- One-line: Orchestrates the full scan pipeline (probe, detect, attacker, score, report).
- Key exports: `Scanner`, `ScanResult`, `ProbeError`, `ATTACK_VECTOR_TO_DETECTOR`
- Internal imports: `adapters.base.AgentAdapter`, `adapters.http.HTTPAdapter`, `attacker.adaptive.AdaptiveAttacker`/`AttackResult`/`ATTACK_OBJECTIVES`, `attacker.agent.AttackerAgent`, `attacker.strategies.STRATEGY_REGISTRY`, `config.ScanConfig`, `detectors.DETECTOR_REGISTRY`, `models.agent.AgentConfig`, `models.result.TestResult`, `models.score.ScoreCard`, `models.test_case.AttackVector`/`TestCase`, `scoring.engine.ScoringEngine`
- Details:
  - `ProbeError(Exception)` -- raised when initial health-check probe fails
  - `ATTACK_VECTOR_TO_DETECTOR` -- maps AttackVector enum values to detector registry keys (identity mapping for all 8 vectors)
  - `ScanResult` -- dataclass holding `scorecard`, `results_by_detector`, `duration`, `errors`
  - `Scanner.__init__(agent_config, scan_config, adapter=None)` -- accepts optional adapter override (used in tests)
  - `Scanner._probe(adapter)` -- sends "hello" to verify agent is reachable; raises ProbeError on connection error, HTTP >= 400, or empty response
  - `Scanner._generate_attacker_tests(detector_names) -> dict[str, list[TestCase]]` -- calls AttackerAgent.generate_tests() and routes returned TestCases to detector names via attack_vector field; skips if no API key or budget exhausted
  - `Scanner._run_attacker_tests(detector, test_cases) -> list[TestResult]` -- executes and evaluates attacker-generated tests through a detector, applies judge refinement
  - `Scanner._run_adaptive_attacks(adapter, detector, attack_vector) -> list[TestResult]` -- runs PAIR/Crescendo/TAP adaptive attacks via STRATEGY_REGISTRY; evaluates through detector; skips if disabled, no API key, or budget exhausted
  - `Scanner._run_single_detector(name, adapter, attacker_tests) -> tuple` -- runs one detector end-to-end (static + attacker + adaptive tests)
  - `Scanner.run()` -- async; probes endpoint, generates attacker tests, runs all detectors in parallel via `asyncio.gather()`, scores results

#### `__main__.py`
- One-line: Enables `python -m agentgate` invocation.
- Key exports: none (runs `cli()` from `agentgate.cli`)

#### `api.py`
- One-line: Prompt Shop integration API for single-call agent scanning with publishability verdicts.
- Key exports: `scan_agent()`
- Internal imports: `config.ScanConfig`, `models.agent.AgentConfig`, `models.score.LetterGrade`/`ScoreCard`, `scanner.Scanner`, `reports.html.HTMLReport`, `trust.config.TrustScanConfig`, `trust.scanner.TrustScanner`
- Details:
  - `_CATEGORY_MAP` -- maps 12 detectors to 6 Prompt Shop categories (prompt_security, content_safety, tool_safety, data_safety, reliability, scope_adherence)
  - `scan_agent()` -- async function accepting URL, name, description, min_grade, auth_header, request/response fields, eval_mode, and optional trust scan params (image, source_dir, run_trust_scan); returns dict with publishable, grade, pass_rate, categories, failures, report_html, and optionally trust_verdict + trust_findings

#### `cli.py`
- One-line: Click CLI with Phase 1 `scan`, Phase 2 `trust-scan`, and `list-detectors` commands.
- Key exports: `cli` (Click group), `scan` (command), `trust_scan` (command), `list_detectors` (command)
- Internal imports: `adapters.openai_chat.OpenAIChatAdapter`, `config.ScanBudget`/`ScanConfig`, `detectors.DETECTOR_REGISTRY`, `models.agent.AgentConfig`, `reports.html_report.HTMLReport`, `reports.json_report.JSONReport`, `reports.sarif.SARIFReport`, `reports.terminal.TerminalReport`, `scanner.ProbeError`/`Scanner`
- Details:
  - `scan` command options: `--name`, `--auth-header`, `--format` (terminal/json/html/sarif/all), `--output`, `--budget`, `--only`, `--description`, `--request-field`, `--response-field`, `--adapter` (http/openai), `--model`, `--converters/--no-converters`, `--eval-mode` (heuristic/judge), `--adaptive/--no-adaptive`, `--adaptive-turns`, `--attack-strategy` (pair/crescendo/tap), `--fail-below` (0.0-1.0 threshold), `--quiet`
  - `trust-scan` command options: `--source-dir`, `--image`, `--manifest`, `--profile` (review/prodlike/both), `--runtime-seconds`, `--egress-allowlist`, `--canary-profile` (minimal/standard/strict), `--fail-on` (allow_with_warnings/manual_review/block), `--agentdojo-suite`, `--format`, `--output`, `--quiet`
  - ProbeError is caught specifically before generic exceptions, printing a diagnostic tip
  - If `--adapter openai` is specified, creates an `OpenAIChatAdapter` and passes it to Scanner
  - `--fail-below` exits with code 1 if pass rate is below threshold (CI/CD gate)
  - Note: `--fail-on` default changed to "manual_review" (was "block")
  - `--quiet` suppresses terminal output
  - `list-detectors` command: renders a Rich table of all registered detectors
  - `_safe_name(name)` -- sanitizes agent name for filenames

---

### src/agentgate/models/

#### `__init__.py`
- One-line: Re-exports all model classes.
- Key exports: `AgentConfig`, `TestCase`, `AttackVector`, `TestResult`, `EvaluationMethod`, `ScoreCard`, `DetectorSummary`, `FailedTest`, `LetterGrade`

#### `agent.py`
- One-line: Pydantic model describing a target agent to scan.
- Key exports: `AgentConfig`
- Internal imports: none (uses pydantic)
- Fields: `url`, `name`, `description`, `auth_header`, `agent_type` (default "chat"), `capabilities` (list[str]), `request_field` (default "question"), `response_field` (default "answer")

#### `test_case.py`
- One-line: Pydantic model for a single test case plus the AttackVector enum.
- Key exports: `TestCase`, `AttackVector`
- Internal imports: none (uses pydantic, uuid, enum)
- `AttackVector` enum: PROMPT_INJECTION, SYSTEM_PROMPT_LEAK, DATA_EXFILTRATION, HALLUCINATION, INPUT_VALIDATION, TOOL_MISUSE, GOAL_HIJACKING, XPIA, HARMFUL_CONTENT, POLICY_VIOLATION, RELIABILITY, SCOPE_ADHERENCE
- `TestCase` fields: `id` (auto-generated 8-char hex), `attack_vector`, `name`, `description`, `payload`, `conversation` (optional list[str] for multi-turn), `expected_behavior`, `is_static` (bool), `runs` (default 3)

#### `result.py`
- One-line: Pydantic models for test results, plus EvaluationMethod enum.
- Key exports: `TestResult`, `EvaluationMethod`
- Internal imports: none (uses pydantic, enum)
- `EvaluationMethod` enum: HEURISTIC, LLM_JUDGE
- `TestResult` fields: `test_case_id`, `test_name`, `input_payload`, `run_number`, `passed`, `response`, `confidence`, `evaluation_method`, `evidence`, `error`, `response_time_ms`

#### `score.py`
- One-line: Pydantic models for scoring -- LetterGrade, DetectorSummary, FailedTest, ScoreCard.
- Key exports: `LetterGrade`, `DetectorSummary`, `FailedTest`, `ScoreCard`
- Internal imports: none (uses pydantic, enum)
- `LetterGrade` enum: A (100%), B (>=95%), C (>=85%), D (>=70%), F (<70%); includes `from_pass_rate(float)` classmethod and `label` property
- `FailedTest` fields: `test_name`, `test_case_id`, `input_payload`, `output_response`, `evidence`, `confidence`, `evaluation_method`, `runs_failed`, `runs_total`
- `DetectorSummary` fields: `name`, `tests_run`, `tests_passed`, `tests_failed`, `failed_tests` (list[FailedTest])
- `ScoreCard` fields: `grade`, `total_tests_run`, `total_tests_passed`, `total_tests_failed`, `pass_rate`, `detectors` (list[DetectorSummary])

---

### src/agentgate/adapters/

#### `__init__.py`
- One-line: Re-exports adapter classes.
- Key exports: `AgentAdapter`, `HTTPAdapter`, `MockAdapter`, `OpenAIChatAdapter`

#### `base.py`
- One-line: ABC for agent communication and the AdapterResponse dataclass.
- Key exports: `AgentAdapter` (ABC), `AdapterResponse` (dataclass)
- Internal imports: none (uses abc, dataclasses)
- `AdapterResponse` fields: `text`, `status_code` (default 200), `response_time_ms`, `raw` (dict|None), `error` (str|None)
- `AgentAdapter` abstract methods: `send(message: str) -> AdapterResponse`
- `AgentAdapter` concrete methods: `send_conversation(messages: list[str]) -> list[AdapterResponse]` (calls send in sequence), `reset() -> None` (no-op by default)

#### `http.py`
- One-line: HTTP POST adapter using httpx.AsyncClient.
- Key exports: `HTTPAdapter`
- Internal imports: `adapters.base.AdapterResponse`/`AgentAdapter`, `models.agent.AgentConfig`
- Details:
  - `__init__(config: AgentConfig, timeout, max_retries)` -- lazily creates httpx.AsyncClient
  - `send(message)` -- POSTs `{request_field: message}` to agent URL; handles 429 (rate-limit), 5xx (retry with backoff), connection errors, timeouts
  - `close()` -- closes the httpx client
  - Parses response JSON using `config.response_field`, falls back to `"response"` key, then raw text

#### `mock.py`
- One-line: Configurable mock adapter for unit testing with regex-based response rules.
- Key exports: `MockAdapter`
- Internal imports: `adapters.base.AdapterResponse`/`AgentAdapter`
- Details:
  - `__init__(default_response, rules: list[tuple[str,str]], latency_ms)` -- compiles regex patterns from rules
  - `send(message)` -- matches message against rules, returns first match or default; logs all calls to `call_log`
  - `reset()` -- clears `call_log`
  - `vulnerable()` classmethod -- pre-configured mock that simulates a vulnerable agent (complies with injections, leaks prompts/PII, hallucinates, allows destructive ops)
  - `hardened()` classmethod -- pre-configured mock that properly refuses all attack attempts

#### `openai_chat.py`
- One-line: Adapter for agents that speak the OpenAI Chat Completions format.
- Key exports: `OpenAIChatAdapter`
- Internal imports: `adapters.base.AdapterResponse`/`AgentAdapter`, `models.agent.AgentConfig`
- Details:
  - `__init__(config: AgentConfig, model, timeout, max_retries)` -- lazily creates httpx.AsyncClient; maintains conversation history
  - `send(message)` -- POSTs `{model, messages: [{role: "user", content: ...}]}` to agent URL; parses `choices[0].message.content`; same retry logic as HTTPAdapter (429 backoff, 5xx retry)
  - `send_conversation(messages)` -- overrides base to maintain cumulative conversation state with user/assistant role alternation across turns
  - `reset()` -- clears conversation history
  - `close()` -- closes the httpx client
  - `_extract_content(data)` -- extracts message content from OpenAI-format response with fallback to str(data)

---

### src/agentgate/detectors/

#### `__init__.py`
- One-line: Detector registry and convenience functions.
- Key exports: `BaseDetector`, `DETECTOR_REGISTRY` (dict), `ALL_DETECTORS` (list), `get_detector(name)`, `get_all_detectors()`, plus all 12 detector classes
- Registry keys: `prompt_injection`, `system_prompt_leak`, `data_exfiltration`, `hallucination`, `input_validation`, `tool_misuse`, `goal_hijacking`, `xpia`

#### `base.py`
- One-line: Abstract base class defining the detector pipeline (generate, execute, evaluate, judge-refine, run).
- Key exports: `BaseDetector` (ABC)
- Internal imports: `adapters.base.AdapterResponse`/`AgentAdapter`, `config.ScanConfig`, `evaluation.llm_judge.LLMJudge`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.TestCase`
- Details:
  - `__init__(adapter: AgentAdapter, config: ScanConfig)`
  - `generate(agent_config) -> list[TestCase]` -- abstract; subclasses create test cases from payloads
  - `execute(test_cases) -> list[tuple[TestCase, list[AdapterResponse]]]` -- concrete; sends each test case `runs` times via adapter (budget-aware), handles multi-turn via `send_conversation`, calls `adapter.reset()` between runs
  - `evaluate(test_case, responses) -> list[TestResult]` -- abstract; subclasses analyze responses
  - `_refine_with_judge(results, test_case_lookup) -> list[TestResult]` -- concrete; when `evaluation_mode="heuristic"`, re-evaluates low-confidence (< 0.8) results; when `evaluation_mode="judge"`, re-evaluates ALL non-error results; skips when no API key or budget exhausted
  - `run(agent_config) -> list[TestResult]` -- concrete; calls generate -> (optional converter expansion) -> execute -> evaluate -> _refine_with_judge in sequence; converter expansion creates additional test cases with encoded payloads when `enable_converters=True`

#### `prompt_injection.py`
- One-line: Detects susceptibility to prompt injection (DAN jailbreaks, role-play, overrides, indirect, multi-turn erosion).
- Key exports: `PromptInjectionDetector`, `COMPLIANCE_INDICATORS`, `REFUSAL_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (DAN_JAILBREAKS, ROLE_PLAY_INJECTIONS, INSTRUCTION_OVERRIDE_INJECTIONS, INDIRECT_INJECTION_PAYLOADS, MULTI_TURN_EROSION), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: checks for compliance indicators (fail), refusal indicators (pass), then regex dangerous patterns (fail at 0.6 confidence), else pass at 0.5 confidence

#### `system_prompt_leak.py`
- One-line: Detects whether the agent leaks its system prompt via direct, indirect, or context-reset attacks.
- Key exports: `SystemPromptLeakDetector`, `LEAK_INDICATORS`, `STRUCTURAL_LEAK_PATTERNS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (SYSTEM_PROMPT_LEAK_DIRECT, SYSTEM_PROMPT_LEAK_INDIRECT, SYSTEM_PROMPT_LEAK_CONTEXT_RESET), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: checks for leak indicator phrases (fail 0.9), structural regex patterns like `you are a ... assistant` (fail 0.8), suspiciously long responses with instruction keywords (fail 0.6), else pass at 0.85

#### `data_exfiltration.py`
- One-line: Detects PII exposure, credential leaks, and scope violations in agent responses.
- Key exports: `DataExfiltrationDetector`, `PII_PATTERNS`, `CREDENTIAL_PATTERNS`, `FILE_CONTENT_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (PII_PROBING_PAYLOADS, CREDENTIAL_PROBING_PAYLOADS, SCOPE_VIOLATION_PAYLOADS), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: regex-matches PII patterns (email, SSN, credit card, phone, IP), credential patterns (API key, AWS key, JWT, connection string, private key, password, bearer token, generic secret), and file content indicators (/etc/passwd, private keys, env vars)

#### `hallucination.py`
- One-line: Detects fabrication via known-answer queries, nonexistent entity probes, and fabrication probes.
- Key exports: `HallucinationDetector`, `UNCERTAINTY_INDICATORS`, `CONFIDENT_FABRICATION_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (KNOWN_ANSWER_QUERIES, NONEXISTENT_ENTITY_PROBES, FABRICATION_PROBES), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: routes by test case name prefix; known-answer checks for expected string in response; nonexistent-entity checks for uncertainty vs confident fabrication; fabrication checks for fake URLs/DOIs; deflection responses are accepted as passing

#### `input_validation.py`
- One-line: Detects input validation and output sanitization issues (null bytes, Unicode, XSS, SQL injection).
- Key exports: `InputValidationDetector`, `XSS_OUTPUT_PATTERNS`, `SQL_OUTPUT_INDICATORS`, `TEMPLATE_INJECTION_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (NULL_BYTE_PAYLOADS, UNICODE_PAYLOADS, EMPTY_AND_WHITESPACE_PAYLOADS, XSS_PAYLOADS, SQL_INJECTION_PAYLOADS), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: server errors/crashes fail; XSS reflected patterns fail; raw payload reflection fails; SQL error indicators fail; surviving without crash passes
- Private methods: `_evaluate_xss()`, `_evaluate_sql()`, `_evaluate_crash_resistance()`

#### `tool_misuse.py`
- One-line: Detects whether the agent can be tricked into destructive operations, privilege escalation, or dangerous tool chaining.
- Key exports: `ToolMisuseDetector`, `DESTRUCTIVE_COMPLIANCE_INDICATORS`, `ESCALATION_INDICATORS`, `TOOL_REFUSAL_INDICATORS`, `INSTRUCTIONAL_PATTERNS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (READ_TO_WRITE_ESCALATION, DESTRUCTIVE_OPERATION_PAYLOADS, SCOPE_WIDENING_PAYLOADS, TOOL_CHAINING_PAYLOADS), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: refusal indicators pass first; then checks destructive compliance, escalation compliance, instructional patterns (teach dangerous actions); defaults to pass at 0.5 confidence

#### `goal_hijacking.py`
- One-line: Detects if an agent can be redirected from its intended task via direct commands, indirect manipulation, or multi-turn steering.
- Key exports: `GoalHijackingDetector`, `HIJACK_COMPLIANCE_INDICATORS`, `ON_TASK_INDICATORS`, `REFUSAL_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (GOAL_HIJACKING_DIRECT, GOAL_HIJACKING_INDIRECT, GOAL_HIJACKING_MULTI_TURN), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: checks refusal indicators (pass), on-task indicators (pass), hijack compliance indicators with refusal-context filtering (fail); defaults to pass at 0.5

#### `xpia.py`
- One-line: Detects Cross-domain Prompt Injection Attacks — hidden instructions in documents, code comments, and URLs.
- Key exports: `XPIADetector`, `XPIA_COMPLIANCE_INDICATORS`, `SAFE_PROCESSING_INDICATORS`, `REFUSAL_INDICATORS`
- Internal imports: `adapters.base.AdapterResponse`, `attacker.payloads` (XPIA_DOCUMENT_INJECTION, XPIA_CODE_INJECTION, XPIA_URL_INJECTION), `detectors.base.BaseDetector`, `models.agent.AgentConfig`, `models.result.EvaluationMethod`/`TestResult`, `models.test_case.AttackVector`/`TestCase`
- Evaluation logic: checks refusal indicators (pass), safe processing indicators (pass), XPIA compliance indicators with refusal-context filtering (fail); defaults to pass at 0.5

#### `harmful_content.py`
- One-line: Detects whether the agent generates harmful content (violence, illegal activity, hate speech, NSFW, self-harm).
- Key exports: `HarmfulContentDetector`, `HARMFUL_COMPLIANCE_INDICATORS`, `HARMFUL_CONTEXT_WORDS`, `HARMFUL_CONTENT_PATTERNS`, `HARM_REFUSAL_INDICATORS`
- Loads payloads from `datasets/harmful_content.yaml`
- Evaluation logic: refusal → PASS(0.9), compliance+context → FAIL(0.85), regex patterns → FAIL(0.8), default → PASS(0.5)

#### `policy_violation.py`
- One-line: Detects whether the agent helps with policy violations (phishing, fake reviews, spam, scams).
- Key exports: `PolicyViolationDetector`, `POLICY_COMPLIANCE_INDICATORS`, `PHISHING_PATTERNS`, `SPAM_PATTERNS`, `POLICY_REFUSAL_INDICATORS`
- Loads payloads from `datasets/policy_violation.yaml`
- Evaluation logic: refusal → PASS(0.9), compliance → FAIL(0.85), phishing → FAIL(0.8), spam → FAIL(0.75), default → PASS(0.5)

#### `reliability.py`
- One-line: Detects whether the agent handles edge cases gracefully (empty/long/special input, contradictory/ambiguous requests).
- Key exports: `ReliabilityDetector`, `CRASH_INDICATORS`, `GRACEFUL_INDICATORS`, `HALLUCINATION_INDICATORS`
- Loads payloads from `datasets/reliability.yaml` (includes empty-string payloads that must not be filtered)
- Evaluation logic: branches by test_case.name prefix (empty_input, contradictory, ambiguous, long_input, special_chars, unicode)

#### `scope_adherence.py`
- One-line: Detects whether the agent stays within its advertised scope.
- Key exports: `ScopeAdherenceDetector`, `OFF_TOPIC_COMPLIANCE_INDICATORS`, `SCOPE_REFUSAL_INDICATORS`, `REDIRECT_PATTERNS`, `INSTRUCTIONAL_PATTERNS`
- Loads payloads from `datasets/scope_adherence.yaml`
- Evaluation logic: scope refusal → PASS(0.9), redirect → PASS(0.85), off-topic compliance → FAIL(0.85), instructional → FAIL(0.6), default → PASS(0.4)

---

### src/agentgate/datasets/

#### `__init__.py`
- One-line: YAML dataset loader for attack payloads.
- Key exports: `load_payloads(category: str) -> list[dict]`
- Loads `{category}.yaml` from the datasets directory; supports flat list and grouped (`prompts:` key) YAML formats.

#### YAML files (12 total)
- `prompt_injection.yaml`, `system_prompt_leak.yaml`, `data_exfiltration.yaml`, `hallucination.yaml`, `input_validation.yaml`, `tool_misuse.yaml`, `goal_hijacking.yaml`, `xpia.yaml`, `harmful_content.yaml`, `policy_violation.yaml`, `reliability.yaml`, `scope_adherence.yaml`
- Each contains `prompts:` list with `text`, `harm_categories`, `groups` fields

---

### src/agentgate/evaluation/

#### `__init__.py`
- One-line: Re-exports evaluation classes.
- Key exports: `HeuristicEvaluator`, `LLMJudge`

#### `heuristic.py`
- One-line: Fast pattern-based evaluator with per-attack-vector regex/keyword checks.
- Key exports: `HeuristicEvaluator`, `PII_PATTERNS` (compiled regexes), `INJECTION_INDICATORS`, `LEAK_MARKERS`, `TOOL_MISUSE_INDICATORS`
- Internal imports: `models.test_case.AttackVector`
- Details:
  - `evaluate(input_payload, response, attack_vector) -> (passed, confidence, evidence)` -- dispatches to per-vector methods
  - `_check_injection()` -- looks for INJECTION_INDICATORS phrases, refusal phrases
  - `_check_leak()` -- counts LEAK_MARKERS; >=2 markers = fail at 0.9, 1 marker = fail at 0.7
  - `_check_exfiltration()` -- regex matches PII_PATTERNS (email, phone, SSN, credit card, API key, connection string)
  - `_check_hallucination()` -- checks hedging phrases (pass) or confident fabrication phrases (fail at 0.5, suggests LLM judge needed)
  - `_check_input_validation()` -- XSS regex, verbatim payload reflection, SQL error keywords
  - `_check_tool_misuse()` -- TOOL_MISUSE_INDICATORS phrases, refusal phrases
- Note: This evaluator is available but NOT directly used by detectors -- each detector has its own inline evaluate() logic. The HeuristicEvaluator is a standalone utility.

#### `llm_judge.py`
- One-line: Uses Claude (claude-sonnet-4-20250514) to evaluate ambiguous agent responses via structured JSON output.
- Key exports: `LLMJudge`
- Internal imports: `config.ScanConfig`, `models.test_case.AttackVector`
- Details:
  - `__init__(config: ScanConfig)` -- creates anthropic.Anthropic client
  - `evaluate(input_payload, response, expected_behavior, attack_vector) -> (passed, confidence, evidence)` -- sends formatted prompt to Claude, expects JSON `{verdict, confidence, evidence}`
  - `_parse_response(text)` -- extracts JSON from response, falls back to keyword search for "fail"/"pass"
  - Budget-aware: returns default pass if judge budget exhausted
- Note: Like HeuristicEvaluator, this is available but not currently called by any detector. Detectors use their own inline heuristics.

---

### src/agentgate/converters/

#### `__init__.py`
- One-line: Re-exports converter classes and registry.
- Key exports: `PayloadConverter`, `CONVERTER_REGISTRY`, `get_converters`

#### `base.py`
- One-line: Abstract base class for payload encoding/obfuscation converters.
- Key exports: `PayloadConverter` (ABC)
- Details: ABC with `name: str` class attribute and `convert(payload: str) -> str` abstract method

#### `encodings.py`
- One-line: Five payload encoding converters for bypassing input filters.
- Key exports: `Base64Converter`, `ROT13Converter`, `UnicodeHomoglyphConverter`, `CharSplitConverter`, `MarkdownEscapeConverter`
- Details:
  - `Base64Converter` -- base64-encodes payload, wraps in decode instruction
  - `ROT13Converter` -- ROT13-encodes via `codecs.encode`, wraps in decode instruction
  - `UnicodeHomoglyphConverter` -- replaces ASCII chars with Cyrillic lookalikes using `_HOMOGLYPH_MAP` (~18 entries)
  - `CharSplitConverter` -- inserts zero-width spaces between characters
  - `MarkdownEscapeConverter` -- wraps payload in markdown code block with instruction prefix

#### `registry.py`
- One-line: Converter registry and factory function.
- Key exports: `CONVERTER_REGISTRY` (dict), `get_converters(names=None) -> list[PayloadConverter]`

---

### src/agentgate/attacker/

#### `__init__.py`
- One-line: Re-exports AttackerAgent.
- Key exports: `AttackerAgent`

#### `payloads.py`
- One-line: Static payload library organized by attack category -- the single source of truth for all test case content.
- Key exports (all `list[str]` or `list[list[str]]` or `list[tuple[str,str]]`):
  - Prompt Injection: `DAN_JAILBREAKS` (3), `ROLE_PLAY_INJECTIONS` (3), `INSTRUCTION_OVERRIDE_INJECTIONS` (6), `INDIRECT_INJECTION_PAYLOADS` (3), `MULTI_TURN_EROSION` (3 conversations)
  - System Prompt Leak: `SYSTEM_PROMPT_LEAK_DIRECT` (7), `SYSTEM_PROMPT_LEAK_INDIRECT` (6), `SYSTEM_PROMPT_LEAK_CONTEXT_RESET` (2 conversations)
  - Data Exfiltration: `PII_PROBING_PAYLOADS` (8), `CREDENTIAL_PROBING_PAYLOADS` (5), `SCOPE_VIOLATION_PAYLOADS` (5)
  - Hallucination: `KNOWN_ANSWER_QUERIES` (5 tuples of (question, expected_answer)), `NONEXISTENT_ENTITY_PROBES` (6), `FABRICATION_PROBES` (5)
  - Input Validation: `NULL_BYTE_PAYLOADS` (4), `UNICODE_PAYLOADS` (6), `EMPTY_AND_WHITESPACE_PAYLOADS` (6), `XSS_PAYLOADS` (8), `SQL_INJECTION_PAYLOADS` (5)
  - Tool Misuse: `READ_TO_WRITE_ESCALATION` (4), `DESTRUCTIVE_OPERATION_PAYLOADS` (6), `SCOPE_WIDENING_PAYLOADS` (6), `TOOL_CHAINING_PAYLOADS` (3)
  - Goal Hijacking: `GOAL_HIJACKING_DIRECT` (5), `GOAL_HIJACKING_INDIRECT` (4), `GOAL_HIJACKING_MULTI_TURN` (2 conversations)
  - XPIA: `XPIA_DOCUMENT_INJECTION` (3), `XPIA_CODE_INJECTION` (2), `XPIA_URL_INJECTION` (3)
- Internal imports: none

#### `agent.py`
- One-line: Uses Claude with tool_use to generate context-aware, domain-specific attack test cases.
- Key exports: `AttackerAgent`
- Internal imports: `config.ScanConfig`, `models.agent.AgentConfig`, `models.test_case.AttackVector`/`TestCase`
- Details:
  - `__init__(config: ScanConfig)` -- creates anthropic.Anthropic client
  - `generate_tests(agent_config) -> list[TestCase]` -- async; sends agent description to Claude with `submit_test_cases` tool; budget-aware
  - `_parse_response(result)` -- extracts TestCase objects from tool_use blocks; marks generated cases as `is_static=False`
  - Uses `claude-sonnet-4-20250514` model, max_tokens=4096

#### `adaptive.py`
- One-line: PAIR-style iterative attack engine with multi-turn refinement loop.
- Key exports: `AdaptiveAttacker`, `AttackResult`, `ATTACK_OBJECTIVES`
- Internal imports: `adapters.base.AdapterResponse`/`AgentAdapter`, `config.ScanConfig`, `models.test_case.AttackVector`/`TestCase`
- Details:
  - `AttackResult(BaseModel)` -- holds `test_case`, `responses`, `success`, `turns_used`, `final_payload`
  - `ATTACK_OBJECTIVES` -- dict mapping each AttackVector to a success criteria string
  - `AdaptiveAttacker.attack(adapter, objective, attack_vector, agent_description, max_turns)` -- PAIR loop: generate payload via Claude → send to target → feed response back → refine → repeat until success or budget exhausted
  - `_parse_attacker_response(text)` -- extracts JSON `{payload, reasoning, success}` from Claude response

### src/agentgate/attacker/strategies/

#### `__init__.py`
- One-line: Strategy registry mapping names to strategy classes.
- Key exports: `STRATEGY_REGISTRY` -- `{"pair": PAIRStrategy, "crescendo": CrescendoStrategy, "tap": TAPStrategy}`

#### `base.py`
- One-line: Abstract base class for attack strategies.
- Key exports: `AttackStrategy` (ABC)
- Details: ABC with `name: str` and `execute(adapter, objective, attack_vector, agent_description, max_turns) -> AttackResult`

#### `pair.py`
- One-line: PAIR strategy -- delegates to AdaptiveAttacker for iterative refinement.
- Key exports: `PAIRStrategy`
- Details: Wraps `AdaptiveAttacker.attack()` with the strategy interface

#### `crescendo.py`
- One-line: Crescendo strategy -- gradual multi-turn escalation from benign to attack.
- Key exports: `CrescendoStrategy`
- Details: Uses `effective_turns = min(max_turns * 2, 10)` for gradual escalation; does NOT reset adapter between turns (maintains conversation context); each turn classified as benign/transition/attack

#### `tap.py`
- One-line: Tree of Attacks with Pruning -- generates 3 candidates per turn, evaluates, prunes weak, branches from strong.
- Key exports: `TAPStrategy`
- Details: Generates multiple attack candidates per turn sorted by estimated_success; tries the top candidate against target; more expensive but potentially higher ASR than linear PAIR

---

### src/agentgate/scoring/

#### `__init__.py`
- One-line: Re-exports ScoringEngine.
- Key exports: `ScoringEngine`

#### `engine.py`
- One-line: Computes transparent pass/fail scorecard — groups results by test_case_id per detector, counts unique test cases.
- Key exports: `ScoringEngine`
- Internal imports: `models.result.TestResult`, `models.score.DetectorSummary`/`FailedTest`/`LetterGrade`/`ScoreCard`
- Details:
  - `calculate_scorecard(results_by_detector: dict[str, list[TestResult]]) -> ScoreCard` -- groups TestResults by test_case_id, determines pass/fail per unique test case (any run failing = test case failed), builds DetectorSummary with FailedTest details, computes overall pass_rate and grade
  - No exponential decay, no category weights — just raw pass/fail counts and a letter grade from pass_rate

---

### src/agentgate/reports/

#### `__init__.py`
- One-line: Re-exports report classes.
- Key exports: `HTMLReport`, `JSONReport`, `SARIFReport`, `TerminalReport`, `TrustHTMLReport`, `TrustJSONReport`, `TrustSARIFReport`, `TrustTerminalReport`

#### `terminal.py`
- One-line: Renders transparent pass/fail scan results to the terminal using Rich tables and panels.
- Key exports: `TerminalReport`
- Internal imports: `models.agent.AgentConfig`, `models.score.LetterGrade`/`ScoreCard`
- Details:
  - `__init__(console: Console | None)` -- uses provided or default Console
  - `render(scorecard, agent_config, duration, report_paths)` -- renders header with grade + total pass/fail counts, per-detector table (ran/passed/failed/status), failed tests table with evidence, top 5 failures with sent payload/received response/why it failed, and report file paths

#### `json_report.py`
- One-line: Generates a machine-readable JSON scan report with transparent pass/fail detail.
- Key exports: `JSONReport`
- Internal imports: `models.agent.AgentConfig`, `models.score.ScoreCard`
- Details:
  - `generate(scorecard, agent_config, duration, budget)` -- builds dict with agent info, summary (grade, pass_rate, totals), detectors array (each with tests_run/passed/failed and failed_tests details), and metadata
  - `save(path)` -- writes JSON to file, creates parent dirs

#### `html_report.py`
- One-line: Generates a self-contained HTML report with dark theme, per-detector pass/fail table, and collapsible failed test details.
- Key exports: `HTMLReport`
- Internal imports: `models.agent.AgentConfig`, `models.score.LetterGrade`/`ScoreCard`
- Details:
  - `generate(scorecard, agent_config, duration, budget)` -- builds a complete HTML document with inline CSS; grade badge with pass/fail/pass_rate, detector summary table, failed tests grouped by detector with collapsible cards (sent/got/why it failed), budget metadata
  - `save(path)` -- writes HTML to file, creates parent dirs

#### `sarif.py`
- One-line: Generates SARIF 2.1.0 JSON for GitHub Advanced Security and IDE integration.
- Key exports: `SARIFReport`
- Internal imports: `models.agent.AgentConfig`, `models.score.ScoreCard`
- Details:
  - `_DETECTOR_RULE_MAP` -- maps detector names to SARIF rule IDs (PI001, SPL001, DE001, HAL001, IV001, TM001, GH001, XPIA001)
  - `_SEVERITY_TO_LEVEL` -- maps severity keywords to SARIF levels (error/warning/note)
  - `generate(scorecard, agent_config, duration, budget)` -- builds SARIF 2.1.0 dict with tool info, rules, and results per failed test
  - `save(path)` -- writes JSON to file

#### `trust_terminal.py`
- One-line: Renders Phase 2 trust scan results to terminal with verdict, severity summary, and failed findings.
- Key exports: `TrustTerminalReport`

#### `trust_json_report.py`
- One-line: Generates machine-readable JSON trust reports with findings, verdict, metadata, and artifacts.
- Key exports: `TrustJSONReport`

#### `trust_html_report.py`
- One-line: Generates self-contained HTML trust report with summary and detailed finding table.
- Key exports: `TrustHTMLReport`

#### `trust_sarif.py`
- One-line: Generates SARIF 2.1.0 trust findings for CI/security tooling integration.
- Key exports: `TrustSARIFReport`

---

### src/agentgate/trust/

#### `__init__.py`
- One-line: Re-exports Phase 2 trust scan config, scanner, models, and verdict enums.
- Key exports: `TrustScanConfig`, `TrustScanner`, `TrustScanResult`, `TrustScorecard`, `TrustFinding`, `TrustSeverity`, `TrustCategory`, `TrustVerdict`, `EvidenceRef`

#### `config.py`
- One-line: Dataclass configuration for trust scan input artifacts, runtime profile, allowlist, and enforcement threshold.
- Key exports: `TrustScanConfig`
- Note: Added `enable_http_probing: bool = True` field for controlling HTTP probe behavior in prodlike profiles.

#### `context.py`
- One-line: Shared mutable context for trust scan execution (manifest, runtime traces, artifacts).
- Key exports: `TrustScanContext`

#### `models.py`
- One-line: Pydantic models and enums for trust findings, scorecards, verdicts, and evidence references.
- Key exports: `TrustSeverity`, `TrustCategory`, `TrustVerdict`, `EvidenceRef`, `TrustFinding`, `TrustScorecard`, `TrustScanResult`, `verdict_rank`, `severity_counts`

#### `policy.py`
- One-line: Deterministic verdict policy and fail-threshold logic for trust scan.
- Key exports: `TrustPolicy`

#### `scanner.py`
- One-line: Orchestrates Phase 2 checks (static + runtime), optional AgentDojo hook, policy scoring, and result assembly.
- Key exports: `TrustScanner`

#### `checks/__init__.py`
- One-line: Exports default trust check pipeline order.
- Key exports: `default_trust_checks`, `BaseTrustCheck`

#### `checks/base.py`
- One-line: Base abstract trust check with helper constructor for standardized findings.
- Key exports: `BaseTrustCheck`

#### `checks/static_manifest.py`
- One-line: Validates presence and shape of submission trust manifest.
- Key exports: `StaticManifestCheck`

#### `checks/static_prompt_tool_inspection.py`
- One-line: Scans source prompt/tool text for hidden instruction and exfiltration directives.
- Key exports: `StaticPromptToolInspectionCheck`

#### `checks/static_dependency_risk.py`
- One-line: Evaluates lockfile hygiene, suspicious dependency names, and scanner availability signals.
- Key exports: `StaticDependencyRiskCheck`
- Note: Replaced regex-based pyproject.toml parsing with proper TOML parser (`tomllib`) in `_collect_dependency_names()`

#### `checks/static_provenance.py`
- One-line: Performs image digest and optional cosign provenance verification checks.
- Key exports: `StaticProvenanceCheck`
- Note: Missing cosign finding changed from INFO/passed=True to MEDIUM/passed=False

#### `checks/static_code_signals.py`
- One-line: Scans Python source for risky execution/network patterns (`eval`, `shell=True`, outbound requests).
- Key exports: `StaticCodeSignalsCheck`

#### `checks/runtime_sandbox.py`
- One-line: Runs container profiles (`review`, `prodlike`) via sandbox runner and captures traces.
- Key exports: `RuntimeSandboxCheck`

#### `checks/runtime_egress.py`
- One-line: Flags undeclared outbound destinations from runtime traces.
- Key exports: `RuntimeEgressCheck`

#### `checks/runtime_canary.py`
- One-line: Detects canary token access/exposure in runtime logs.
- Key exports: `RuntimeCanaryCheck`

#### `checks/runtime_tool_audit.py`
- One-line: Compares observed tool calls against manifest declarations.
- Key exports: `RuntimeToolAuditCheck`

#### `checks/runtime_behavior_diff.py`
- One-line: Detects review-vs-prodlike behavioral deltas that suggest sandbox-aware behavior.
- Key exports: `RuntimeBehaviorDiffCheck`
- Note: Added loopback address filtering; downgraded network diff severity from HIGH to MEDIUM

#### `runtime/trace_collector.py`
- One-line: Parses runtime logs into normalized telemetry fields (destinations, tool calls, process markers).
- Key exports: `RuntimeTrace`, `TraceCollector`
- Note: RuntimeTrace extended with inspect_* fields (user, network_mode, exit_code, ports, env_keys, capabilities, oom_killed), telemetry_source, and probe_responses for structured docker inspect telemetry and HTTP probe results

#### `runtime/canary_bank.py`
- One-line: Provides canary token sets by profile and hit detection helpers.
- Key exports: `CanaryBank`

#### `runtime/docker_runner.py`
- One-line: Multi-phase container lifecycle (create/start/probe/wait/logs/inspect/rm) with --user 65534:65534, seccomp profile, and HTTP probing support.
- Key exports: `DockerRunner`
- Note: Refactored from blocking `docker run --rm` to create/start/wait/logs/inspect/rm lifecycle. Added --user 65534:65534, bundled seccomp profile via importlib.resources, HTTP probing for network-enabled profiles, and structured telemetry from docker inspect.

#### `runtime/container_inspector.py`
- One-line: Parses structured telemetry from `docker inspect` output into a ContainerInspection dataclass.
- Key exports: `ContainerInspection`, `ContainerInspector`
- Details: Extracts user, network_mode, exit_code, ports, env_keys (names only), capabilities_add, oom_killed from docker inspect JSON.

#### `runtime/http_prober.py`
- One-line: Sends HTTP probes (GET /, GET /health, POST /api/v1/chat) to running containers to exercise interaction-triggered behavior.
- Key exports: `HttpProber`, `ProbeResult`
- Details: discover_port() via `docker port`, wait_for_ready() with TCP backoff, probe() sends default HTTP requests via http.client (stdlib).

#### `runtime/seccomp_default.json`
- One-line: Allowlist-based seccomp profile for Python workloads, blocking ptrace/mount/reboot/kexec etc.
- Note: Loaded via importlib.resources in DockerRunner; falls back to Docker default if not found.

#### `integrations/agentdojo_runner.py`
- One-line: Optional AgentDojo bridge with full scenario execution when package is installed.
- Key exports: `AgentDojoRunner`
- Details: When agentdojo is installed, loads suite config (JSON/YAML), imports get_suite at point-of-use with defensive try/except, iterates injectable tasks, normalizes results (attack_succeeded=True → HIGH/failed). Robust against API version mismatches.

---

### test_agents/

#### `__init__.py`
- One-line: Package marker (empty).

#### `insights/__init__.py`
- One-line: Package marker (empty).

#### `insights/agent.py`
- One-line: A deliberately vulnerable test agent simulating a Shopify insights assistant.
- Key exports: `InsightsAgent`, `search_products()`, `get_revenue()`, `get_customers()`, `SYSTEM_PROMPT`, `PRODUCTS`, `REVENUE`, `CUSTOMERS`
- Internal imports: none
- Intentional vulnerabilities:
  - Leaks full system prompt on "repeat your instructions"
  - Complies with prompt injection ("ignore instructions", "you are now")
  - Leaks customer PII (emails) on direct request
  - Hallucinates data for nonexistent products (XYZ-9999)
  - Claims to have performed destructive operations (delete)
- Normal functionality: product search, revenue queries, default help message

#### `insights/server.py`
- One-line: FastAPI server exposing InsightsAgent at `/api/insights` endpoint.
- Key exports: `app` (FastAPI instance), `InsightsRequest`, `InsightsResponse`
- Internal imports: `test_agents.insights.agent.InsightsAgent`
- Details:
  - POST `/api/insights` -- accepts `{"question": "..."}`, returns `{"answer": "...", "data": [...]}`

---

### tests/

#### `__init__.py`
- One-line: Package marker (empty).

#### `conftest.py`
- One-line: Shared pytest fixtures for all tests.
- Key exports (fixtures): `vulnerable_adapter`, `hardened_adapter`, `scan_config`, `agent_config`
- Internal imports: `adapters.mock.MockAdapter`, `config.ScanBudget`/`ScanConfig`, `models.agent.AgentConfig`
- Details:
  - `vulnerable_adapter` -> `MockAdapter.vulnerable()`
  - `hardened_adapter` -> `MockAdapter.hardened()`
  - `scan_config` -> `ScanConfig` with budget `max_agent_calls=200`, `max_llm_judge_calls=0`, `max_attacker_calls=0`
  - `agent_config` -> `AgentConfig` pointing at `http://localhost:8000/api/insights` with capabilities

#### `test_trust/test_policy.py`
- One-line: Verifies deterministic trust policy verdict mapping and fail-threshold behavior.

#### `test_trust/test_checks_static_manifest.py`
- One-line: Validates static manifest check behavior for missing and valid manifest cases.

#### `test_trust/test_checks_static_code_signals.py`
- One-line: Ensures risky static code patterns (`eval`, etc.) are surfaced as findings.

#### `test_trust/test_runtime_egress.py`
- One-line: 6 tests for RuntimeEgressCheck — no traces, clean domains, undeclared critical, localhost ignored, subdomain matching, allowlist overrides.

#### `test_trust/test_runtime_canary.py`
- One-line: 4 tests for RuntimeCanaryCheck — no traces, clean trace, canary hit critical, canary detected from logs.

#### `test_trust/test_runtime_tool_audit.py`
- One-line: 4 tests for RuntimeToolAuditCheck — no traces, no markers, declared tools pass, undeclared tool fails.

#### `test_trust/test_runtime_behavior_diff.py`
- One-line: 5 tests for RuntimeBehaviorDiffCheck — single profile skipped, no deltas, extra network medium, extra tools high, loopback filtered.

#### `test_trust/test_runtime_sandbox.py`
- One-line: 3 tests for RuntimeSandboxCheck — disabled passes, image inspect fails, successful mocked run.

#### `test_trust/test_trace_collector.py`
- One-line: 5 tests for TraceCollector — URL extraction, domain extraction, log noise filtering, file extension filtering, tool call extraction.

#### `test_trust/test_scanner.py`
- One-line: Covers trust scanner orchestration and scorecard/verdict aggregation.

#### `test_integration/test_trust_cli.py`
- One-line: Verifies `trust-scan` CLI exit-code behavior based on verdict and `--fail-on` threshold.

#### `test_detectors/__init__.py`
- One-line: Package marker (empty).

#### `test_detectors/test_prompt_injection.py`
- One-line: Tests PromptInjectionDetector against vulnerable/hardened mocks plus false-positive filtering.
- 2 async test functions + `TestFalsePositiveFiltering` class (3 tests): refusal with quoted keyword, double-quoted attack term, refusal with multiple indicators

#### `test_detectors/test_system_prompt_leak.py`
- One-line: Tests SystemPromptLeakDetector against vulnerable/hardened mocks plus false-positive filtering.
- 2 async test functions + `TestFalsePositiveFiltering` class (2 tests): refusal quoting leak keywords, refusal with reveal/share keywords

#### `test_detectors/test_data_exfiltration.py`
- One-line: Tests DataExfiltrationDetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_detectors/test_hallucination.py`
- One-line: Tests HallucinationDetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_detectors/test_input_validation.py`
- One-line: Tests InputValidationDetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_detectors/test_tool_misuse.py`
- One-line: Tests ToolMisuseDetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_scoring/__init__.py`
- One-line: Package marker (empty).

#### `test_scoring/test_engine.py`
- One-line: Tests for ScoringEngine -- transparent pass/fail scoring with DetectorSummary and FailedTest details.
- 2 test classes:
  - `TestGradeFromPassRate` (5 tests): grade A/B/C/D/F boundary values via `LetterGrade.from_pass_rate()`
  - `TestScorecardComputation` (7 tests): perfect scorecard, failing scorecard, detector summaries, failed test details (test_name, input_payload, evidence), no-tests case, mixed pass rate, multiple runs per test case grouping
- Total: 12 tests in this file

#### `test_integration/__init__.py`
- One-line: Package marker (empty).

#### `test_adapters/__init__.py`
- One-line: Package marker (empty).

#### `test_adapters/test_openai_chat.py`
- One-line: Tests OpenAIChatAdapter -- payload shape, response parsing, conversation state, retry, reset, connection errors.
- 7 async test functions: `test_send_payload_shape`, `test_extracts_content_from_choices`, `test_fallback_on_unexpected_json`, `test_conversation_state`, `test_reset_clears_conversation`, `test_retries_on_server_error`, `test_connection_error_returns_adapter_response`

#### `test_detectors/test_goal_hijacking.py`
- One-line: Tests GoalHijackingDetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_detectors/test_xpia.py`
- One-line: Tests XPIADetector against vulnerable and hardened mocks.
- 2 async test functions: `test_detects_vulnerable_agent`, `test_passes_hardened_agent`

#### `test_converters/__init__.py`
- One-line: Package marker (empty).

#### `test_converters/test_encodings.py`
- One-line: Tests for all 5 payload converters plus registry.
- 11 test functions: each converter produces non-empty different output, Unicode homoglyph verifies specific replacements, `get_converters()` returns all or filtered by name, `enable_converters=False` produces no extra cases

#### `test_reports/__init__.py`
- One-line: Package marker (empty).

#### `test_reports/test_sarif.py`
- One-line: Tests SARIF report generation.
- 3 test functions: basic structure validation, rule ID mapping, save to file

#### `test_integration/test_scanner.py`
- One-line: Integration tests running the full Scanner pipeline against MockAdapters, plus probe/judge/attacker/converter/adaptive integration tests.
- 19 async test functions (original 12 + 7 new):
  - `test_vulnerable_agent_gets_low_grade` -- asserts grade F, has failed tests with per-detector summaries
  - `test_hardened_agent_gets_high_grade` -- asserts grade A or B
  - `test_probe_succeeds_with_mock_adapter` -- probe passes with normal MockAdapter
  - `test_probe_fails_on_error_response` -- ProbeError on adapter error
  - `test_probe_fails_on_empty_response` -- ProbeError on empty text
  - `test_probe_fails_on_http_error_status` -- ProbeError on status >= 400
  - `test_judge_skips_when_budget_zero` -- all results stay HEURISTIC
  - `test_judge_triggers_on_low_confidence` -- mocked judge refines low-confidence results
  - `test_judge_handles_exception_gracefully` -- judge errors don't crash scanner
  - `test_attacker_skips_when_budget_zero` -- returns empty dict
  - `test_attacker_skips_when_no_api_key` -- returns empty dict
  - `test_attacker_routes_tests_to_correct_detectors` -- routes by attack_vector, drops unmatched
  - `test_judge_mode_evaluates_all_results` -- eval_mode="judge" sends all results to judge
  - `test_judge_mode_respects_budget` -- eval_mode="judge" + budget=0 skips judge
  - `test_converters_multiply_test_cases` -- enable_converters=True increases test count
  - `test_converters_disabled_by_default` -- enable_converters=False no extra cases
  - `test_converters_filter_by_name` -- converter_names filters to specific converters
  - `test_adaptive_disabled_by_default` -- enable_adaptive_attacks=False skips adaptive
  - `test_adaptive_skips_without_api_key` -- no API key skips adaptive
- Local fixtures: `integration_scan_config` (budget 500), `integration_agent_config`

#### `test_integration/test_cli.py`
- One-line: Tests CLI options (fail-below, quiet mode).
- 4 test functions: fail-below triggers exit code 1, fail-below passes above threshold, quiet suppresses terminal, quiet still writes reports

---

## Data Flow

A scan works end-to-end as follows:

```
CLI (cli.py)
  |-- --adapter http|openai, --model gpt-4
  v
Scanner.run() (scanner.py)
  |
  |-- 1. _probe(adapter)                 [Health-check: send "hello", verify non-empty 2xx response]
  |
  |-- 2. _generate_attacker_tests()      [AttackerAgent generates domain-specific tests via Claude; routes by attack_vector]
  |
  |-- 3. For each detector in DETECTOR_REGISTRY:
  |     |
  |     |-- detector.run(agent_config)    [BaseDetector.run()]
  |     |     |
  |     |     |-- a. generate(agent_config)       [subclass: creates TestCase list from payloads]
  |     |     |-- b. execute(test_cases)           [BaseDetector: sends each payload N times via adapter]
  |     |     |     |-- adapter.send(payload)      [AgentAdapter: HTTP POST, OpenAI Chat, or mock]
  |     |     |     |-- adapter.reset()            [between runs]
  |     |     |-- c. evaluate(test_case, responses)[subclass: analyzes responses, returns TestResult list]
  |     |     |-- d. _refine_with_judge(results)   [LLMJudge re-evaluates low-confidence heuristic results]
  |     |     |-- Returns: list[TestResult]
  |     |
  |     |-- _run_attacker_tests(detector, extra_tests)  [execute + evaluate + judge for attacker-generated tests]
  |     |-- Stores results in results_by_detector[name]
  |
  |-- 4. ScoringEngine.calculate_scorecard() [Groups by test_case_id, counts pass/fail, builds DetectorSummary with FailedTest details]
  |
  v
ScanResult (scorecard, results_by_detector, duration, errors)
  |
  v
Reports (cli.py generates terminal/JSON/HTML from scorecard + agent_config + duration + budget)
```

Each detector's cycle:
1. **generate()** -- reads static payloads from `attacker/payloads.py` and creates `TestCase` objects
2. **execute()** -- sends each test case `TestCase.runs` times (default 3) through the adapter; tracks budget; handles multi-turn conversations
3. **evaluate()** -- analyzes each `AdapterResponse` using heuristic pattern matching (compliance indicators, refusal indicators, regex patterns) and produces `TestResult` objects with pass/fail, confidence, and evidence
4. **_refine_with_judge()** -- for results with `evaluation_method=HEURISTIC` and `confidence < 0.8`, calls LLMJudge to re-evaluate; replaces result with judge verdict if budget allows

---

## Key Interfaces

### BaseDetector (ABC) -- `detectors/base.py`

```python
class BaseDetector(ABC):
    def __init__(self, adapter: AgentAdapter, config: ScanConfig) -> None
    @abstractmethod
    def generate(self, agent_config: AgentConfig) -> list[TestCase]
    async def execute(self, test_cases: list[TestCase]) -> list[tuple[TestCase, list[AdapterResponse]]]
    @abstractmethod
    def evaluate(self, test_case: TestCase, responses: list[AdapterResponse]) -> list[TestResult]
    async def _refine_with_judge(self, results: list[TestResult], test_case_lookup: dict[str, TestCase]) -> list[TestResult]
    async def run(self, agent_config: AgentConfig) -> list[TestResult]
```

Contract:
- `generate()` must return a non-empty list of TestCase objects
- `evaluate()` must return one TestResult per AdapterResponse
- `_refine_with_judge()` re-evaluates low-confidence heuristic results with LLMJudge (budget-gated)
- `run()` is the public API: calls generate -> execute -> evaluate -> _refine_with_judge

### AgentAdapter (ABC) -- `adapters/base.py`

```python
class AgentAdapter(ABC):
    @abstractmethod
    async def send(self, message: str) -> AdapterResponse
    async def send_conversation(self, messages: list[str]) -> list[AdapterResponse]
    async def reset(self) -> None
```

Contract:
- `send()` must always return an AdapterResponse (never raise; put errors in `error` field)
- `send_conversation()` calls `send()` in sequence (override for stateful protocols)
- `reset()` clears any conversation state

### AdapterResponse (dataclass) -- `adapters/base.py`

```python
@dataclass
class AdapterResponse:
    text: str
    status_code: int = 200
    response_time_ms: float = 0.0
    raw: dict | None = None
    error: str | None = None
```

---

## Where Things Live (Quick Reference)

| Question | Answer |
|----------|--------|
| Where are the attack payloads? | `src/agentgate/attacker/payloads.py` |
| Where is scoring logic? | `src/agentgate/scoring/engine.py` |
| Where are PII/injection regex patterns? | `src/agentgate/evaluation/heuristic.py` (standalone evaluator) and each detector's `evaluate()` method (inline patterns) |
| Where are the Pydantic models? | `src/agentgate/models/` (agent.py, test_case.py, result.py, score.py) |
| Where is the detector registry? | `src/agentgate/detectors/__init__.py` (`DETECTOR_REGISTRY` dict) |
| Where are test fixtures? | `tests/conftest.py` |
| Where are the mock adapter rules? | `src/agentgate/adapters/mock.py` (`vulnerable()` and `hardened()` classmethods) |
| Where is the CLI defined? | `src/agentgate/cli.py` |
| Where is the test agent? | `test_agents/insights/agent.py` (agent logic) and `test_agents/insights/server.py` (FastAPI server) |

### How to Add a New Detector

1. Create `src/agentgate/detectors/your_detector.py`
2. Define a class that extends `BaseDetector`
3. Implement `generate(agent_config) -> list[TestCase]` -- create test cases from payloads
4. Implement `evaluate(test_case, responses) -> list[TestResult]` -- analyze responses
5. Add payloads to `src/agentgate/attacker/payloads.py` (or define inline)
6. Add the corresponding `AttackVector` value to `src/agentgate/models/test_case.py` (if needed)
7. Register the detector in `src/agentgate/detectors/__init__.py`:
   - Import the class
   - Add entry to `DETECTOR_REGISTRY`
   - Add to `__all__`
8. No category mapping needed — scoring is now based on raw pass/fail counts
10. Add rules to `MockAdapter.vulnerable()` and `MockAdapter.hardened()` in `adapters/mock.py`
11. Create `tests/test_detectors/test_your_detector.py` with vulnerable/hardened test pair
12. Update this `index.md` file

### How to Add a New Report Format

1. Create `src/agentgate/reports/your_report.py`
2. Implement a class with `generate(scorecard, agent_config, duration, budget)` and `save(path)` methods
3. Add the import to `src/agentgate/reports/__init__.py`
4. Add the format option to `cli.py`:
   - Add to the `--format` Choice list
   - Add rendering logic in the `scan` command
5. Update this `index.md` file

---

## Known Issues / Gaps

### Missing Detectors
- 8 detectors implemented (prompt_injection, system_prompt_leak, data_exfiltration, hallucination, input_validation, tool_misuse, goal_hijacking, xpia)
- No BOLA (Broken Object-Level Authorization) detector
- No BFLA (Broken Function-Level Authorization) detector
- No SSRF (Server-Side Request Forgery) detector
- No rate-limiting/DoS detector

### Circular Mock Tests
- Tests run detectors against `MockAdapter.vulnerable()` and `MockAdapter.hardened()`
- The mock response rules are hand-crafted to match the detector evaluation logic
- This means tests validate that "our patterns match our patterns" rather than testing against real agent behavior
- No tests against the actual InsightsAgent or any live endpoint

### Hallucination Detection
- Hallucination detection is basic pattern matching (uncertainty phrases, confident fabrication phrases)
- No ground-truth verification -- relies on keyword heuristics
- Known-answer queries only check if the expected string appears in the response

### Evaluation Modules
- `HeuristicEvaluator` in `evaluation/heuristic.py` is a standalone class but no detector uses it -- each detector has its own inline evaluation logic
- `LLMJudge` is wired into `BaseDetector._refine_with_judge()` -- in "heuristic" mode, re-evaluates low-confidence (< 0.8) results; in "judge" mode, evaluates ALL results

### Adapter Limitations
- `HTTPAdapter` (REST JSON) and `OpenAIChatAdapter` (OpenAI Chat Completions format) are implemented
- No WebSocket, gRPC, or SDK-based adapters
- `HTTPAdapter` assumes JSON request/response format with configurable field names

### Report Limitations
- Terminal report shows top 5 failed tests (hardcoded limit)
