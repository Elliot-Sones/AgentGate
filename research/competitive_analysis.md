# Competitive Analysis: AI Agent Security Testing Tools

Research date: 2026-03-03

---

## Executive Summary

We analyzed 11 tools/frameworks in the AI security testing space. The key insight: **the market has evolved far beyond prompt fuzzing**. Leading tools now test tool-calling abuse, multi-turn adaptive attacks, memory poisoning, cross-session leaks, and indirect injection through RAG/external content. AgentScorer currently only does single-turn prompt testing with keyword matching — the most basic tier of what competitors offer.

### Where AgentScorer Stands

| Capability | AgentScorer | PyRIT | Promptfoo | Giskard | AgentDojo |
|---|---|---|---|---|---|
| Single-turn prompt attacks | Yes | Yes | Yes | Yes | Yes |
| Multi-turn adaptive attacks | No | Yes (Crescendo, TAP, PAIR) | Yes (Crescendo, GOAT, Hydra) | Yes (Crescendo, Skeleton Key, GOAT) | No |
| Prompt encoding/obfuscation | No | Yes (61 converters) | Yes (Base64, ROT13, leetspeak, etc.) | Yes (Base64, ROT13, Unicode, etc.) | No |
| LLM-as-judge evaluation | Wired but untested | Yes (SelfAskTrueFalseScorer) | Yes (GPT-4o default) | Yes (4-tier system) | No (ground-truth state inspection) |
| Tool/function call testing | No | Yes (XPIA orchestrator) | Yes (excessive-agency, tool-discovery) | Yes (BOLA, BFLA, parameter hallucination) | Yes (primary focus) |
| Memory/state poisoning | No | No | Yes (memory-poisoning plugin) | No (Hub only) | No |
| Indirect injection (RAG/web) | No | Yes (XPIA via blob/web) | Yes (indirect-web-pwn, rag-poisoning) | Yes (RAGET) | Yes (via tool outputs) |
| API-level security (BOLA/BFLA) | No | No | Yes (dedicated plugins) | Yes (Hub) | No |
| CI/CD integration | No | No | Yes (--fail-below, SARIF) | Yes (Hub) | No |
| OWASP LLM Top 10 coverage | 3/10 | ~6/10 | 10/10 | 8/10 (Hub) | 1/10 |

---

## 1. PyRIT (Microsoft)

**What it is:** Python Risk Identification Tool — Microsoft's open-source red teaming framework for generative AI systems. Built by Microsoft's AI Red Team, now integrated into Azure AI Foundry.

**GitHub:** https://github.com/Azure/PyRIT
**Docs:** https://azure.github.io/PyRIT/
**Paper:** https://arxiv.org/html/2410.02828v1
**License:** MIT

### Architecture

Five core components in a modular "Lego-brick" design:

1. **Datasets** — Seed prompts, jailbreak templates, images, attack strategies
2. **Orchestrators** — Coordinate attacks end-to-end. Types:
   - `PromptSendingOrchestrator` — Single-turn bulk sending
   - `RedTeamingOrchestrator` — Multi-turn with adversarial LLM
   - `XPIATestOrchestrator` — Cross-domain prompt injection (indirect injection via blob storage, web, etc.)
   - `CrescendoOrchestrator` — Gradual escalation over turns
   - `TreeOfAttacksOrchestrator` — Branching attack paths (TAP algorithm)
   - `PAIROrchestrator` — Prompt Automatic Iterative Refinement
3. **Converters** — Transform prompts before sending. **61 built-in converters** including:
   - Encoding: Base64, ROT13, Morse, Caesar cipher, Atbash, ASCII art
   - Unicode: leetspeak, confusables, superscript, random capitalization
   - Semantic: MathPromptConverter (frame as math), PersuasionConverter (expert endorsement), RandomTranslationConverter
   - Media: image compression, text-to-image overlay, audio
4. **Targets** — Anything receiving prompts: LLMs, HTTP endpoints, Azure services, storage accounts
5. **Scoring Engine** — Evaluates attack success

### Scoring / Evaluation

| Scorer Type | How It Works |
|---|---|
| SelfAskTrueFalseScorer | Adversarial LLM judges yes/no on attack success |
| SelfAskScaleScorer | LLM rates on numeric scale |
| SelfAskLikertScorer | Ordinal measurement (1-5) |
| SelfAskCategoryScorer | Classifies into predefined categories |
| SelfAskRefusalScorer | Detects when target refused (context-aware, not pattern matching) |
| SubStringScorer | Keyword presence check |
| PatternScorer | Regex matching |
| AzureContentFilterScorer | External API: Azure Content Safety |
| PromptShieldScorer | External API: Azure Prompt Shield |
| TrueFalseCompositeScorer | Combines multiple scorers with AND/OR logic |
| HumanInTheLoopScorerGradio | Human evaluator via web UI |

### Multi-Turn Attack Strategies

- **PAIR (Prompt Automatic Iterative Refinement):** Adversarial LLM generates attack → sends to target → scores result → refines attack. Repeats until objective achieved or budget exhausted.
- **Crescendo:** Start with benign conversation, gradually escalate harm level. Backtracks on refusal. Evaluated against ChatGPT, Gemini, LLaMA with high ASR.
- **TAP (Tree of Attacks with Pruning):** Branching attack paths exploring multiple directions. Prunes unsuccessful branches. >80% jailbreak rate against GPT-4.
- **GCG (Greedy Coordinate Gradient):** White-box gradient-based adversarial suffix optimization. Requires model weight access.
- **Skeleton Key:** Asks model to augment (not change) guidelines — provide warnings instead of refusals.
- **FlipAttack:** Reverses characters in harmful portion, instructs model to reverse-interpret. ~98% ASR against GPT-4o.
- **Many-Shot Jailbreaking:** Prepends 50-250 fake Q&A pairs exploiting long-context windows.
- **Context Compliance Attack:** Injects fabricated conversation history where AI already agreed to help.

### Cross-Domain Prompt Injection (XPIA)

PyRIT's most unique capability — testing indirect injection through external content:

1. Attacker embeds malicious instructions in an HTML file / PDF / resume
2. Uploads to Azure Blob Storage or web server
3. Target LLM (with tools) fetches and processes the content
4. LLM treats malicious instructions as legitimate
5. Scorer evaluates if injection succeeded

Demonstrated against: resume parsing (AI recruiter), web summarization, email processing.

### What PyRIT Does That We Don't

- 61 prompt encoding/obfuscation converters (we have 0)
- Multi-turn adaptive attacks with backtracking
- Cross-domain indirect injection testing
- LLM-as-judge with multiple scoring strategies
- Multimodal attacks (image, audio, video)
- Memory system for tracking attack history across sessions
- Composable orchestrators (can chain attack strategies)

### What PyRIT Doesn't Do

- No API-level security testing (BOLA, BFLA, auth bypass)
- No CI/CD integration or threshold-based pass/fail
- No memory/state poisoning
- Steep learning curve — designed for security researchers, not developers

---

## 2. Promptfoo

**What it is:** Open-source CLI/library for LLM evaluation and red teaming. The most comprehensive tool in terms of vulnerability coverage. 133 plugins, 50+ vulnerability types.

**GitHub:** https://github.com/promptfoo/promptfoo (8,800+ stars)
**Docs:** https://www.promptfoo.dev/docs/red-team/
**License:** MIT

### Architecture

Declarative YAML configuration separating:
- **Plugins** (what to attack) — 133 vulnerability-specific test generators
- **Strategies** (how to deliver) — Attack delivery mechanisms
- **Graders** (how to evaluate) — LLM judge with customizable criteria

Three testing layers for agents:
1. **Black-box / end-to-end** — Test the full system as a user
2. **Component testing** — Isolate individual steps (planning, tool selection, reasoning)
3. **Trace-based / glass-box** — OpenTelemetry tracing to observe internal agent behavior

### Vulnerability Categories (133 plugins)

**Security & Access Control:**
- SQL injection, Shell injection, SSRF
- BOLA (Broken Object Level Authorization)
- BFLA (Broken Function Level Authorization)
- Cross-session leak, Indirect prompt injection, ASCII smuggling, Prompt extraction

**Agent-Specific:**
- Excessive agency (agent takes actions beyond scope)
- Goal misalignment
- Tool discovery (reveal available tools)
- Memory poisoning (corrupt persistent memory)
- RAG poisoning / RAG document exfiltration

**Privacy:** PII via direct exposure, API/database, social engineering, session data. COPPA, FERPA compliance.

**Industry-Specific:** Financial (calculation errors, market manipulation), Medical (hallucinations, drug interactions), Ecommerce (fraud, payment security)

### Attack Strategies (Tiered by ASR)

**Static (20-30% ASR):** Base64, Hex, ROT13, Morse, Leetspeak, Homoglyphs, Image encoding, Jailbreak templates

**Dynamic Single-Turn (40-80% ASR):** Iterative jailbreak (LLM-as-judge loop), Composite jailbreaks, Best-of-N, Tree-based, Citation/academic framing, Math prompt encoding

**Multi-Turn (70-90% ASR):**
- **Crescendo** — Gradual escalation. 97% ASR@10 against Llama 3.1, 88% against GPT-4-Turbo
- **GOAT** — Meta Research. Observe → Plan → Attack cycle per turn
- **Hydra** — Persistent scan-wide memory, backtracks on refusal, pivots to unexplored branches
- **Meta Agent** — Builds custom attack taxonomy per target, learns from all attempts

### Compliance Framework Presets

`owasp:llm`, `owasp:api`, `mitre:atlas`, `nist:ai:measure`, `iso:42001`, `gdpr`, `eu:ai-act`

### What Promptfoo Does That We Don't

- 133 vulnerability plugins vs our 6 detectors
- Multi-turn adaptive attacks with 70-90% ASR
- API-level security testing (BOLA, BFLA, SSRF)
- Agent tool-calling abuse (excessive agency, tool discovery)
- Memory and RAG poisoning
- MCP server security testing
- OpenTelemetry trace-based testing
- Industry-specific testing
- CI/CD integration with threshold pass/fail
- Compliance framework presets

---

## 3. Giskard

**What it is:** AI security testing with two tiers — open-source scanner (9 detectors) and enterprise Hub (40+ probes with autonomous red teaming agents).

**GitHub:** https://github.com/Giskard-AI/giskard-oss
**Docs:** https://docs.giskard.ai/
**License:** Apache 2.0 (OSS), Commercial (Hub)

### Architecture

Key design principle: **Context-aware generation** — the attacker LLM reads your model's description and knowledge base before generating inputs. Attacks are domain-specific.

### 9 OSS Detectors

| Detector | What It Tests |
|---|---|
| LLMPromptInjectionDetector | 12+ jailbreak/manipulation techniques |
| LLMCharsInjectionDetector | Control characters causing prompt amnesia |
| LLMBasicSycophancyDetector | Agreement bias via paired opposing prompts |
| LLMImplausibleOutputDetector | Hallucination proxy via adversarial inputs |
| LLMHarmfulContentDetector | Content filter bypass |
| LLMStereotypesDetector | Bias/discrimination |
| LLMInformationDisclosureDetector | PII, system prompt leak, credential exposure |
| LLMOutputFormattingDetector | Format constraint violations |
| Faithfulness (RAGET) | RAG coherence against retrieval context |

### Hub Additional Capabilities

- 40+ probes covering OWASP LLM Top 10
- Autonomous red teaming agent (strategy proposer + adaptive attacker)
- Multi-turn: Crescendo, Skeleton Key, GOAT
- Tool/function calling security: BOLA, BFLA, parameter hallucination, false completion detection
- Continuous automated scanning

### Evaluation (4 Tiers)

1. **String Match** — Keyword check (weakest, baseline only)
2. **Conformity Check** — LLM judge evaluates rule compliance with reasoning
3. **Groundedness Check** — Verifies facts present in reference context (RAG)
4. **Correctness Check** — Strict: answer must fully agree with reference, no omissions

### Tool/Function Calling Testing (Hub)

- Mock simulation of production environments
- Parameter hallucination detection (agent fabricates tool parameter values)
- BOLA (access other user's data via tool calls)
- BFLA (invoke unauthorized functions)
- False completion detection (agent claims it did something it didn't)

### What Giskard Does That We Don't

- Domain-specific attack generation
- Sycophancy detection (paired opposing prompts)
- Control character injection
- RAG-specific testing with component isolation (RAGET)
- Tool call security testing
- 4-tier evaluation system
- Vulnerability-to-test-suite pipeline (regression testing)

---

## 4. AgentDojo (ETH Zurich)

**What it is:** Security benchmark for tool-augmented AI agents. 97 tasks across 4 domains, 629 security test cases. Focuses exclusively on indirect prompt injection through tool outputs.

**GitHub:** https://github.com/ethz-spylab/agentdojo
**Paper:** https://arxiv.org/abs/2406.13352
**Presented at:** NeurIPS 2024

### How It Works

- 97 realistic user tasks across: email/calendar, e-banking, travel booking, Slack workspace
- Each task paired with an injection task (attacker wants the agent to do something different)
- Agent has tools (send email, transfer money, book flight, etc.)
- Malicious content embedded in tool outputs

### Three Metrics (Unique in the Field)

1. **Benign Utility (BU):** Task completion rate with no attack
2. **Utility Under Attack (UA):** Task completion rate when injection is present
3. **Attack Success Rate (ASR):** How often the attacker's goal is achieved

### Evaluation Method

**Programmatic ground-truth checkers** — inspects environment state after execution (what the agent actually did), NOT what it said. Avoids circular LLM-judges-LLM problem.

### Key Finding

GPT-4o: 69% benign utility → 45% under attack. No current defense eliminates the tradeoff.

### What AgentDojo Does That We Don't

- Tests tool-calling agents in realistic environments
- Measures utility degradation alongside security
- Ground-truth state inspection
- Indirect injection through tool outputs

---

## 5. OWASP Top 10 for LLM Applications (2025)

**URL:** https://genai.owasp.org/llm-top-10/

Our current coverage:

| ID | Category | AgentScorer Coverage |
|----|----------|---------------------|
| LLM01 | Prompt Injection | Yes (basic) |
| LLM02 | Sensitive Information Disclosure | Partial (system_prompt_leak) |
| LLM03 | Supply Chain | No |
| LLM04 | Data and Model Poisoning | No |
| LLM05 | Improper Output Handling (XSS, SQLi, SSRF) | No |
| LLM06 | Excessive Agency (tool abuse) | No (tool_misuse is prompt-only) |
| LLM07 | System Prompt Leakage | Yes (basic) |
| LLM08 | Vector and Embedding Weaknesses | No |
| LLM09 | Misinformation / Hallucination | Yes (basic) |
| LLM10 | Unbounded Consumption (DoS) | No |

**We cover 3/10 categories, and those 3 are basic prompt-level testing only.**

---

## 6. Other Tools

### HouYi
- **Focus:** Black-box prompt injection against real deployed apps
- **Unique:** Three-element injection (pre-constructed prompt + context partition + payload), inspired by SQL injection
- **Results:** 31/36 live LLM apps found vulnerable, 10 vendors confirmed
- **URL:** https://github.com/LLMSecurity/HouYi

### Vigil
- **Focus:** Input/output scanning for prompt injection
- **5 scanners:** YARA rules, transformer classifier, vector DB similarity, prompt-response similarity, canary token
- **Unique:** Canary token mechanism (inject secret in system prompt, detect if leaked in output)
- **URL:** https://github.com/deadbits/vigil-llm

### Rebuff
- **Focus:** Prompt injection detection with self-hardening
- **4 layers:** Heuristics → LLM detection → vector DB → canary tokens
- **Unique:** Self-hardening feedback loop — successful attacks stored as embeddings for future detection
- **URL:** https://github.com/protectai/rebuff

### LLM Guard
- **Focus:** Most comprehensive scanning library — 35 scanners (15 input, 20 output)
- **Covers:** PII anonymization/deanonymization, invisible text (zero-width Unicode), malicious URLs, factual consistency, secrets detection
- **Unique:** Entirely local, provider-agnostic, no LLM calls needed
- **URL:** https://github.com/protectai/llm-guard

### NeMo Guardrails (NVIDIA)
- **Focus:** Runtime guardrail enforcement, not just testing
- **5 interception points:** Input rails → Dialog rails → Retrieval rails → Execution rails → Output rails
- **Unique:** Colang DSL for defining guardrail policies; execution rails validate tool call inputs
- **URL:** https://github.com/NVIDIA-NeMo/Guardrails

### Lakera
- **Focus:** Commercial AI security with human red-team data flywheel
- **Unique:** Gandalf (CTF) and Agent Breaker generate ~100K new attack patterns/day, training the Guard classifier
- **URL:** https://www.lakera.ai/lakera-guard

---

## Key Patterns Across All Tools

### 1. Multi-Turn is Table Stakes
Every serious tool supports multi-turn adaptive attacks. The most effective strategies (Crescendo, GOAT, Hydra) achieve 70-90% ASR vs 20-30% for static single-turn. AgentScorer is single-turn only.

### 2. LLM-as-Judge is Standard
Every tool except AgentDojo and LLM Guard uses LLM-as-judge for evaluation. Keyword matching is considered the weakest possible evaluation.

### 3. Prompt Encoding/Obfuscation is Expected
PyRIT has 61 converters. Promptfoo has ~20 static strategies. AgentScorer sends raw plaintext prompts.

### 4. Tool/Function Call Testing is the New Frontier
Testing what an agent DOES (which tools it calls, with what parameters) is fundamentally different from testing what it SAYS. AgentDojo, Promptfoo, and Giskard Hub all test this. We don't.

### 5. Indirect Injection is Critical
Attacks through external content (RAG documents, web pages, emails, tool outputs) bypass all direct prompt-level defenses. PyRIT, Promptfoo, Giskard, and AgentDojo all test this. We don't.

### 6. Domain-Specific > Generic
Giskard generates attacks tailored to the agent's domain. Promptfoo uses the `purpose` field. Generic "say HACKED" prompts are the weakest possible attack.

---

## What This Means for AgentScorer

### Critical Gaps (Must Address)

1. **Evaluation quality** — Keyword matching produces false positives (agent refused but got flagged for quoting "hacked"). Need LLM judge as default.
2. **Prompt encoding** — We send raw plaintext. Any basic guardrail blocks these. Need at least 10 encoding strategies.
3. **Multi-turn attacks** — Single-turn is trivially defended. Need Crescendo-style escalation at minimum.
4. **Tool/function call testing** — Real agents have tools. We don't test tool usage at all.
5. **Indirect injection** — Attacks through RAG, web content, tool outputs. We don't test any of these.

### Important Gaps (Should Address)

6. **Domain-specific attack generation** — Use agent description to generate targeted attacks.
7. **OWASP coverage** — We cover 3/10 categories. Need at minimum: Excessive Agency, Improper Output Handling, Unbounded Consumption.
8. **CI/CD integration** — `--fail-below`, SARIF output.
9. **API-level security** — BOLA, BFLA, auth bypass, rate limiting.

### Differentiators We Could Own

10. **Simplicity** — PyRIT requires security researcher expertise. Promptfoo requires YAML configuration. We could be the "one command" scanner.
11. **Combined utility + security** — Only AgentDojo measures both. We could test whether the agent still works correctly while also testing security.
12. **Agent-native testing** — Most tools were built for LLMs and retrofitted for agents. We could build agent-first.

---

## Sources

### PyRIT
- https://github.com/Azure/PyRIT
- https://azure.github.io/PyRIT/
- https://arxiv.org/html/2410.02828v1
- https://deepwiki.com/Azure/PyRIT/7.1-scorer-architecture
- https://www.nccgroup.com/research-blog/proxying-pyrit-for-fun-and-profit/

### Promptfoo
- https://github.com/promptfoo/promptfoo
- https://www.promptfoo.dev/docs/red-team/
- https://www.promptfoo.dev/docs/red-team/strategies/
- https://www.promptfoo.dev/docs/red-team/plugins/
- https://www.promptfoo.dev/docs/red-team/agents/
- https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/
- https://www.promptfoo.dev/blog/llm-agent-red-teaming-plugins/

### Giskard
- https://github.com/Giskard-AI/giskard-oss
- https://docs.giskard.ai/oss/sdk/security.html
- https://www.giskard.ai/knowledge/function-calling-in-llms-testing-agent-tool-usage-for-ai-security
- https://www.giskard.ai/knowledge/new-llm-vulnerability-scanner-for-dynamic-multi-turn-red-teaming

### AgentDojo
- https://github.com/ethz-spylab/agentdojo
- https://arxiv.org/abs/2406.13352

### OWASP
- https://genai.owasp.org/llm-top-10/

### Other Tools
- HouYi: https://github.com/LLMSecurity/HouYi
- Vigil: https://github.com/deadbits/vigil-llm
- Rebuff: https://github.com/protectai/rebuff
- LLM Guard: https://github.com/protectai/llm-guard
- NeMo Guardrails: https://github.com/NVIDIA-NeMo/Guardrails
- Lakera: https://www.lakera.ai/lakera-guard
