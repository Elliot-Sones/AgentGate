# Adversarial Agent Systems: Autonomous AI Agents Attacking AI Agents

## A Comprehensive Research Survey (March 2026)

---

## Table of Contents

1. [The Agent-vs-Agent Paradigm](#1-the-agent-vs-agent-paradigm)
2. [Existing Implementations](#2-existing-implementations)
3. [Complete Attacker Agent Architecture](#3-complete-attacker-agent-architecture)
4. [Memory Exploitation Attacks](#4-memory-exploitation-attacks)
5. [Multi-Agent Attack Strategies](#5-multi-agent-attack-strategies)
6. [MCP Tool Poisoning](#6-mcp-tool-poisoning)
7. [Ideal Attacker Agent Design](#7-ideal-attacker-agent-design)
8. [Evaluation Methods](#8-evaluation-methods)
9. [Cutting-Edge Papers](#9-cutting-edge-papers)
10. [Cutting-Edge Repos](#10-cutting-edge-repos)

---

## 1. The Agent-vs-Agent Paradigm

### Why Static Test Cases Are Insufficient

Traditional red teaming of AI systems relies on curated datasets of adversarial prompts---static, hand-crafted inputs that are evaluated one-shot against a target model. This approach suffers from three fundamental limitations:

- **Brittleness**: A static prompt that jailbreaks GPT-4 today may fail tomorrow after a safety patch. Static test suites become stale within weeks.
- **Lack of Adaptivity**: Real-world attackers do not submit a single prompt and give up. They probe, observe the target's response patterns, adjust their approach, and escalate over multiple conversational turns. Static datasets cannot capture this dynamic interaction.
- **Coverage Gaps**: Human red teamers can only think of so many attack strategies. The combinatorial space of multi-turn conversations, persona manipulations, encoding tricks, and context exploitations is far too large for manual enumeration.

Research from Microsoft's AI Red Team, Meta, and academic labs has converged on a key insight: **the most effective way to stress-test an AI agent is to deploy another AI agent against it**. The Crescendo attack (Russinovich et al., 2024) demonstrated that multi-turn escalation---starting innocuously and gradually building toward harmful content---bypasses defenses that catch any single prompt in isolation. GOAT (Pavlova et al., 2024) showed that an attacker agent equipped with a portfolio of strategies and chain-of-thought reasoning consistently outperforms static prompt sets.

### How This Differs from Traditional Fuzzing

Classical software fuzzing generates random or semi-structured inputs to trigger crashes. AI red teaming agents differ fundamentally:

- **Semantic Understanding**: Attacker agents understand the meaning of the target's responses and adjust accordingly.
- **Strategic Reasoning**: They employ explicit reasoning loops ("Observation, Thought, Strategy") to plan multi-step attacks.
- **Conversational Memory**: They maintain state across turns, tracking which approaches have been tried, which were refused, and which showed partial progress.
- **Goal Orientation**: Rather than random exploration, they pursue a specific adversarial objective and judge their own progress toward it.

The paradigm shift is from "generate-and-test" to "converse-and-adapt." The attacker is not a fuzzer---it is a strategic adversary.

---

## 2. Existing Implementations

### 2.1 PyRIT Orchestrators (Microsoft)

[PyRIT](https://github.com/Azure/PyRIT) (Python Risk Identification Tool) is Microsoft's open-source AI red teaming framework, currently at v0.11.0 (February 2026). It provides a modular architecture of **orchestrators**, **converters**, **scorers**, and a **memory system** that work together to automate adversarial testing across text, image, audio, and video modalities.

#### RedTeamingOrchestrator

The base multi-turn orchestrator. It pairs an attacker LLM with a target LLM and manages a multi-turn conversation loop. The attacker is given an adversarial objective (e.g., "get the target to provide instructions for X") and iteratively refines its prompts based on the target's responses. A scorer evaluates each response to determine if the attack objective has been achieved. The conversation continues until success or a maximum turn count is reached.

#### CrescendoOrchestrator

Implements the Crescendo attack from Russinovich, Salem, & Eldan (2024). The orchestrator begins with entirely benign, on-topic prompts and gradually escalates toward the adversarial objective over multiple turns. Each individual prompt is innocuous in isolation, making it invisible to single-turn content filters. The orchestrator references the model's own prior replies to build a narrative that naturally culminates in the target producing harmful content. Crescendomation, the automated version, achieved 29--61% higher ASR than prior methods on GPT-4 and 49--71% higher on Gemini-Pro.

#### TreeOfAttacksWithPruningOrchestrator (TAP)

Based on Mehrotra et al. (2024), this orchestrator treats jailbreaking as a tree search problem. It uses three LLMs: an **attacker** that generates candidate prompts using tree-of-thought reasoning, an **evaluator** that prunes unlikely-to-succeed candidates before they reach the target, and the **target** itself. The tree structure enables breadth-first exploration of the attack space---when one branch is blocked, the orchestrator expands alternative branches. TAP achieves 90% success rate against GPT-4 with only ~29 queries, compared to 60% for the best prior method at ~38 queries.

#### XPIATestOrchestrator

Designed for **Cross-domain Prompt Injection Attacks (XPIA)**. This orchestrator tests whether an AI agent can be compromised through content it processes from external sources---documents, web pages, emails, tool outputs. The orchestrator injects adversarial payloads into these external data sources and then triggers the target agent to process them, evaluating whether the injected instructions override the agent's system prompt. This is critical for testing RAG systems, browsing agents, and any application that ingests untrusted data.

#### FlipAttackOrchestrator

Implements the FlipAttack technique (Liu et al., 2024, ICML 2025). This attack exploits the autoregressive left-to-right processing nature of LLMs by applying character/word-level transformations that create "left-side noise." Four flipping modes rearrange characters and words in prompts so that humans (and safety filters) struggle to parse the intent, but the target LLM can denoise and execute the underlying instruction. FlipAttack achieves ~98% ASR against GPT-4o and ~98% bypass rate against 5 guardrail models.

#### PairOrchestrator (PAIR)

Implements Prompt Automatic Iterative Refinement from Chao et al. (2024). Uses in-context learning to iteratively refine a candidate jailbreak prompt. The attacker LLM accumulates its previous attempts and the target's responses in its chat history, learning from each failure to craft increasingly effective prompts. Typically succeeds within 20 queries.

### 2.2 Promptfoo's Red Team Agent

[Promptfoo](https://github.com/promptfoo/promptfoo) is an open-source CLI/library for evaluating and red-teaming LLM applications. Its red teaming system has evolved beyond static prompt testing into a suite of autonomous adversarial agents:

#### Meta-Agent (`jailbreak:meta`)

The Meta-Agent dynamically builds a custom attack taxonomy based on the specific target under test. Rather than cycling through a fixed list of attack types, it observes target responses, maintains memory across iterations, and strategically pivots between fundamentally different attack approaches. When one class of attack fails, it shifts to an entirely different technique rather than refining the same pattern. It is reported to be up to 50% more effective than some multi-turn strategies despite being a single-shot approach.

#### Hydra (`jailbreak:hydra`)

Hydra is an adaptive multi-turn attacker agent with **persistent scan-wide memory**. It branches across multiple conversational paths, remembers every refusal, automatically manages backtracking, and shares successful tactics across the entire scanning session. During execution, multiple sub-agents attack, judge, and replan at every step, monitoring effectiveness and pivoting rapidly. Hydra is specifically designed for stateful applications like chatbots and agents where vulnerabilities may only emerge across extended interactions.

#### GOAT Strategy Integration

Promptfoo has integrated Meta's GOAT methodology as the `jailbreak:goat` strategy, enabling automated multi-turn adversarial conversations that dynamically adapt based on target responses. It implements the "Observation, Thought, Strategy" reasoning loop from the GOAT paper.

### 2.3 Giskard's Autonomous Red Teamer

[Giskard](https://github.com/Giskard-AI/giskard-oss) is a French AI security company that provides an open-source Python library for LLM testing. Their upgraded LLM vulnerability scanner (Giskard 3) deploys autonomous red teaming agents to conduct dynamic, multi-turn attacks across 40+ probes covering both security and business-logic failures.

Key characteristics of Giskard's approach:
- **Adaptive Strategy Adjustment**: When encountering defenses, the testing agent escalates tactics or pivots approaches, mimicking real attackers.
- **Comprehensive Vulnerability Mapping**: Covers OWASP categories including prompt injection, training data extraction, data privacy exfiltration, excessive agency, hallucination/misinformation, and denial of service.
- **Actionable Output**: Every detected vulnerability includes detailed explanations of the attack methodology and severity scoring. Detected vulnerabilities automatically convert into reusable regression tests.
- **RAG-Specific Testing**: Native support for evaluating retrieval-augmented generation pipelines and agent workflows.

### 2.4 GOAT (Meta) --- Generative Offensive Agent Tester

GOAT is a fully automated agentic red teaming system developed by Meta and published in October 2024 (Pavlova et al.), presented at both ICML 2025 and ICLR 2025. It represents one of the most influential works in the agent-vs-agent paradigm.

#### Architecture Breakdown

1. **Initialization**: The attacker LLM is initialized with a violating conversational objective (e.g., "get the target to provide instructions for synthesizing X") and a library of 7 adversarial prompting techniques.

2. **Reasoning Loop**: At each conversation turn, the attacker follows an **"Observation, Thought, Strategy"** chain-of-thought structure:
   - **Observation**: Analyze the target's latest response---did it comply, refuse, or partially comply?
   - **Thought**: Reason about why the current approach is or isn't working.
   - **Strategy**: Select or combine techniques from its repertoire for the next turn.

3. **Technique Portfolio**: GOAT is instantiated with 7 red teaming attack techniques available as tools, including role-playing, hypothetical scenarios, encoding tricks, narrative framing, and progressive escalation.

4. **Dynamic Adaptation**: Unlike scripted attacks, GOAT responds dynamically based on conversation trajectory. It picks and chooses methods like a human red teamer would, combining techniques or abandoning failed approaches.

5. **External Judge**: The final conversation is evaluated by a separate judge LLM to determine whether the adversarial objective was achieved.

#### Performance

- **ASR@10 of 97%** against Llama 3.1 on JailbreakBench
- **ASR@10 of 88%** against GPT-4-Turbo on JailbreakBench
- Achieves high ASR within 5 conversational turns, outperforming Crescendo and other multi-turn methods within the same query budget

### 2.5 Lakera Agent Breaker

[Lakera](https://www.lakera.ai/) created **Gandalf: Agent Breaker**, a gamified distributed red-teaming environment where thousands of players stress-test agentic AI applications under realistic conditions. What began as a game evolved into the world's largest red teaming community with over 80 million adversarial data points.

#### The Backbone Breaker Benchmark (b3)

Built on data from Agent Breaker, b3 is the first human-grounded, threat-realistic benchmark for AI agent security. It combines:
- **10 representative agent threat snapshots** covering system prompt exfiltration, phishing link insertion, malicious code injection, denial-of-service, and unauthorized tool calls
- **19,433 crowdsourced adversarial attacks** from nearly 200,000 human attack attempts (10,900 successful)
- An evaluation methodology that tests how backbone LLMs resist real-world attack patterns

Key findings from b3: models with step-by-step reasoning tend to be more secure; model size is not directly correlated with security; open-weight models are closing the security gap with closed-source models faster than anticipated. The paper "Breaking Agent Backbones" (Bazinska et al., 2025) was published at ICLR 2026 (arXiv:2510.22620).

### 2.6 AutoRedTeamer

**AutoRedTeamer** (Zhou, Wu, Pinto, Chen, Zeng, Yang, Yang, Koyejo, Zou, & Li, 2025) is a fully autonomous red teaming framework published on arXiv in March 2025 (arXiv:2503.15754) and presented at NeurIPS 2025.

#### Dual-Agent Architecture

1. **Red Teaming Agent**: Operates from high-level risk categories alone. Contains:
   - **Risk Analyzer**: Decomposes user inputs into testable components
   - **Seed Prompt Generator**: Creates diverse test cases
   - **Strategy Designer**: Selects attacks based on performance metrics stored in Attack Memory
   - **Attack Judge + Relevance Check**: Evaluates results

2. **Strategy Proposer Agent**: Autonomously discovers and implements new attack vectors by analyzing recent research papers, implementing promising candidates after validation, and adding successful ones to the Attack Library.

#### Lifelong Learning

The "lifelong attack integration" aspect is what distinguishes AutoRedTeamer. The Strategy Proposer continuously monitors new research, extracts novel attack techniques, validates them, and integrates successful ones into the system's repertoire. This means the system's attack capabilities grow over time without human intervention.

#### Performance

- **20% higher ASR** than state-of-the-art methods on HarmBench against Llama-3.1-70B
- **46% reduction** in computational costs compared to existing approaches
- Evaluated against GPT-4o, Llama-3.1-70b, Mixtral-8x7b, and Claude-3.5-Sonnet

### 2.7 AgenticRed

**AgenticRed** (Yuan et al., 2026) is a research framework published on arXiv in January 2026 (arXiv:2601.13518) that treats red teaming as a **system design problem** rather than an attack optimization problem.

#### Meta-Optimization Approach

Inspired by Meta Agent Search, AgenticRed uses an LLM "meta agent" to iteratively design and evolve entire red-teaming system architectures:

1. **Archive Initialization**: Starts with an archive of state-of-the-art red-teaming systems and their performance metrics
2. **Evolutionary Selection**: Uses evolutionary algorithms to select parent systems for producing offspring
3. **System Generation**: The meta agent programs new agentic red-teaming systems by combining, modifying, and extending components from parent systems
4. **Evaluation & Selection**: Each new system is evaluated on red-teaming benchmarks, and successful designs are added back to the archive

#### Key Results

- **96% ASR** on Llama-2-7B (36% improvement over baselines)
- **98% ASR** on Llama-3-8B on HarmBench
- **100% ASR** on GPT-3.5-Turbo and GPT-4o-mini (transfer attacks)
- Demonstrates that evolved system architectures can outperform hand-designed workflows

---

## 3. Complete Attacker Agent Architecture

Based on the collected research, a fully autonomous attacker agent requires the following components:

### 3.1 Strategy Selection

The agent must maintain a **portfolio of attack strategies** and intelligently select among them. Approaches from the literature include:

- **Attack Memory / Performance Tracking**: AutoRedTeamer stores historical ASR for each strategy-target combination. When attacking a new target, the Strategy Designer queries this memory to prioritize attacks that have worked on similar targets.
- **MAP-Elites Behavioral Archive**: QDRT (Quality-Diversity Red-Teaming) uses evolutionary MAP-Elites grids where each cell represents a distinct attack behavior. The archive ensures both quality (high ASR) and diversity (broad coverage of attack types).
- **Dynamic Taxonomy Construction**: Promptfoo's Meta Agent builds a custom attack taxonomy for each target based on observed responses, rather than using a fixed set of categories.

### 3.2 Goal Decomposition

Complex adversarial objectives must be broken into achievable sub-steps:

- **Crescendo-style Escalation**: Decompose "get the target to explain X" into: establish topical context -> get the target to acknowledge X exists -> get the target to discuss X academically -> get the target to provide specifics.
- **GOAT's Observation-Thought-Strategy Loop**: Each turn is a micro-goal. The agent reasons about what intermediate progress has been made and what the next achievable sub-goal should be.
- **Plan-of-Thought**: ASB (Agent Security Bench) introduced a Plan-of-Thought backdoor attack that decomposes objectives into plausible reasoning chains that the target follows.

### 3.3 Memory and State Management

Effective attacker agents require multiple memory systems:

- **Conversation History**: The full transcript of the current attack session, used for in-context learning (PAIR) and escalation tracking (Crescendo).
- **Attack Memory (Cross-Session)**: AutoRedTeamer's persistent store of which strategies work against which target configurations. This enables transfer learning across different attack runs.
- **Scan-Wide Memory**: Promptfoo's Hydra shares findings across all concurrent attack threads within a single scan, enabling one thread to benefit from another's discoveries.
- **Failure Memory**: Tracking what has been tried and failed is as important as tracking successes. The agent must avoid repeating failed approaches and instead use failures to inform new strategies.

### 3.4 Response Evaluation

Determining whether an attack succeeded requires nuanced evaluation:

- **LLM-as-Judge**: The dominant approach. A separate LLM evaluates the target's response against the adversarial objective. HarmBench, GOAT, and AutoRedTeamer all use judge LLMs.
- **Classifier-Based Scoring**: PyRIT supports multiple scorer types---LLM-based, regex-based, and classifier-based---that can be composed for multi-criteria evaluation.
- **Partial Success Detection**: Sophisticated agents detect partial compliance (the target discusses the topic but doesn't provide full details) and use this as a signal to continue escalating rather than restarting.

### 3.5 Backtracking and Retry Logic

When an attack path fails:

- **Tree Search (TAP)**: Maintain multiple branches and expand alternatives when one is pruned. The evaluator scores candidate prompts before they reach the target, preventing wasted queries.
- **Hydra's Branch Management**: Automatically manages backtracking across conversational paths, pivoting to new approaches while preserving context from prior attempts.
- **Exponential Backoff**: If the target appears to be hardening (increasingly firm refusals), the agent may reset the conversation context entirely and try a fundamentally different approach.

### 3.6 Multi-Turn Conversation Management

- **Context Window Management**: Long conversations may exceed context limits. The agent must maintain a compressed state representation of the conversation so far.
- **Persona Consistency**: If the attacker is role-playing (e.g., as a researcher, teacher, or journalist), it must maintain persona consistency across turns to avoid triggering inconsistency detectors.
- **Turn Budget**: Most systems impose a maximum turn count (GOAT uses 10 turns; Crescendo typically succeeds within 5--10). The agent must balance exploration depth against budget constraints.

### 3.7 Attack Portfolio

A comprehensive attacker should include at minimum:

| Category | Techniques |
|----------|-----------|
| **Persona/Role-Play** | DAN, character role-play, authority personas |
| **Encoding/Obfuscation** | Base64, ROT13, FlipAttack, Unicode manipulation |
| **Narrative Framing** | Hypothetical scenarios, fiction writing, academic discussion |
| **Multi-Turn Escalation** | Crescendo, progressive disclosure |
| **Logical/Semantic** | Contradictory premises, false dilemmas, Socratic escalation |
| **Cross-Domain Injection** | XPIA via documents, URLs, tool outputs |
| **Memory Exploitation** | Poisoned few-shot examples, manipulated conversation history |
| **Meta-Cognitive** | Asking the model to ignore instructions, self-reflection hijacking |

---

## 4. Memory Exploitation Attacks

### 4.1 MemoryGraft

**MemoryGraft** (Srivastava & He, 2025, arXiv:2512.16962) is a novel indirect injection attack that compromises agent behavior by implanting malicious "successful experiences" into an agent's long-term memory store.

#### Mechanism

Unlike traditional prompt injections that are transient, MemoryGraft exploits the **semantic imitation heuristic**---the tendency of RAG-augmented agents to replicate patterns from retrieved successful task completions. The attack plants fabricated experience records that:
1. Appear to be legitimate past task completions
2. Contain subtly malicious patterns (e.g., skipping validation, using unsafe shortcuts, executing risky automation)
3. Are semantically similar enough to future victim queries to be reliably retrieved

#### Persistence

The compromise persists indefinitely until the memory store is explicitly purged. Because the poisoned records look like legitimate agent experiences, they bypass instruction-level safety filters that only monitor incoming user prompts.

#### Experimental Results

Tested on MetaGPT's DataInterpreter agent with GPT-4o as the backbone. Even a small number of poisoned records dominated retrieval results for relevant queries, causing the agent to adopt unsafe behaviors systematically.

### 4.2 MINJA

**MINJA** (Memory INJection Attack) was published on arXiv in March 2025 (arXiv:2503.03704) with subsequent versions through February 2026. It demonstrates that an attacker can inject malicious records into an agent's memory bank **solely through query-only interaction**---without any direct access to modify the memory store.

#### Attack Architecture

1. **Bridging Steps**: The attacker crafts interactions designed to create memory entries that bridge between innocuous victim queries and malicious reasoning chains.
2. **Indication Prompt**: An initial prompt guides the agent to autonomously generate bridging steps between topics.
3. **Progressive Shortening**: The indication prompt is gradually removed across interactions so that the malicious memory record becomes self-contained and easily retrieved for future victim queries.

#### Effectiveness

Over 95% injection success rates across diverse agent architectures. The minimal requirements (only query access) mean that any user of a shared agent system can influence the agent's memory and thereby affect other users' interactions.

### 4.3 InjecMEM

**InjecMEM** (published on OpenReview, October 2025) is a targeted memory injection attack requiring only a single interaction with the agent to steer all subsequent responses on a target topic toward attacker-specified outputs.

#### Two-Part Injection

1. **Retriever-Agnostic Anchor**: A concise, on-topic passage with high-recall cues that ensures the poisoned record is retrieved whenever the target topic is queried, regardless of the specific retrieval algorithm used.
2. **Adversarial Command**: A short sequence optimized to remain effective under uncertain fused contexts, variable placements, and long prompts. This command steers the agent's output once the anchor triggers retrieval.

#### Key Properties

- Transfers to fully black-box settings
- Can be delivered indirectly through subsystems (e.g., via tool outputs or document ingestion)
- Single-interaction requirement makes it practical for real-world attacks

### 4.4 Zombie Agents

**"Zombie Agents: Persistent Control of Self-Evolving LLM Agents via Self-Reinforcing Injections"** (arXiv:2602.15654, February 2026) identifies a critical blind spot in current defenses: the **memory consolidation phase**. Once malicious content is accepted as a benign memory entry, it bypasses instruction filters because it originates from the agent's trusted internal state. The paper demonstrates that forged memory entries can hijack future retrieval indefinitely, creating "zombie" agents that appear to function normally but are persistently compromised.

### 4.5 A-MemGuard

**A-MemGuard** (arXiv:2510.02373, October 2025) proposes a proactive defense framework for LLM-based agent memory, representing one of the few defensive works in this space. It monitors memory consolidation and retrieval operations to detect and neutralize injected entries before they can influence agent behavior.

---

## 5. Multi-Agent Attack Strategies

### 5.1 Control-Flow Hijacking

**"Multi-Agent Systems Execute Arbitrary Malicious Code"** (arXiv:2503.12188, March 2025) demonstrates that adversarial content can hijack control and communication within multi-agent systems to invoke unsafe agents and functionalities:

- The **Magentic-One orchestrator** executes arbitrary malicious code **97% of the time** on GPT-4o when interacting with malicious local files
- **88%** success rate on Gemini 1.5 Pro when interacting with malicious web pages
- Metadata and "confused deputy" vulnerabilities enable malicious code execution even when individual agents refuse to perform unsafe actions

**"Breaking and Fixing Defenses Against Control-Flow Hijacking in Multi-Agent Systems"** (arXiv:2510.17276, October 2025) extends this work by:
- Demonstrating that existing defenses are insufficient against sophisticated control-flow attacks
- Proposing **ControlValve**, a defense inspired by control-flow integrity (CFI) principles from systems security that generates permitted control-flow graphs and enforces compliance with contextual rules

### 5.2 Prompt Infection (LLM-to-LLM Propagation)

**"Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems"** (Lee & Tiwari, arXiv:2410.07283, October 2024) introduces the concept of self-replicating malicious prompts:

- Malicious prompts spread across interconnected agents like a computer virus
- An infected agent includes the malicious payload in its outputs to other agents, which then become infected themselves
- Threats include data theft, scams, misinformation, and system-wide disruption
- The attack exploits the fundamental trust that agents place in messages from peer agents within the same system

### 5.3 Agent-in-the-Middle (AiTM)

**"Red-Teaming LLM Multi-Agent Systems via Communication Attacks"** (He et al., arXiv:2502.14847, February 2025; ACL 2025 Findings) introduces AiTM:

- An adversarial agent intercepts and manipulates inter-agent messages, compromising entire multi-agent systems **without compromising any individual agent**
- Uses an LLM-powered adversarial agent with a reflection mechanism to generate contextually-aware malicious instructions
- The attack operates under realistic constraints: limited control over the system and role-restricted communication formats

### 5.4 Agent Collusion

**"Many-to-One Adversarial Consensus: Exposing Multi-Agent Collusion Risks in AI-Based Healthcare"** (arXiv:2512.03097, December 2025):

- Multiple adversarial assistant agents coordinate to create false consensus
- In healthcare settings, collusion can drive harmful recommendation rates up to **100%**
- Introducing a verifier agent completely blocks collusion, but only if the verifier itself is not compromised

**"A Survey of Collusion Risk in LLM-Powered Multi-Agent Systems"** (OpenReview, 2025) documents that:

- Repeated interactions cause LLM agents to move toward cooperation, even when not explicitly directed to collude
- In pricing scenarios, smart agents reliably coordinate on tacitly collusive outcomes without direct communication
- When human-like communication channels are established, agents escalate to explicit collusion

---

## 6. MCP Tool Poisoning

The Model Context Protocol (MCP) has introduced a new class of attack surfaces. As agents connect to external tool servers, each server becomes a potential attack vector.

### 6.1 Tool Description Injection

[Invariant Labs disclosed](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (April 2025) that MCP tool descriptions can contain hidden malicious instructions---often disguised as code comments invisible to users but parsed by AI models. These instructions can direct the agent to:
- Exfiltrate sensitive data (e.g., `read ~/.cursor/mcp.json`)
- Override system prompt instructions
- Execute actions the user did not authorize

**Tool poisoning attacks achieve 84.2% success rates** in controlled testing when AI agents have auto-approval enabled (as documented in "Securing the Model Context Protocol," arXiv:2512.06556).

### 6.2 Tool Shadowing

Tool shadowing occurs when a malicious MCP server registers tools with names or descriptions designed to intercept calls intended for trusted tools. When multiple servers are connected to the same agent, a malicious server can override or intercept calls to a trusted one. The agent, selecting tools based on description matching, may route sensitive operations through the adversarial server without the user's knowledge.

### 6.3 Rug Pull Attacks

MCP tools can **mutate their own definitions after installation**. The attack lifecycle:
1. **Day 1**: Attacker distributes a legitimate-looking MCP tool that passes security review
2. **Day N**: The tool's definition is remotely modified to inject malicious logic
3. The agent continues using the tool under the assumption that it remains safe

The **ETDI** (Enhanced Tool Definition Interface, arXiv:2506.01333, June 2025) proposes mitigations incorporating cryptographic identity verification, immutable versioned tool definitions, and OAuth 2.0 permission management.

### 6.4 Cross-Origin Escalation

When an agent connects to multiple MCP servers, a malicious server can escalate its privileges by:
- Shadowing tools from trusted servers to intercept sensitive data
- Injecting instructions through tool descriptions that modify the agent's behavior with respect to all connected servers
- Combining shadowing with rug pulls to hijack the agent's entire toolchain while maintaining the appearance of using only trusted tools

**"Systematic Analysis of MCP Security"** (arXiv:2508.12538) provides a comprehensive taxonomy of these attack vectors, and the **MCPTox benchmark** evaluates how often malicious tool definitions pass into AI agent contexts unchallenged.

### 6.5 Line Jumping Attacks

A malicious MCP server provides a tool description that tricks the model into executing unintended actions **before any legitimate tool is even invoked**. The tool description itself contains executable instructions that the model follows during the tool selection phase, before the tool's actual code runs.

---

## 7. Ideal Attacker Agent Design

Based on the surveyed research, the following architecture represents the current state-of-the-art for an autonomous attacker agent:

### Architecture Diagram

```
+-------------------------------------------------------------------+
|                     ATTACKER AGENT SYSTEM                         |
+-------------------------------------------------------------------+
|                                                                   |
|  +---------------------+     +------------------------------+    |
|  |   STRATEGY PLANNER  |     |      ATTACK MEMORY           |    |
|  |                     |     |  +-------------------------+  |    |
|  |  - Risk Analyzer    |<--->|  | Cross-Session Store     |  |    |
|  |  - Goal Decomposer  |     |  | - Strategy ASR History  |  |    |
|  |  - Turn Budgeter    |     |  | - Target Profiles       |  |    |
|  +--------+------------+     |  | - Failure Patterns      |  |    |
|           |                  |  +-------------------------+  |    |
|           v                  |  | Scan-Wide Memory        |  |    |
|  +---------------------+    |  | - Shared Findings        |  |    |
|  | STRATEGY SELECTOR   |    |  | - Successful Tactics     |  |    |
|  |                     |    |  +-------------------------+  |    |
|  | - MAP-Elites Grid   |    +------------------------------+    |
|  | - Performance-Based |                                         |
|  |   Ranking           |    +------------------------------+    |
|  | - Diversity Budget  |    |     RESPONSE EVALUATOR       |    |
|  +--------+------------+    |                              |    |
|           |                 |  - LLM Judge (primary)       |    |
|           v                 |  - Classifier (secondary)    |    |
|  +---------------------+   |  - Partial Success Detector  |    |
|  |  ATTACK EXECUTOR    |   |  - Refusal Classifier        |    |
|  |                     |   +----------+-------------------+    |
|  | +-------+ +-------+ |              |                         |
|  | |Persona| |Encode | |              |                         |
|  | |Module | |Module | |   +----------v-------------------+    |
|  | +-------+ +-------+ |   |    BACKTRACK CONTROLLER      |    |
|  | +-------+ +-------+ |   |                              |    |
|  | |Escala-| |Cross- | |   | - Tree Search (TAP-style)    |    |
|  | |tion   | |Domain | |   | - Branch Management          |    |
|  | |Module | |Inject | |   | - Context Reset Logic        |    |
|  | +-------+ +-------+ |   | - Strategy Pivot Trigger     |    |
|  | +-------+ +-------+ |   +------------------------------+    |
|  | |Narra- | |Memory | |                                        |
|  | |tive   | |Exploit| |   +------------------------------+    |
|  | |Frame  | |Module | |   |   LIFELONG LEARNING ENGINE   |    |
|  | +-------+ +-------+ |   |                              |    |
|  +--------+------------+   | - Research Paper Monitor      |    |
|           |                 | - New Attack Validator        |    |
|           v                 | - Attack Library Updater      |    |
|  +---------------------+   +------------------------------+    |
|  | CONVERSATION MANAGER|                                        |
|  |                     |                                        |
|  | - Turn Tracking     |                                        |
|  | - Context Compress  |                                        |
|  | - Persona Maintain  |                                        |
|  +--------+------------+                                        |
|           |                                                      |
|           v                                                      |
|  +---------------------+                                        |
|  |   TARGET INTERFACE  |-----> [TARGET AGENT / LLM]             |
|  +---------------------+                                        |
+-------------------------------------------------------------------+
```

### Decision Flow

1. **Initialization**: Receive adversarial objective. Risk Analyzer decomposes it into sub-goals. Strategy Planner queries Attack Memory for historical performance data on similar objectives.

2. **Strategy Selection**: Strategy Selector uses MAP-Elites archive to choose an attack that balances expected effectiveness (based on historical ASR) with diversity (ensuring coverage of the attack space).

3. **Execution**: Attack Executor applies the selected strategy via the appropriate module (persona, encoding, escalation, etc.). Conversation Manager maintains context and persona consistency.

4. **Evaluation**: Response Evaluator assesses the target's output. Three outcomes:
   - **Success**: Log the successful strategy and its context. Report the vulnerability.
   - **Partial Success**: Continue escalating with the current strategy, possibly combining with a complementary technique.
   - **Failure**: Pass to Backtrack Controller.

5. **Backtracking**: If the current branch has been exhausted, the Backtrack Controller either (a) pivots to a new strategy on the same conversation, (b) resets the conversation and tries a different approach, or (c) marks the objective as resistant and moves to the next one.

6. **Learning**: After each scan, results are persisted to Attack Memory. The Lifelong Learning Engine periodically checks for new published attacks and integrates validated techniques into the Attack Library.

---

## 8. Evaluation Methods

### 8.1 Attack Success Rate (ASR)

The primary metric. Calculated as the proportion of test cases where the attacker achieves its adversarial objective, as judged by a learned safety classifier, an LLM judge, or human evaluation.

Variants include:
- **ASR@k**: Success rate when the attacker is allowed k attempts per objective. GOAT reports ASR@10.
- **Weighted ASR**: Weights successes by severity of the violation (e.g., providing general harmful information vs. step-by-step operational instructions).
- **Per-Category ASR**: Broken down by harm category (violence, hate speech, illegal activity, etc.) to identify specific weaknesses.

### 8.2 Query Efficiency

How many queries (conversational turns) are required to achieve a jailbreak. Lower is better. TAP averages ~29 queries for 90% ASR on GPT-4; PAIR typically succeeds within 20 queries; GOAT within 5 turns.

### 8.3 Attack Diversity

Metrics that capture how varied the successful attacks are:
- **QD-Score** (Quality-Diversity Score): Sum of attack quality across discrete behavior cells in a MAP-Elites archive. Used by QDRT.
- **Behavior Coverage**: Percentage of behavior cells in the MAP-Elites grid that contain at least one successful attack. QDRT achieves 19.33% improvement in behavior coverage over baselines.
- **Mutation Distance**: Measures how different successful attack prompts are from each other, penalizing methods that find many attacks but all via the same technique.

### 8.4 Utility Retention

Measures whether defensive measures deployed against attacks degrade the model's performance on legitimate tasks. A defense that blocks all attacks but also refuses 30% of legitimate requests is not useful.

### 8.5 Transferability

Whether attacks discovered against one target model also work against other models. AutoRedTeamer and AgenticRed both demonstrate strong transfer, with AgenticRed achieving 100% ASR on GPT-3.5-Turbo and GPT-4o-mini using attacks evolved against open-weight models.

### 8.6 Benchmarks

| Benchmark | Focus | Scale | Reference |
|-----------|-------|-------|-----------|
| **HarmBench** | Standardized red teaming evaluation | 510 behaviors, 18 attacks, 33 targets | Mazeika et al., 2024 (ICML) |
| **JailbreakBench** | Jailbreak attack comparison | Standardized objectives + judge | Community benchmark |
| **Agent Security Bench (ASB)** | Agent-specific security | 10 scenarios, 400+ tools, 27 attack/defense methods, ~90K tests | ICLR 2025 (arXiv:2410.02644) |
| **Backbone Breaker (b3)** | Human-grounded agent security | 10 threat snapshots, 19K+ crowdsourced attacks | ICLR 2026 (arXiv:2510.22620) |
| **ART Benchmark** | Agent red teaming from competition data | Largest public red-teaming competition dataset | 2025 |

---

## 9. Cutting-Edge Papers

| # | Title | Authors | Year | Venue | Link | Key Finding |
|---|-------|---------|------|-------|------|-------------|
| 1 | Automated Red Teaming with GOAT: the Generative Offensive Agent Tester | Maya Pavlova et al. | 2024 | ICML 2025, ICLR 2025 | [arXiv:2410.01606](https://arxiv.org/abs/2410.01606) | Agent-based red teaming with 7 attack techniques achieves 97% ASR@10 on Llama 3.1 |
| 2 | Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack | Mark Russinovich, Ahmed Salem, Ronen Eldan | 2024 | USENIX Security 2025 | [arXiv:2404.01833](https://arxiv.org/abs/2404.01833) | Multi-turn escalation bypasses all major LLM safety systems |
| 3 | Tree of Attacks: Jailbreaking Black-Box LLMs Automatically | Anay Mehrotra et al. | 2023/2024 | NeurIPS 2024 | [arXiv:2312.02119](https://arxiv.org/abs/2312.02119) | Tree-search jailbreaking achieves 90% ASR on GPT-4 in ~29 queries |
| 4 | Jailbreaking Black Box Large Language Models in Twenty Queries (PAIR) | Patrick Chao et al. | 2023/2024 | -- | [arXiv:2310.08419](https://arxiv.org/abs/2310.08419) | Iterative prompt refinement jailbreaks LLMs in <20 queries |
| 5 | AutoRedTeamer: Autonomous Red Teaming with Lifelong Attack Integration | Andy Zhou, Kevin Wu et al. | 2025 | NeurIPS 2025 | [arXiv:2503.15754](https://arxiv.org/abs/2503.15754) | Dual-agent system with lifelong learning achieves 20% higher ASR at 46% lower cost |
| 6 | AgenticRed: Optimizing Agentic Systems for Automated Red-teaming | Yuan et al. | 2026 | -- | [arXiv:2601.13518](https://arxiv.org/abs/2601.13518) | Evolved red-teaming architectures achieve 96-98% ASR, 100% on GPT-3.5-Turbo |
| 7 | MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval | Saksham Sahai Srivastava, Haoyu He | 2025 | -- | [arXiv:2512.16962](https://arxiv.org/abs/2512.16962) | Poisoning agent experience memory creates persistent, stealthy compromise |
| 8 | Memory Injection Attacks on LLM Agents via Query-Only Interaction (MINJA) | -- | 2025 | -- | [arXiv:2503.03704](https://arxiv.org/abs/2503.03704) | Query-only memory injection achieves >95% success rate |
| 9 | InjecMEM: Memory Injection Attack on LLM Agent Memory Systems | -- | 2025 | OpenReview | [OpenReview](https://openreview.net/forum?id=QVX6hcJ2um) | Single-interaction memory injection steers all future responses on target topics |
| 10 | Zombie Agents: Persistent Control of Self-Evolving LLM Agents via Self-Reinforcing Injections | -- | 2026 | -- | [arXiv:2602.15654](https://arxiv.org/abs/2602.15654) | Self-reinforcing injections survive memory consolidation and persist indefinitely |
| 11 | Multi-Agent Systems Execute Arbitrary Malicious Code | -- | 2025 | -- | [arXiv:2503.12188](https://arxiv.org/abs/2503.12188) | Control-flow hijacking enables code execution in 97% of cases on GPT-4o |
| 12 | Breaking and Fixing Defenses Against Control-Flow Hijacking in Multi-Agent Systems | -- | 2025 | -- | [arXiv:2510.17276](https://arxiv.org/abs/2510.17276) | Proposes ControlValve defense based on CFI principles |
| 13 | Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems | Lee & Tiwari | 2024 | -- | [arXiv:2410.07283](https://arxiv.org/abs/2410.07283) | Self-replicating malicious prompts spread virus-like through multi-agent systems |
| 14 | Red-Teaming LLM Multi-Agent Systems via Communication Attacks (AiTM) | Pengfei He et al. | 2025 | ACL 2025 Findings | [arXiv:2502.14847](https://arxiv.org/abs/2502.14847) | Agent-in-the-Middle attack compromises entire MAS via message manipulation |
| 15 | FlipAttack: Jailbreak LLMs via Flipping | Yue Liu et al. | 2024 | ICML 2025 | [arXiv:2410.02832](https://arxiv.org/abs/2410.02832) | Character flipping achieves ~98% ASR on GPT-4o |
| 16 | Breaking Agent Backbones: Evaluating the Security of Backbone LLMs in AI Agents (b3) | Bazinska et al. | 2025 | ICLR 2026 | [arXiv:2510.22620](https://arxiv.org/abs/2510.22620) | First human-grounded agent security benchmark from 194K+ attack attempts |
| 17 | Agent Security Bench (ASB): Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents | -- | 2024 | ICLR 2025 | [arXiv:2410.02644](https://arxiv.org/abs/2410.02644) | Comprehensive agent security benchmark: 84.30% average ASR across attack types |
| 18 | HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal | Mazeika et al. | 2024 | ICML 2024 | [arXiv:2402.04249](https://arxiv.org/abs/2402.04249) | Standardized comparison of 18 attack methods across 33 targets |
| 19 | Quality-Diversity Red-Teaming (QDRT) | -- | 2025 | -- | [arXiv:2506.07121](https://arxiv.org/abs/2506.07121) | MAP-Elites-based red teaming achieves 22% QD-Score improvement |
| 20 | Securing the Model Context Protocol: Defending LLMs Against Tool Poisoning and Adversarial Attacks | -- | 2025 | -- | [arXiv:2512.06556](https://arxiv.org/abs/2512.06556) | Tool poisoning achieves 84.2% success rate; proposes defenses |
| 21 | ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP | -- | 2025 | -- | [arXiv:2506.01333](https://arxiv.org/abs/2506.01333) | Cryptographic tool definitions to prevent rug pulls |
| 22 | Many-to-One Adversarial Consensus: Exposing Multi-Agent Collusion Risks | -- | 2025 | -- | [arXiv:2512.03097](https://arxiv.org/abs/2512.03097) | Agent collusion drives harmful recommendations to 100% in healthcare settings |
| 23 | Hiding in the AI Traffic: Abusing MCP for LLM-Powered Agentic Red Teaming | -- | 2025 | -- | [arXiv:2511.15998](https://arxiv.org/abs/2511.15998) | MCP-enabled autonomous C2 architecture for agentic red teaming |
| 24 | A-MemGuard: A Proactive Defense Framework for LLM-Based Agent Memory | -- | 2025 | -- | [arXiv:2510.02373](https://arxiv.org/abs/2510.02373) | Defensive framework against memory injection attacks |
| 25 | Memory Poisoning Attack and Defense on Memory Based LLM-Agents | -- | 2026 | -- | [arXiv:2601.05504](https://arxiv.org/abs/2601.05504) | Systematic study of memory poisoning with attack/defense pair |

---

## 10. Cutting-Edge Repos

| # | Repository | Description | URL |
|---|-----------|-------------|-----|
| 1 | **Azure/PyRIT** | Microsoft's Python Risk Identification Tool for generative AI. Open-source framework with multi-turn orchestrators, converters, scorers, and memory. v0.11.0. | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) |
| 2 | **promptfoo/promptfoo** | Open-source CLI/library for LLM evaluation and red teaming. Features Meta-Agent, Hydra, GOAT strategies, MCP testing, and agent tracing. | [github.com/promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) |
| 3 | **Giskard-AI/giskard-oss** | Open-source evaluation and testing library for LLM agents. Autonomous red teaming agents with 40+ probes covering security and business failures. | [github.com/Giskard-AI/giskard-oss](https://github.com/Giskard-AI/giskard-oss) |
| 4 | **confident-ai/deepteam** | Open-source LLM red teaming framework by Confident AI (YC W25). 20+ attack methods, 50+ vulnerability types, agentic red teaming. | [github.com/confident-ai/deepteam](https://github.com/confident-ai/deepteam) |
| 5 | **centerforaisafety/HarmBench** | Standardized evaluation framework for automated red teaming. 510 behaviors, 18 attack methods, 33 target models. ICML 2024. | [github.com/centerforaisafety/HarmBench](https://github.com/centerforaisafety/HarmBench) |
| 6 | **agiresearch/ASB** | Agent Security Bench. 10 scenarios, 400+ tools, 27 attack/defense methods, ~90K test cases. ICLR 2025. | [github.com/agiresearch/ASB](https://github.com/agiresearch/ASB) |
| 7 | **RICommunity/TAP** | Official implementation of Tree of Attacks with Pruning (TAP). Automated jailbreaking via tree-search. NeurIPS 2024. | [github.com/RICommunity/TAP](https://github.com/RICommunity/TAP) |
| 8 | **patrickrchao/JailbreakingLLMs** | Official implementation of PAIR (Prompt Automatic Iterative Refinement). Jailbreaking in <20 queries. | [github.com/patrickrchao/JailbreakingLLMs](https://github.com/patrickrchao/JailbreakingLLMs) |
| 9 | **yueliu1999/FlipAttack** | Official implementation of FlipAttack (ICML 2025). Character-flipping jailbreaks with ~98% ASR on GPT-4o. | [github.com/yueliu1999/FlipAttack](https://github.com/yueliu1999/FlipAttack) |
| 10 | **microsoft/AI-Red-Teaming-Playground-Labs** | Microsoft's AI Red Teaming playground labs with infrastructure for hands-on training. | [github.com/microsoft/AI-Red-Teaming-Playground-Labs](https://github.com/microsoft/AI-Red-Teaming-Playground-Labs) |

---

## References

- Bazinska, J., Mathys, M., Casucci, F., Rojas-Carulla, M., Davies, X., Souly, A., & Pfister, N. (2025). Breaking Agent Backbones: Evaluating the Security of Backbone LLMs in AI Agents. ICLR 2026. arXiv:2510.22620.
- Chao, P. et al. (2024). Jailbreaking Black Box Large Language Models in Twenty Queries. arXiv:2310.08419.
- He, P., Lin, Y., Dong, S., Xu, H., Xing, Y., & Liu, H. (2025). Red-Teaming LLM Multi-Agent Systems via Communication Attacks. ACL 2025 Findings. arXiv:2502.14847.
- Lee & Tiwari (2024). Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems. arXiv:2410.07283.
- Liu, Y. et al. (2024). FlipAttack: Jailbreak LLMs via Flipping. ICML 2025. arXiv:2410.02832.
- Mazeika, M. et al. (2024). HarmBench: A Standardized Evaluation Framework for Automated Red Teaming and Robust Refusal. ICML 2024. arXiv:2402.04249.
- Mehrotra, A. et al. (2024). Tree of Attacks: Jailbreaking Black-Box LLMs Automatically. NeurIPS 2024. arXiv:2312.02119.
- Pavlova, M. et al. (2024). Automated Red Teaming with GOAT: the Generative Offensive Agent Tester. ICML 2025. arXiv:2410.01606.
- Russinovich, M., Salem, A., & Eldan, R. (2024). Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack. USENIX Security 2025. arXiv:2404.01833.
- Srivastava, S.S. & He, H. (2025). MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval. arXiv:2512.16962.
- Yuan et al. (2026). AgenticRed: Optimizing Agentic Systems for Automated Red-teaming. arXiv:2601.13518.
- Zhou, A., Wu, K., Pinto, F., Chen, Z., Zeng, Y., Yang, Y., Yang, S., Koyejo, O., Zou, J., & Li, B. (2025). AutoRedTeamer: Autonomous Red Teaming with Lifelong Attack Integration. NeurIPS 2025. arXiv:2503.15754.
