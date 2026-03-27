"""OWASP LLM Top 10 (2025) coverage mapping for AgentGate.

Each OWASPMapping entry reflects what AgentGate genuinely covers today.
Coverage levels:
  full    — the category is substantively addressed end-to-end
  partial — meaningful coverage exists but important sub-areas are missing
  minimal — a single narrow check touches the category
  none    — no current coverage
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OWASPMapping:
    """Maps one OWASP LLM Top 10 category to AgentGate components."""

    owasp_id: str
    name: str
    coverage_level: str  # "full" | "partial" | "minimal" | "none"
    components: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def get_owasp_coverage() -> list[OWASPMapping]:
    """Return the full OWASP LLM Top 10 (2025) coverage mapping."""
    return [
        OWASPMapping(
            owasp_id="LLM01",
            name="Prompt Injection",
            coverage_level="partial",
            components=[
                "prompt_injection",   # security scan: DAN jailbreaks, role-play, instruction
                                      # override, indirect injection, multi-turn erosion
                "xpia",               # security scan: cross-domain prompt injection (document,
                                      # code, URL injection)
                "goal_hijacking",     # security scan: direct & indirect goal redirection
                "static_prompt_tool_inspection",  # trust scan: scans source for override phrases
                                                  # and hidden instruction tokens
                "data_boundary",      # adaptive specialist: probes for cross-tenant and system
                                      # prompt disclosure
            ],
            gaps=[
                "Evaluation relies on heuristic keyword matching; adversarial injections that "
                "avoid known compliance keywords may go undetected.",
                "No multi-modal (image, audio) injection coverage.",
                "Indirect injection via tool return values (e.g., a poisoned database row) is "
                "not directly simulated — XPIA covers documents and code but not arbitrary "
                "tool output.",
                "No coverage of agentic re-injection between orchestrator and sub-agent calls.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM02",
            name="Sensitive Information Disclosure",
            coverage_level="partial",
            components=[
                "data_exfiltration",   # security scan: PII probing, credential probing, scope
                                       # violation payloads; regex detection of leaked patterns
                "runtime_canary",      # trust scan: detects canary token leakage in runtime logs
                                       # and network traffic
                "canary_stresser",     # adaptive specialist: social-engineers agent into
                                       # disclosing env vars and secrets
                "data_boundary",       # adaptive specialist: probes cross-tenant data access and
                                       # env variable exposure
                "runtime_egress",      # trust scan: flags undeclared outbound destinations that
                                       # may indicate data transmission
            ],
            gaps=[
                "Detection is output-pattern-based; indirect disclosure (e.g. timing oracles, "
                "differential responses) is not covered.",
                "No coverage of model memorisation / training data extraction attacks.",
                "Canary detection requires seeding canary tokens; agents not exercised through "
                "runtime checks receive no canary coverage.",
                "No structured privacy-classification enforcement (e.g., GDPR data categories).",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM03",
            name="Supply Chain Vulnerabilities",
            coverage_level="partial",
            components=[
                "static_dependency_risk",  # trust scan: typosquat detection, lockfile presence
                                           # check, optional trivy/grype/pip-audit hooks
                "static_provenance",       # trust scan: cosign container image signature
                                           # verification, immutable digest enforcement
                "static_code_signals",     # trust scan: detects dynamic exec/eval, shell=True,
                                           # outbound HTTP calls in source
            ],
            gaps=[
                "Typosquat list is small and static; it does not integrate a live CVE or "
                "malicious-package feed (e.g., OSV, Snyk, Socket).",
                "Deep SBOM analysis (syft/grype) is optional and skipped when tools are absent "
                "from PATH.",
                "No coverage of compromised base images beyond cosign signature verification.",
                "Model supply chain (fine-tuned or third-party model weights) is not assessed.",
                "No software composition analysis of JavaScript / non-Python dependencies.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM04",
            name="Data and Model Poisoning",
            coverage_level="minimal",
            components=[
                "static_prompt_tool_inspection",  # trust scan: detects hardcoded adversarial
                                                  # instructions or exfil directives in source
                "static_code_signals",            # trust scan: flags suspicious patterns that
                                                  # could indicate training-time tampering hooks
            ],
            gaps=[
                "No runtime detection of poisoned outputs from fine-tuned or RAG-backed models.",
                "No benchmark comparison to a known-clean model baseline.",
                "No coverage of indirect poisoning through retrieval corpora or vector stores.",
                "Static checks only scan Python source; prompt templates loaded at runtime from "
                "external stores are not inspected.",
                "No adversarial example testing targeting model decision boundaries.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM05",
            name="Improper Output Handling",
            coverage_level="partial",
            components=[
                "input_validation",   # security scan: XSS reflection detection, SQL error
                                      # indicators in output, crash-resistance for null bytes /
                                      # Unicode / empty inputs
                "data_exfiltration",  # security scan: detects PII and credential patterns in
                                      # responses
                "tool_misuse",        # security scan: checks for instructional patterns in
                                      # responses to dangerous tool-use requests
            ],
            gaps=[
                "XSS detection checks for reflected patterns in the agent's text response; "
                "downstream rendering context (HTML, Markdown, PDF) is not evaluated.",
                "No coverage of SSRF triggered by agent-generated URLs passed to downstream "
                "services.",
                "No structured output schema validation; agents may produce malformed JSON "
                "that breaks callers.",
                "Command injection in agent-generated shell arguments is not tested.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM06",
            name="Excessive Agency",
            coverage_level="partial",
            components=[
                "tool_misuse",              # security scan: read-to-write escalation, destructive
                                            # operations, scope widening, tool chaining
                "runtime_tool_audit",       # trust scan: compares observed tool calls against
                                            # manifest declarations at runtime
                "tool_exerciser",           # adaptive specialist: exercises declared tools,
                                            # flags unexpected invocations and over-triggering
                "static_prompt_tool_inspection",  # trust scan: inspects hardcoded tool
                                                  # definitions for overly broad permissions
            ],
            gaps=[
                "Tool misuse detector relies on heuristic response keywords; it does not "
                "observe actual tool invocation traces.",
                "No coverage of autonomous multi-step planning that accumulates excessive "
                "permissions across tool calls.",
                "Scope widening and privilege escalation checks are prompt-response only; "
                "no live tool execution sandbox is used.",
                "No coverage of agentic workflows where one sub-agent grants another "
                "elevated permissions.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM07",
            name="System Prompt Leakage",
            coverage_level="partial",
            components=[
                "system_prompt_leak",  # security scan: direct/indirect prompt extraction,
                                       # context-reset attacks; heuristic detection of leaked
                                       # system prompt content
                "data_boundary",       # adaptive specialist: probes for system prompt and
                                       # internal instruction disclosure
                "runtime_canary",      # trust scan: canary tokens seeded in system context
                                       # catch exfiltration through logs or network
            ],
            gaps=[
                "Detection is heuristic; system prompts that are paraphrased rather than "
                "quoted verbatim may not be detected.",
                "No coverage of side-channel leakage (e.g., token-count timing attacks).",
                "Canary-based detection requires canary tokens to actually be placed in the "
                "system prompt; this is not enforced automatically.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM08",
            name="Vector and Embedding Weaknesses",
            coverage_level="none",
            components=[],
            gaps=[
                "No coverage of embedding inversion attacks or nearest-neighbour probing.",
                "No RAG poisoning detection (injecting adversarial documents into vector stores).",
                "No coverage of cross-user data leakage through shared embedding caches.",
                "No semantic similarity threshold analysis for retrieval quality.",
                "This category requires direct access to the embedding pipeline and vector "
                "store, which AgentGate does not currently model.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM09",
            name="Misinformation",
            coverage_level="partial",
            components=[
                "hallucination",  # security scan: known-answer queries, nonexistent entity
                                  # probes, fabricated citation/URL/DOI detection
            ],
            gaps=[
                "Coverage is limited to a small curated probe set; factual accuracy across "
                "an agent's full knowledge domain is not evaluated.",
                "Evaluation is heuristic (keyword-based uncertainty indicators); nuanced "
                "confident-but-wrong responses may pass.",
                "No retrieval-augmented grounding check — agents that cite real URLs may still "
                "misrepresent the content.",
                "No automated ground-truth verification against authoritative knowledge bases.",
                "Overconfidence scoring (calibration) is not measured.",
            ],
        ),
        OWASPMapping(
            owasp_id="LLM10",
            name="Unbounded Consumption",
            coverage_level="minimal",
            components=[
                "runtime_egress",       # trust scan: flags unexpected outbound connections that
                                        # may indicate resource-abuse (e.g., cryptomining egress)
                "runtime_behavior_diff",  # trust scan: detects profile-dependent spikes in tool
                                          # invocations or network calls
            ],
            gaps=[
                "No token consumption monitoring or per-request cost budgeting.",
                "No denial-of-service / resource exhaustion testing (recursive calls, large "
                "context injection, infinite loops).",
                "No rate-limit bypass detection.",
                "Egress monitoring detects unexpected destinations but not volumetric abuse.",
                "No coverage of model-as-a-service billing abuse patterns.",
            ],
        ),
    ]


def owasp_coverage_summary() -> dict:
    """Return a summary dict of OWASP LLM Top 10 coverage.

    Keys:
      covered_count  — number of categories with 'full' or 'partial' coverage
      total          — always 10
      coverage_level — highest aggregate descriptor ('partial' unless all are 'full')
      categories     — list of per-category dicts
    """
    mappings = get_owasp_coverage()
    covered = [m for m in mappings if m.coverage_level in {"full", "partial"}]
    all_full = all(m.coverage_level == "full" for m in mappings)
    any_covered = bool(covered)

    if all_full:
        aggregate_level = "full"
    elif any_covered:
        aggregate_level = "partial"
    elif any(m.coverage_level == "minimal" for m in mappings):
        aggregate_level = "minimal"
    else:
        aggregate_level = "none"

    categories = [
        {
            "id": m.owasp_id,
            "name": m.name,
            "level": m.coverage_level,
            "components": m.components,
            "gaps": m.gaps,
        }
        for m in mappings
    ]

    return {
        "covered_count": len(covered),
        "total": 10,
        "coverage_level": aggregate_level,
        "categories": categories,
    }
