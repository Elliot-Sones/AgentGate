# OWASP LLM Top 10 (2025) Coverage

This document shows how AgentGate's three scanning systems map to the OWASP LLM Top 10 (2025).
Coverage levels are conservative and reflect what the code actually does today.

**Coverage levels**

| Level | Meaning |
|-------|---------|
| `full` | Substantively addresses the category end-to-end |
| `partial` | Meaningful coverage exists but important sub-areas are missing |
| `minimal` | A single narrow check touches the category |
| `none` | No current coverage |

---

## Summary

7 of 10 categories have partial or better coverage. No category is rated `full` — there are
honest gaps in each area. Two categories (LLM04, LLM10) are `minimal`, and one (LLM08) has
no coverage.

---

## Mapping table

| ID | Category | Level | AgentGate Components | Key Gaps |
|----|----------|-------|----------------------|----------|
| LLM01 | Prompt Injection | partial | `prompt_injection`, `xpia`, `goal_hijacking`, `static_prompt_tool_inspection`, `data_boundary` | Heuristic keyword evaluation; no multi-modal injection; indirect injection via tool return values not simulated; no cross-agent re-injection coverage |
| LLM02 | Sensitive Information Disclosure | partial | `data_exfiltration`, `runtime_canary`, `canary_stresser`, `data_boundary`, `runtime_egress` | Output-pattern detection only; no model memorisation / training data extraction; no privacy classification enforcement |
| LLM03 | Supply Chain Vulnerabilities | partial | `static_dependency_risk`, `static_provenance`, `static_code_signals` | Typosquat list is small and static; deep SBOM tools are optional; no model-weight supply chain coverage; Python-only |
| LLM04 | Data and Model Poisoning | minimal | `static_prompt_tool_inspection`, `static_code_signals` | No runtime poisoning detection; no clean-baseline comparison; no retrieval corpus or vector-store coverage |
| LLM05 | Improper Output Handling | partial | `input_validation`, `data_exfiltration`, `tool_misuse` | XSS detection covers text output only; no SSRF via agent-generated URLs; no structured output schema validation |
| LLM06 | Excessive Agency | partial | `tool_misuse`, `runtime_tool_audit`, `tool_exerciser`, `static_prompt_tool_inspection` | Tool misuse uses heuristic response keywords, not live tool traces; no multi-step autonomous planning coverage |
| LLM07 | System Prompt Leakage | partial | `system_prompt_leak`, `data_boundary`, `runtime_canary` | Paraphrased leakage not detected; no timing side-channel coverage; canary seeding not automatically enforced |
| LLM08 | Vector and Embedding Weaknesses | none | *(none)* | Requires direct pipeline and vector-store access; no embedding inversion, RAG poisoning, or cross-user leakage detection |
| LLM09 | Misinformation | partial | `hallucination` | Small probe set; heuristic uncertainty detection; no ground-truth verification; no calibration scoring |
| LLM10 | Unbounded Consumption | minimal | `runtime_egress`, `runtime_behavior_diff` | No token consumption monitoring; no DoS/resource exhaustion testing; no rate-limit bypass detection |

---

## Component reference

### Security scan detectors (`src/agentgate/detectors/`)

| Component ID | What it does |
|---|---|
| `prompt_injection` | Tests DAN jailbreaks, role-play injections, instruction overrides, indirect injection, and multi-turn erosion attacks |
| `xpia` | Tests cross-domain prompt injection hidden in documents, code comments, and URL parameters |
| `goal_hijacking` | Tests direct, indirect, and multi-turn attempts to redirect the agent from its stated purpose |
| `system_prompt_leak` | Tests direct and indirect attempts to extract the system prompt, including context-reset attacks |
| `data_exfiltration` | Tests PII probing, credential probing, and scope violation; regex-scans responses for leaked patterns |
| `hallucination` | Tests known-answer accuracy, nonexistent entity confabulation, and fabricated citation/URL generation |
| `input_validation` | Tests null bytes, Unicode edge cases, empty inputs, XSS reflection, and SQL injection indicators |
| `tool_misuse` | Tests read-to-write escalation, destructive operations, scope widening, and dangerous tool chaining |

### Trust scan checks (`src/agentgate/trust/checks/`)

| Component ID | What it does |
|---|---|
| `static_manifest` | Validates trust manifest structure and required fields |
| `static_dependency_risk` | Typosquat detection; lockfile presence; optional pip-audit/trivy/grype hooks |
| `static_provenance` | cosign container image signature verification; immutable digest enforcement |
| `static_code_signals` | Detects dynamic exec/eval, `shell=True`, outbound HTTP calls in Python source |
| `static_prompt_tool_inspection` | Scans source for hidden instruction tokens, override phrases, and exfil directives |
| `runtime_egress` | Compares observed network destinations against declared domains; flags undeclared egress |
| `runtime_canary` | Checks runtime logs and traffic for seeded canary token values |
| `runtime_tool_audit` | Compares observed runtime tool calls against manifest declarations |
| `runtime_behavior_diff` | Detects network and tool-call differences between review and production-like profiles |
| `runtime_hosted` | Drives the hosted runtime runner and surfaces adaptive specialist findings |

### Adaptive specialists (`src/agentgate/trust/runtime/adaptive/specialists/`)

| Component ID | What it does |
|---|---|
| `tool_exerciser` | Exercises declared tools with realistic queries; flags unexpected invocations and data leakage |
| `egress_prober` | Social-engineers the agent into making external HTTP calls; detects undeclared egress and SSRF |
| `data_boundary` | Probes cross-tenant access, system prompt disclosure, and environment variable exposure |
| `canary_stresser` | Attempts to socially engineer the agent into revealing canary token values and secrets |
| `behavior_consistency` | Sends paired review-vs-production queries and flags behavioural inconsistencies |

---

## Programmatic access

```python
from agentgate.trust.owasp_mapping import get_owasp_coverage, owasp_coverage_summary

# Full structured list
for mapping in get_owasp_coverage():
    print(mapping.owasp_id, mapping.coverage_level, mapping.components)

# Summary dict
summary = owasp_coverage_summary()
print(summary["covered_count"], "/", summary["total"])
```

The summary is also embedded in every trust scan result under `metadata["owasp_coverage"]`.

To print the table from the CLI:

```
agentgate owasp-coverage
```
