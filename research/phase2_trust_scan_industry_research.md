# Phase 2 Trust Scan Research (Marketplace Malware Analysis)

## Why Phase 2 Exists
Phase 1 (`agentgate scan`) answers: "Can a user break this agent?"

Phase 2 answers a different marketplace question: "Is this submitted agent trustworthy at all?"

For Prompt Shop, the submitter can be adversarial. The trust problem includes hidden exfiltration logic, delayed triggers, poisoned MCP tool descriptions, environment-aware behavior, and compromised dependencies.

## Industry Standards (Primary Sources)
The baseline control stack for a production marketplace should align to:

- NIST AI RMF 1.0 and the NIST GenAI profile (AI 600-1) for governance and risk treatment.
- NIST SP 800-218A (GenAI SSDF profile) for secure development lifecycle controls.
- OWASP Top 10 for LLM Applications and OWASP Top 10 for Agentic AI Applications for threat taxonomy coverage.
- SLSA + in-toto + Sigstore cosign for software supply-chain provenance and artifact verification.
- MCP security best practices for tool/server integration boundaries and least privilege.

Industry trend: teams do not rely on prompt-level controls alone. They combine policy/governance, supply-chain verification, and runtime behavior monitoring.

## What Leading Repos and Tools Actually Do
### Agent-specific evaluation frameworks
- AgentDojo provides realistic task/attack benchmarks and reports both utility and attack success metrics.
- PyRIT focuses on orchestrated, adaptive red teaming (multi-turn, objective-driven attacks).
- Promptfoo emphasizes policy plugins (`bola`, `bfla`, `ssrf`, `mcp`) and deterministic security controls around agents.
- Giskard organizes detector-style LLM/agent vulnerability scans.

### Supply chain and malware-adjacent scanning
- GuardDog focuses on malicious package/repo heuristics and SARIF output.
- Trivy and Grype scan vulnerabilities/misconfigurations; Syft generates SBOMs.
- Falco focuses on runtime syscall/process/network anomaly detection.

Practical takeaway: cutting-edge teams use layered controls, not one giant model-based detector.

## Marketplace Operations Patterns
From major marketplaces and security policies, recurring patterns are:

- Automated review + manual review queue for high-risk findings.
- Re-review cadence after listing (not one-time approval only).
- Stronger scrutiny for privileged permissions and networked integrations.
- Incident response expectations with fast notification timelines.

This matches a trust-gate model better than a one-shot benchmark model.

## Lean Architecture for Prompt Shop (Avoid Overengineering)
### Implement now (MVP controls)
1. Submission intake
- Require source bundle + lockfiles + build artifact (container image).
- Record hashes and submission metadata for reproducibility.

2. Static trust checks
- Prompt/system/tool description inspection for hidden instruction patterns.
- Dependency/SBOM/provenance checks (Syft + Trivy/OSV/pip-audit + cosign verification).
- Heuristic code checks for exfil paths (`requests` to unknown hosts, dynamic exec, shell construction).

3. Dynamic detonation checks
- Run in isolated sandbox with default-deny egress and explicit allowlist.
- Capture network destinations, process tree, and tool-call traces.
- Plant canary secrets/data and detect access/transmission.
- Compare declared tool behavior vs observed side effects.

4. Decision engine
- Verdicts: `allow`, `manual_review`, `block`.
- Critical auto-block signals: canary exfil, undeclared outbound egress, provenance/signature failure.

5. Reporting and evidence
- Emit JSON/HTML/SARIF trust reports with evidence artifacts and reviewer notes.
- Keep replay bundles for appeals/forensics.

### Defer to later (to prevent overengineering)
- Full custom microVM orchestration platform from day one.
- ML-based anomaly scoring as a first-line gate.
- Large autonomous "malware analyst agent" before deterministic controls are stable.
- Complex behavioral fingerprinting beyond basic environment-diff checks.

## Recommended 90-Day Rollout
### Weeks 1-3: Foundation
- Add `trust-scan` mode/command in current `agentgate` codebase.
- Ship static checks and supply-chain verification.
- Output structured findings with severity and evidence.

### Weeks 4-7: Runtime trust checks
- Add sandbox runner with egress policy controls.
- Add canary token framework and exfil detection.
- Add tool-call auditing and declared-vs-observed mismatch findings.

### Weeks 8-10: Marketplace integration
- Integrate with review workflow: advisory mode first.
- Auto-route high-risk submissions to manual review.
- Establish evidence retention and appeal path.

### Weeks 11-13: Enforcement calibration
- Tune false positives with historical submissions.
- Move to staged enforcement: block on critical findings; review on high.
- Publish clear developer-facing trust requirements.

## Integration Guidance for Current AgentGate
To minimize rework, build Phase 2 as a sibling pipeline rather than a rewrite:

- Keep Phase 1 detectors for user-facing robustness.
- Add Phase 2 "trust detectors" for malicious submitter behavior.
- Reuse existing scanner orchestration, scoring, and reporting surfaces where possible.
- Keep policies explicit and deterministic before introducing LLM-judge behavior in trust gating.

This keeps implementation incremental and avoids breaking existing scans.

## Verification Notes
- The Amazon Q VS Code extension compromise bulletin is a verified primary source from AWS.
- VirusTotal's MCP repository analysis (June 4, 2025) is a verified primary source.
- The specific "12% ClawHub malicious" claim was not confirmed from a primary source in this research set and should not be used as a hard statistic without citation.

## Verified Sources
- NIST AI RMF 1.0: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10
- NIST AI RMF GenAI Profile (AI 600-1): https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- NIST SP 800-218A: https://csrc.nist.gov/pubs/sp/800/218/a/ipd
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Agentic Top 10 (2026): https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- MCP security best practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- Anthropic MCP directory policy: https://support.anthropic.com/en/articles/11697096-anthropic-mcp-directory-policy
- AgentDojo repository: https://github.com/ethz-spylab/agentdojo
- AgentDojo benchmark results: https://agentdojo.spylab.ai/results/
- PyRIT docs: https://azure.github.io/PyRIT/
- Promptfoo agent red teaming docs: https://www.promptfoo.dev/docs/red-team/agents/
- Promptfoo MCP plugin docs: https://www.promptfoo.dev/docs/red-team/plugins/mcp/
- Giskard LLM detector reference: https://docs.giskard.ai/oss/sdk/reference/scan/llm_detectors.html
- GuardDog repository: https://github.com/DataDog/guarddog
- Syft SBOM tool: https://github.com/anchore/syft
- Trivy scanner docs: https://trivy.dev/docs/
- Grype scanner: https://github.com/anchore/grype
- Falco docs: https://falco.org/docs/
- Sigstore cosign signing: https://docs.sigstore.dev/cosign/signing/signing_with_containers/
- Sigstore cosign verify: https://docs.sigstore.dev/cosign/verifying/verify/
- in-toto framework: https://github.com/in-toto/in-toto
- SLSA build requirements: https://slsa.dev/spec/v1.2/build-requirements
- OpenSSF Scorecard: https://scorecard.dev/
- Kubernetes NetworkPolicy: https://v1-33.docs.kubernetes.io/docs/concepts/services-networking/network-policies/
- Cilium egress gateway: https://docs.cilium.io/en/latest/network/egress-gateway/egress-gateway/
- Canarytokens AWS key token: https://docs.canarytokens.org/guide/aws-keys-token.html
- AWS security bulletin (Amazon Q extension): https://aws.amazon.com/security/security-bulletins/AWS-2025-015/
- VirusTotal MCP analysis (June 4, 2025): https://blog.virustotal.com/2025/06/what-17845-github-repos-taught-us-about.html
