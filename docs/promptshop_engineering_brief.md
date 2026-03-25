# PromptShop Engineering Brief

## What AgentGate already demonstrates well

The current implementation has a strong trust-model core that maps cleanly to a
marketplace review system:

- static manifest and code inspection
- hosted runtime execution against the deployed agent endpoint
- deployment-context-aware behavior checks
- canary token seeding for secret exposure detection
- simple verdict policy for publish / hold / block decisions

## Why this is technically interesting for PromptShop

The most compelling idea is not "AI red teaming" in the abstract. It is the
declared-versus-observed trust model:

- the seller declares tools, domains, and intended behavior
- AgentGate inspects the submission and probes the hosted deployment
- the report explains where reality diverges from the listing narrative

That is a natural fit for a curated marketplace.

## Suggested integration model

1. Seller uploads source, hosted endpoint, and trust manifest.
2. PromptShop triggers `agentgate trust-scan`.
3. The resulting JSON is stored as a review artifact.
4. `ALLOW_CLEAN` and `ALLOW_WITH_WARNINGS` can route differently from
   `MANUAL_REVIEW` and `BLOCK`.
5. A trimmed summary powers listing trust metadata after approval.

## Current demo-specific additions

This PromptShop-oriented version adds:

- `--report-profile promptshop`
- optional manifest metadata for marketplace presentation
- reviewer-friendly HTML summaries
- listing-style trust summaries in JSON output

## Engineering talking points

- The trust report is deterministic and machine-readable.
- The HTML output is self-contained and easy to attach to review flows.
- The CLI already supports CI/CD and can be used as a publish gate.
- The current limitations are explicit, which makes the project feel honest and
  production-minded rather than overclaimed.

## Reasonable future work

- richer provenance and signature enforcement
- stronger continuous network tracing
- dedicated reviewer dashboard service
- seller-facing submission API
- explicit listing trust badges backed by stored scan results
