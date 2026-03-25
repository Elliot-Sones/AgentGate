# PromptShop Demo Flow

This demo repackages AgentGate as a marketplace trust workflow for PromptShop.

## Recommended walkthrough

1. Build the three demo images with `./run_demo.sh` or your own Docker commands.
2. Run `./run_promptshop_demo.sh`.
3. Open each generated `trust_scan_report.html`.
4. Narrate the flow as:
   - seller submits a solution
   - AgentGate verifies declared behavior
   - reviewer gets a publish recommendation
   - buyer-facing trust signals can be derived from the same report

## Suggested talk track

- Clean support listing: should read like a publishable PromptShop submission.
- Trojanized listing: should show why a reviewer would stop publication.
- Stealth listing: demonstrates why log-only scanning is not enough for a curated marketplace.
