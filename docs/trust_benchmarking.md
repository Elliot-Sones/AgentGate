# Trust Benchmarking

This repository now includes a small, reproducible trust benchmark harness for
showing how AgentGate performs on a marketplace-style seller corpus.

## What it measures

The benchmark compares two scenarios:

- `full`: full trust scan with static and runtime checks
- `static_only`: baseline that only runs static manifest/code checks

For each scenario, the harness reports:

- malicious detection rate
- clean auto-approve rate
- clean escalation count
- average scan time
- per-case verdicts

This is intentionally simple and founder-friendly. It gives you a defensible
benchmark story without pretending the project already has a massive public
evaluation corpus.

## Corpus

The default suite lives at
[`benchmarks/promptshop_demo_suite.yaml`](/Users/elliot18/Desktop/Home/Projects/AgentGate/benchmarks/promptshop_demo_suite.yaml)
and uses the PromptShop-style demo agents:

- clean support listing
- trojanized support listing
- stealth exfiltration listing

## Run it

```bash
PYTHONPATH=src python3 scripts/benchmark_trust_scan.py --build-images
```

Outputs are written to:

```bash
benchmark_output/trust/
```

Key files:

- `benchmark_summary.md`
- `benchmark_summary.json`
- per-scenario `trust_scan_report.json` artifacts for each case

## How to talk about it

The strongest presentation framing is:

"We benchmark AgentGate against a weaker static-only baseline. The benchmark
shows how much detection value comes from runtime detonation, egress telemetry,
and declared-vs-observed validation."

If the results come out as expected, the story should be:

- `full` catches both malicious listings
- `static_only` misses the stealth runtime case
- clean listings remain publishable

The benchmark suite also includes a harder `runtime_only_stealth_listing`
case intended to minimize static red flags while still triggering a runtime
block through undeclared egress.

That makes the benchmark directly relevant to a curated marketplace like
PromptShop.
