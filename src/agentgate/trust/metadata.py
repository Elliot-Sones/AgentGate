from __future__ import annotations

from agentgate.trust.context import TrustScanContext

_LISTING_KEYS = {
    "submission_id",
    "agent_name",
    "version",
    "entrypoint",
    "description",
    "solution_category",
    "business_use_case",
    "declared_tools",
    "declared_external_domains",
    "permissions",
    "customer_data_access",
    "integrations",
    "business_claims",
    "dependencies",
}


def build_submission_profile(ctx: TrustScanContext) -> dict[str, object]:
    if not isinstance(ctx.manifest, dict):
        return {}

    profile: dict[str, object] = {}
    for key in _LISTING_KEYS:
        value = ctx.manifest.get(key)
        if value in (None, "", []):
            continue
        profile[key] = value
    return profile


def build_runtime_summary(ctx: TrustScanContext) -> dict[str, object]:
    observed_destinations: set[str] = set()
    observed_tools: set[str] = set()
    observed_internal_destinations: set[str] = set()
    dependency_services: set[str] = set()

    for trace in ctx.runtime_traces.values():
        observed_destinations.update(trace.network_destinations)
        observed_tools.update(trace.tool_calls)
        observed_internal_destinations.update(trace.internal_network_destinations)
        dependency_services.update(trace.dependency_services)

    summary = {
        "observed_external_destinations": sorted(observed_destinations),
        "observed_internal_destinations": sorted(observed_internal_destinations),
        "observed_tools": sorted(observed_tools),
        "dependency_services": sorted(dependency_services),
        "dependency_inference_notes": list(ctx.config.dependency_inference_notes),
    }
    if ctx.hosted_runtime_context:
        summary["hosted_runtime_context"] = dict(ctx.hosted_runtime_context)
    return summary
