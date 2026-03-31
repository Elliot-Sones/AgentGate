from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.destination_taxonomy import build_telemetry_registry, classify_destination
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.normalizer import normalize_finding
from agentgate.trust.signals import TrustSignal


class RuntimeEgressCheck(BaseTrustCheck):
    check_id = "runtime_egress"
    description = "Checks observed network destinations against declared domains and allowlists."

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        if not ctx.runtime_traces:
            return [
                self.finding(
                    title="No runtime traces available for egress analysis",
                    category=TrustCategory.EGRESS,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Runtime egress check requires hosted runtime traces.",
                    recommendation="Run the hosted runtime check against a live deployed agent URL.",
                )
            ]

        declared = set()
        if ctx.manifest and isinstance(ctx.manifest.get("declared_external_domains"), list):
            declared = {str(v).lower() for v in ctx.manifest["declared_external_domains"]}
        allowlist = {d.lower() for d in ctx.config.egress_allowlist}
        telemetry_registry = _build_telemetry_registry(ctx)
        verified_internal_ips, verified_internal_domains = _build_verified_internal_destinations(
            ctx
        )

        all_allowed = {v.strip().lower() for v in (declared | allowlist) if str(v).strip()}
        allowed_domains, allowed_ip_literals, allowed_ip_networks = _split_allow_targets(
            all_allowed
        )
        violations: list[TrustFinding] = []
        low_confidence_profiles: list[str] = []
        resolved_allowed_domain_ips: set[str] | None = None

        def get_resolved_allowed_domain_ips() -> set[str]:
            nonlocal resolved_allowed_domain_ips
            if resolved_allowed_domain_ips is None:
                resolved_allowed_domain_ips = set()
                for domain in allowed_domains:
                    resolved_allowed_domain_ips.update(_resolve_domain_ips(domain))
            return resolved_allowed_domain_ips

        for profile, trace in ctx.runtime_traces.items():
            if (
                trace.network_destinations
                and not trace.network_destinations_procfs
                and trace.inspect_network_mode
                and trace.inspect_network_mode != "none"
            ):
                low_confidence_profiles.append(profile)

            profile_allowed_log_ips: set[str] = set()
            for observed in trace.network_destinations_logs:
                if _is_allowed_domain(observed, allowed_domains):
                    profile_allowed_log_ips.update(_resolve_domain_ips(observed))

            for dest in trace.network_destinations:
                if _is_allowed_domain(dest, allowed_domains):
                    continue
                if _is_local_destination(dest):
                    continue
                if _is_allowed_ip_destination(
                    dest=dest,
                    allowed_ip_literals=allowed_ip_literals,
                    allowed_ip_networks=allowed_ip_networks,
                    resolved_allowed_domain_ips=get_resolved_allowed_domain_ips(),
                    profile_allowed_log_ips=profile_allowed_log_ips,
                ):
                    continue
                classification = classify_destination(
                    dest,
                    verified_internal_ips=verified_internal_ips,
                    verified_internal_domains=verified_internal_domains,
                    declared_domains=all_allowed,
                    telemetry_registry=telemetry_registry,
                )
                if classification.destination_class in {
                    "platform_internal_verified",
                    "declared_business",
                    "framework_telemetry",
                    "dependency_service",
                }:
                    continue
                violations.append(
                    _build_violation_finding(
                        profile=profile,
                        dest=dest,
                        destination_class=classification.destination_class or "unknown_external",
                        trace=trace,
                    )
                )

        if low_confidence_profiles:
            findings.append(
                self.finding(
                    title="Egress telemetry confidence reduced (log-only observations)",
                    category=TrustCategory.EGRESS,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=(
                        "One or more profiles observed destinations only in logs, without procfs socket evidence: "
                        + ", ".join(sorted(set(low_confidence_profiles)))
                    ),
                    recommendation=(
                        "Treat egress verdict as provisional and instrument runtime network capture "
                        "for stronger evidence from the hosted deployment."
                    ),
                )
            )

        if violations:
            findings.extend(violations)
            return findings

        findings.append(
            self.finding(
                title="Runtime egress matched taxonomy",
                category=TrustCategory.EGRESS,
                severity=TrustSeverity.INFO,
                passed=True,
                summary=(
                    "Observed runtime destinations were classified as internal, declared, "
                    "telemetry, or allowlisted destinations."
                ),
            )
        )
        return findings


def _split_allow_targets(
    allowed: set[str],
) -> tuple[set[str], set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    domains: set[str] = set()
    ip_literals: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    for candidate in allowed:
        token = candidate.strip().lower()
        if not token:
            continue
        try:
            ip = ipaddress.ip_address(token)
            ip_literals.add(str(ip))
            continue
        except ValueError:
            pass

        try:
            net = ipaddress.ip_network(token, strict=False)
            networks.append(net)
            continue
        except ValueError:
            pass

        domains.add(token)

    return domains, ip_literals, networks


def _is_allowed_domain(dest: str, allowed_domains: set[str]) -> bool:
    if not allowed_domains:
        return False
    dest_lower = dest.strip().lower()
    if not dest_lower:
        return False
    for domain in allowed_domains:
        if dest_lower == domain:
            return True
        if dest_lower.endswith(f".{domain}"):
            return True
    return False


def _is_allowed_ip_destination(
    *,
    dest: str,
    allowed_ip_literals: set[str],
    allowed_ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    resolved_allowed_domain_ips: set[str],
    profile_allowed_log_ips: set[str],
) -> bool:
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        return False

    ip_text = str(ip)
    if ip_text in allowed_ip_literals:
        return True
    if ip_text in resolved_allowed_domain_ips:
        return True
    if ip_text in profile_allowed_log_ips:
        return True
    return any(ip in net for net in allowed_ip_networks)


@lru_cache(maxsize=512)
def _resolve_domain_ips(domain: str) -> set[str]:
    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(domain, None)
    except Exception:
        return ips

    for entry in infos:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        raw_ip = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if parsed.is_unspecified:
            continue
        ips.add(str(parsed))
    return ips


def _is_local_destination(dest: str) -> bool:
    if dest in {"localhost", "127.0.0.1", "0.0.0.0", "::", "::1"}:
        return True
    try:
        parsed = ipaddress.ip_address(dest)
    except ValueError:
        return False
    return parsed.is_loopback or parsed.is_unspecified


def _build_verified_internal_destinations(
    ctx: TrustScanContext,
) -> tuple[set[str], set[str]]:
    verified_internal_ips: set[str] = set()
    verified_internal_domains: set[str] = set()

    runtime_context = ctx.hosted_runtime_context or {}
    for raw_ip in _normalize_sequence(runtime_context.get("verified_internal_ips")):
        if _looks_like_ip(raw_ip):
            verified_internal_ips.add(raw_ip)
    for raw_domain in _normalize_sequence(runtime_context.get("verified_internal_domains")):
        if raw_domain:
            verified_internal_domains.add(raw_domain)

    for trace in ctx.runtime_traces.values():
        for destination in trace.internal_network_destinations:
            normalized = destination.strip().lower()
            if not normalized:
                continue
            if _looks_like_ip(normalized):
                verified_internal_ips.add(normalized)
            else:
                verified_internal_domains.add(normalized)

        for service in trace.dependency_services:
            normalized = service.strip().lower()
            if not normalized:
                continue
            verified_internal_domains.add(f"{normalized}.railway.internal")

    deployment_result = ctx.deployment_result
    if deployment_result is not None:
        for service in deployment_result.dependency_services:
            normalized = service.strip().lower()
            if normalized:
                verified_internal_domains.add(f"{normalized}.railway.internal")

    return verified_internal_ips, verified_internal_domains


def _build_telemetry_registry(ctx: TrustScanContext) -> dict[str, str]:
    packages: set[str] = set()

    runtime_context = ctx.hosted_runtime_context or {}
    for raw_package in _normalize_sequence(runtime_context.get("telemetry_packages")):
        if raw_package:
            packages.add(raw_package)

    raw_env_packages = runtime_context.get("telemetry_package_list", "")
    if isinstance(raw_env_packages, str) and raw_env_packages.strip():
        for token in raw_env_packages.split(","):
            normalized = token.strip()
            if normalized:
                packages.add(normalized)

    return build_telemetry_registry(sorted(packages))


def _build_violation_finding(
    *,
    profile: str,
    dest: str,
    destination_class: str,
    trace,
) -> TrustFinding:
    severity = (
        TrustSeverity.MEDIUM
        if destination_class == "private_unattributed"
        else TrustSeverity.CRITICAL
    )
    evidence_strength = _evidence_strength_for_destination(dest=dest, trace=trace)
    signal = TrustSignal(
        check_id="runtime_egress",
        signal_type="outbound_connection",
        title=(
            "Private network destination observed"
            if severity == TrustSeverity.MEDIUM
            else "Undeclared outbound egress detected"
        ),
        summary=(
            f"Profile '{profile}' connected to '{dest}' classified as "
            f"'{destination_class}'."
        ),
        raw_evidence=dest,
        detection_method=evidence_strength,
        source_location=f"runtime:{profile}",
        base_severity=severity,
        category=TrustCategory.EGRESS,
        recommendation=(
            "Verify the internal destination or add it to the allowlist."
            if severity == TrustSeverity.MEDIUM
            else "Block submission and require explicit domain declaration and justification."
        ),
    )
    return normalize_finding(
        signal,
        destination_class=destination_class,
        evidence_strength=evidence_strength,
        runtime_attribution=_runtime_attribution_for_trace(trace),
        attribution_confidence="high" if evidence_strength == "procfs_confirmed" else "medium",
        destination_declared=False,
    )


def _evidence_strength_for_destination(*, dest: str, trace) -> str:
    normalized = dest.strip().lower()
    procfs_destinations = {value.strip().lower() for value in trace.network_destinations_procfs}
    log_destinations = {value.strip().lower() for value in trace.network_destinations_logs}
    if normalized in procfs_destinations:
        return "procfs_confirmed"
    if normalized in log_destinations:
        return "log_only"
    if procfs_destinations:
        return "heuristic"
    return "log_only"


def _runtime_attribution_for_trace(trace) -> str:
    if trace.probe_responses:
        return "request_time"
    if trace.status == "ok":
        return "startup"
    return "unknown"


def _normalize_sequence(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (set, tuple, list)):
        return [str(item) for item in value]
    return [str(value)]


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
