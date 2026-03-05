from __future__ import annotations

from functools import lru_cache
import ipaddress
import socket

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity


class RuntimeEgressCheck(BaseTrustCheck):
    check_id = "runtime_egress"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        findings: list[TrustFinding] = []

        if not ctx.runtime_traces:
            return [
                self.finding(
                    title="No runtime traces available for egress analysis",
                    category=TrustCategory.EGRESS,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Runtime egress check requires runtime sandbox traces.",
                    recommendation="Enable runtime checks and ensure image runs in the sandbox.",
                )
            ]

        declared = set()
        if ctx.manifest and isinstance(ctx.manifest.get("declared_external_domains"), list):
            declared = {str(v).lower() for v in ctx.manifest["declared_external_domains"]}
        allowlist = {d.lower() for d in ctx.config.egress_allowlist}

        all_allowed = {v.strip().lower() for v in (declared | allowlist) if str(v).strip()}
        allowed_domains, allowed_ip_literals, allowed_ip_networks = _split_allow_targets(all_allowed)
        violations: list[tuple[str, str]] = []
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
                violations.append((profile, dest))

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
                        "for stronger evidence."
                    ),
                )
            )

        if violations:
            for profile, dest in violations:
                findings.append(
                    self.finding(
                        title="Undeclared outbound egress detected",
                        category=TrustCategory.EGRESS,
                        severity=TrustSeverity.CRITICAL,
                        passed=False,
                        summary=f"Profile '{profile}' connected to '{dest}' outside declared/allowlisted domains.",
                        recommendation="Block submission and require explicit domain declaration and justification.",
                        observed=dest,
                        expected=", ".join(sorted(all_allowed)) or "No external destinations",
                    )
                )
            return findings

        findings.append(
            self.finding(
                title="Runtime egress matched declarations",
                category=TrustCategory.EGRESS,
                severity=TrustSeverity.INFO,
                passed=True,
                summary="Observed runtime destinations were within declared/allowlisted domains.",
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
