from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ContextBundle:
    source_files: dict[str, str]
    manifest: dict | None
    static_findings: list[str]
    live_url: str
    canary_tokens: dict[str, str]
    declared_tools: list[str] = field(default_factory=list)
    declared_domains: list[str] = field(default_factory=list)
    customer_data_access: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    openapi_spec: dict | None = None

    def source_summary(self, max_chars: int = 8000) -> str:
        parts: list[str] = []
        remaining = max_chars
        for filename, content in self.source_files.items():
            header = f"--- {filename} ---\n"
            if remaining <= len(header):
                break
            remaining -= len(header)
            snippet = content[:remaining]
            parts.append(header + snippet)
            remaining -= len(snippet)
            if remaining <= 0:
                break
        return "\n".join(parts)


@dataclass
class Phase:
    agents: list[str]
    parallel: bool
    reason: str = ""


@dataclass
class DispatchPlan:
    phases: list[Phase] = field(default_factory=list)


@dataclass
class ProbeRequest:
    specialist: str
    method: str
    path: str
    body: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class ProbeResult:
    specialist: str
    method: str
    path: str
    request_body: dict | None
    status_code: int
    response_body: str
    content_type: str
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status_code > 0 and not self.error


@dataclass
class SpecialistReport:
    specialist: str
    probes_sent: int
    probes_succeeded: int
    probe_results: list[ProbeResult] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    severity: str = "info"
    railway_logs: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0
