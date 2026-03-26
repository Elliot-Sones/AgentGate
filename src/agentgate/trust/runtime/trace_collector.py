from __future__ import annotations

import re
from dataclasses import dataclass, field


URL_RE = re.compile(r"https?://([a-zA-Z0-9.-]+)")
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b")
TOOL_CALL_RE = re.compile(r"TOOL_CALL:([a-zA-Z0-9_.-]+)")

# Known false-positive domain-like tokens from logs.
# Python module references (e.g. asyncio.run, self.app) look like domains to
# DOMAIN_RE but are never real network destinations.
_LOG_NOISE = {
    "setuptools.build",
    "pydantic.v2",
    "uvicorn.error",
    "uvicorn.access",
    "asyncio.events",
    "asyncio.run",
    "asyncio.base",
    "asyncio.runners",
    "starlette.routing",
    "fastapi.applications",
    "config.load",
    "future.result",
    "self.app",
    "self.run",
    "self.serve",
    "self.get",
    "self.post",
    "self.put",
    "self.delete",
    "os.makedirs",
    "os.path",
    "os.environ",
    "runner.run",
    "logger.info",
    "logger.debug",
    "logger.error",
    "logger.warning",
}

# Prefixes that are almost always Python attribute access, not domains
_NOISE_PREFIXES = ("self.", "cls.", "os.", "sys.", "re.", "io.")

# TLDs that are very unlikely to be real network destinations when seen in logs
_CODE_TLDS = {
    "run",
    "load",
    "result",
    "send",
    "close",
    "start",
    "stop",
    "read",
    "write",
    "call",
    "init",
    "get",
    "set",
    "put",
    "post",
    "delete",
    "serve",
    "app",
    "log",
    "error",
    "debug",
    "info",
    "warning",
    "client",
    "memory",
    "config",
}

_DESTINATION_EXCLUDED_PREFIXES = (
    "[PROBE ",
    "[HOSTED TARGET]",
    "[RAILWAY CONTEXT]",
    "[RAILWAY SERVICE]",
)


@dataclass
class RuntimeTrace:
    profile: str
    status: str = "ok"  # ok | unavailable | error | timeout
    error: str = ""
    network_destinations: list[str] = field(default_factory=list)
    network_destinations_logs: list[str] = field(default_factory=list)
    network_destinations_procfs: list[str] = field(default_factory=list)
    internal_network_destinations: list[str] = field(default_factory=list)
    process_events: list[str] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)
    canary_hits: list[str] = field(default_factory=list)
    logs: str = ""
    dependency_services: list[str] = field(default_factory=list)

    # Structured telemetry from docker inspect (Finding 1)
    inspect_user: str = ""
    inspect_network_mode: str = ""
    inspect_exit_code: int | None = None
    inspect_ports: list[str] = field(default_factory=list)
    inspect_env_keys: list[str] = field(default_factory=list)
    inspect_capabilities: list[str] = field(default_factory=list)
    inspect_oom_killed: bool = False
    telemetry_source: str = "logs"  # "logs" | "logs+inspect"

    # HTTP probe responses (Finding 2)
    probe_responses: list[dict] = field(default_factory=list)


class TraceCollector:
    """Extract lightweight telemetry from runtime output logs."""

    def collect(self, profile: str, logs: str, error: str = "") -> RuntimeTrace:
        trace = RuntimeTrace(profile=profile, logs=logs, error=error)

        if error:
            trace.status = "error"

        destination_source = "\n".join(
            line
            for line in logs.splitlines()
            if not any(line.startswith(prefix) for prefix in _DESTINATION_EXCLUDED_PREFIXES)
        )

        destinations: set[str] = set()
        for match in URL_RE.finditer(destination_source):
            destinations.add(match.group(1).lower())
        for match in DOMAIN_RE.finditer(destination_source):
            token = match.group(1).lower()
            if token.count(".") >= 1:
                destinations.add(token)
        destinations -= _LOG_NOISE
        destinations = {
            d
            for d in destinations
            if not d.endswith(
                (
                    ".py",
                    ".pyc",
                    ".pyi",
                    ".cfg",
                    ".txt",
                    ".md",
                    ".toml",
                    ".json",
                    ".js",
                    ".css",
                    ".png",
                    ".ico",
                    ".svg",
                )
            )
            and not any(d.startswith(p) for p in _NOISE_PREFIXES)
            and d.rsplit(".", 1)[-1] not in _CODE_TLDS
        }
        log_destinations = sorted(destinations)
        trace.network_destinations_logs = log_destinations
        trace.network_destinations = list(log_destinations)

        tools: set[str] = set()
        for match in TOOL_CALL_RE.finditer(logs):
            tools.add(match.group(1))
        trace.tool_calls = sorted(tools)

        events = []
        for line in logs.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("PROC:") or line.startswith("EXEC:"):
                events.append(line)
        trace.process_events = events

        return trace
