from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx

from agentgate.trust.runtime.canary_bank import CanaryBank
from agentgate.trust.runtime.railway_auth import railway_cli_env
from agentgate.trust.runtime.railway_discovery import (
    RailwayDiscoveryError,
    discover_railway_runtime,
)
from agentgate.trust.runtime.trace_collector import RuntimeTrace, TraceCollector

logger = logging.getLogger(__name__)

_DEFAULT_HOSTED_PROBES: tuple[tuple[str, str], ...] = (
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/docs"),
    ("GET", "/openapi.json"),
    ("POST", "/api/v1/chat"),
)
_MAX_BODY_SNIPPET = 2048


class HostedRuntimeRunner:
    """Collect runtime evidence from the live hosted agent instead of local Docker."""

    def __init__(
        self,
        base_url: str,
        runtime_seconds: int = 30,
        railway_workspace_dir: Path | None = None,
        railway_service: str = "",
        railway_environment: str = "",
        railway_project_token: str = "",
        probe_paths: list[str] | None = None,
        adaptive_api_key: str = "",
        adaptive_model: str = "claude-sonnet-4-6",
        source_dir: Path | None = None,
        manifest: dict | None = None,
        static_findings: list[str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.runtime_seconds = runtime_seconds
        self.railway_workspace_dir = railway_workspace_dir
        self.railway_service = railway_service
        self.railway_environment = railway_environment
        self.railway_project_token = railway_project_token.strip()
        self.probe_paths = list(probe_paths or [])
        self.adaptive_api_key = adaptive_api_key
        self.adaptive_model = adaptive_model
        self.source_dir = source_dir
        self.manifest = manifest
        self.static_findings = list(static_findings or [])
        self.runtime_context: dict[str, object] = {}
        self.probing_mode: str = ""
        self.specialist_reports: list = []
        self.adaptive_fallback_reason: str = ""

    def run_profile(
        self,
        profile: str,
        canary_profile: str,
        artifact_dir: Path,
    ) -> RuntimeTrace:
        bank = CanaryBank(profile=canary_profile)
        log_path = artifact_dir / f"runtime_{profile}.log"

        if self.adaptive_api_key:
            (
                probe_responses,
                self.specialist_reports,
                self.probing_mode,
                self.adaptive_fallback_reason,
            ) = self._probe_adaptive(bank)
        else:
            probe_responses = self._probe_static(bank)
            self.probing_mode = "static"
            self.specialist_reports = []
            self.adaptive_fallback_reason = ""

        railway_logs = self._fetch_railway_logs()
        discovery = self._discover_railway_context()

        combined_logs = self._compose_logs(
            probe_responses=probe_responses,
            railway_logs=railway_logs,
            discovery=discovery,
        )
        log_path.write_text(combined_logs)

        trace = TraceCollector().collect(profile=profile, logs=combined_logs)
        trace.logs = combined_logs
        trace.probe_responses = probe_responses
        trace.inspect_network_mode = "hosted"
        trace.inspect_user = "hosted"
        trace.telemetry_source = "logs"
        if discovery is not None:
            trace.dependency_services = [
                dependency.service for dependency in discovery.dependencies
            ]

        has_successful_probe = any(response.get("status_code", 0) for response in probe_responses)
        if has_successful_probe or railway_logs.strip():
            trace.status = "ok"
        else:
            trace.status = "error"
            trace.error = "Hosted runtime probes did not return any successful responses."

        self.runtime_context = {
            "base_url": self.base_url,
            "host": urlparse(self.base_url).hostname or "",
            "probe_count": len(probe_responses),
            "railway_log_lines": len([line for line in railway_logs.splitlines() if line.strip()]),
            "probing_mode": self.probing_mode,
        }
        if self.adaptive_fallback_reason:
            self.runtime_context["adaptive_fallback_reason"] = self.adaptive_fallback_reason
        if self.specialist_reports:
            self.runtime_context["adaptive_specialists"] = [
                {
                    "specialist": report.specialist,
                    "severity": report.severity,
                    "findings": list(report.findings),
                    "evidence": list(report.evidence),
                    "probes_sent": report.probes_sent,
                    "probes_succeeded": report.probes_succeeded,
                }
                for report in self.specialist_reports
            ]
        if discovery is not None:
            self.runtime_context.update(
                {
                    "railway_project": discovery.project_name,
                    "railway_environment": discovery.environment_name,
                    "railway_service": discovery.service_name,
                    "railway_dependencies": [
                        dependency.service for dependency in discovery.dependencies
                    ],
                    "railway_public_domain": discovery.public_domain,
                }
            )

        return trace

    def _probe_adaptive(self, bank: CanaryBank) -> tuple[list[dict], list, str, str]:
        """Run adaptive per-agent probing using the AdaptiveProbeOrchestrator."""
        try:
            from agentgate.trust.runtime.adaptive.context_builder import ContextBuilder
            from agentgate.trust.runtime.adaptive.orchestrator import AdaptiveProbeOrchestrator

            # Run a quick static probe first to get OpenAPI spec
            static_responses = self._probe_static(bank)

            bundle = ContextBuilder.build(
                source_dir=self.source_dir,
                manifest=self.manifest,
                static_findings=self.static_findings,
                live_url=self.base_url,
                canary_tokens=bank.tokens(),
                probe_responses=static_responses,
            )

            orchestrator = AdaptiveProbeOrchestrator(
                api_key=self.adaptive_api_key,
                model=self.adaptive_model,
            )
            adaptive_responses, specialist_reports = orchestrator.run(
                bundle,
                log_fetcher=self._fetch_railway_logs,
            )

            # Merge: static first, then adaptive
            all_responses = static_responses + adaptive_responses
            return all_responses, specialist_reports, "adaptive", ""
        except Exception as exc:
            logger.warning("Adaptive probing failed, falling back to static: %s", exc)
            return self._probe_static(bank), [], "static", str(exc)

    def _probe_static(self, bank: CanaryBank) -> list[dict]:
        """Run the original static probe plan."""
        token_values = list(bank.tokens().values())
        headers = {}
        if token_values:
            headers["X-AgentGate-Canary"] = token_values[0]

        responses: list[dict] = []
        timeout = max(min(self.runtime_seconds, 15), 5)
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for method, path in self._probe_plan():
                url = f"{self.base_url}{path}"
                body = None
                if method == "POST":
                    body = {"message": "AgentGate hosted probe"}
                try:
                    response = client.request(method, url, json=body, headers=headers)
                    body_text = response.text
                    body_snippet = body_text[:_MAX_BODY_SNIPPET]
                    payload: dict[str, object] = {
                        "method": method,
                        "path": path,
                        "status_code": response.status_code,
                        "body_snippet": body_snippet,
                        "content_type": response.headers.get("content-type", ""),
                        "error": "",
                    }
                    if path == "/openapi.json":
                        payload["body_full"] = body_text
                    responses.append(
                        payload
                    )
                except Exception as exc:
                    responses.append(
                        {
                            "method": method,
                            "path": path,
                            "status_code": 0,
                            "body_snippet": "",
                            "content_type": "",
                            "error": str(exc),
                        }
                    )
        return responses

    # Keep the old name as an alias for backward compatibility (and tests)
    def _probe_live_agent(self, bank: CanaryBank) -> list[dict]:
        return self._probe_static(bank)

    def _probe_plan(self) -> list[tuple[str, str]]:
        planned: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for method, path in _DEFAULT_HOSTED_PROBES:
            seen.add((method, path))
            planned.append((method, path))

        for path in self.probe_paths:
            normalized = str(path).strip()
            if not normalized.startswith("/"):
                continue
            method = (
                "POST"
                if any(token in normalized.lower() for token in ("/chat", "/search", "/query"))
                else "GET"
            )
            candidate = (method, normalized)
            if candidate in seen:
                continue
            seen.add(candidate)
            planned.append(candidate)

        return planned

    def _fetch_railway_logs(self) -> str:
        if self.railway_workspace_dir is None or not self.railway_service:
            return ""

        cmd = [
            "railway",
            "logs",
            "--service",
            self.railway_service,
            "--lines",
            "120",
            "--latest",
        ]
        if self.railway_environment:
            cmd.extend(["--environment", self.railway_environment])

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.railway_workspace_dir),
                env=railway_cli_env(self.railway_project_token),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except Exception as exc:
            return f"[RAILWAY LOG ERROR] {exc}"

        if proc.returncode != 0:
            message = (proc.stderr or "").strip() or (proc.stdout or "").strip()
            if not message:
                return ""
            return f"[RAILWAY LOG ERROR] {message}"
        return proc.stdout

    def _discover_railway_context(self):
        if self.railway_workspace_dir is None:
            return None
        try:
            return discover_railway_runtime(
                workspace_dir=self.railway_workspace_dir,
                service=self.railway_service or None,
                environment=self.railway_environment or None,
                source_dir=None,
                project_token=self.railway_project_token,
            )
        except RailwayDiscoveryError as exc:
            self.runtime_context["railway_discovery_error"] = str(exc)
            return None

    def _compose_logs(
        self,
        *,
        probe_responses: list[dict],
        railway_logs: str,
        discovery,
    ) -> str:
        lines: list[str] = [f"[HOSTED TARGET] {self.base_url}"]

        if self.probing_mode:
            lines.append(f"[PROBING MODE] {self.probing_mode}")

        if discovery is not None:
            lines.append(
                "[RAILWAY CONTEXT] "
                f"project={discovery.project_name} service={discovery.service_name} "
                f"environment={discovery.environment_name}"
            )
            for service in discovery.service_graph:
                lines.append(
                    "[RAILWAY SERVICE] "
                    f"name={service.name} status={service.latest_status or 'unknown'}"
                )

        for response in probe_responses:
            status = response.get("status_code", 0)
            error = response.get("error", "")
            specialist = response.get("specialist", "")
            prefix = f"[{specialist.upper()}] " if specialist else ""
            if error:
                lines.append(
                    f"{prefix}[PROBE {response['method']} {response['path']}] ERROR {error}"
                )
                continue
            lines.append(f"{prefix}[PROBE {response['method']} {response['path']}] status={status}")
            snippet = str(response.get("body_snippet", "")).strip()
            content_type = str(response.get("content_type", "")).lower()
            if snippet and not _is_markup_content_type(content_type):
                lines.append(snippet)

        if railway_logs.strip():
            lines.append("[RAILWAY LOGS]")
            lines.append(railway_logs.strip())

        return "\n".join(lines) + "\n"


def _is_markup_content_type(content_type: str) -> bool:
    return "text/html" in content_type or "javascript" in content_type
