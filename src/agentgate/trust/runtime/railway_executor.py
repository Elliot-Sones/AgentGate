from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from agentgate.trust.config import DependencySpec
from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES
from agentgate.trust.runtime.railway_auth import railway_cli_env
from agentgate.trust.runtime.dependency_runtime_env import build_dependency_runtime_env


class RailwayExecutionError(RuntimeError):
    """Raised when a Railway-backed submission deployment cannot be prepared."""


@dataclass
class RailwayExecutionResult:
    workspace_dir: Path
    project_id: str
    project_name: str
    environment_name: str
    service_name: str
    public_url: str
    dependency_services: list[str] = field(default_factory=list)
    issued_integrations: list[str] = field(default_factory=list)
    cleanup_project: bool = True
    cleanup_workspace_dir: bool = True
    reused_pool: bool = False
    notes: list[str] = field(default_factory=list)


class RailwayExecutor:
    def __init__(
        self,
        *,
        project_name_prefix: str = "agentgate-scan",
        workspace_id: str = "",
        project_token: str = "",
        pool_workspace_dir: Path | None = None,
        pool_environment: str = "",
        pool_service_name: str = "submission-agent",
    ) -> None:
        self.project_name_prefix = project_name_prefix
        self.workspace_id = workspace_id.strip()
        self.project_token = project_token.strip()
        self.pool_workspace_dir = pool_workspace_dir.resolve() if pool_workspace_dir else None
        self.pool_environment = pool_environment.strip()
        self.pool_service_name = pool_service_name.strip() or "submission-agent"

    def deploy_submission(
        self,
        *,
        source_dir: Path,
        dependencies: list[DependencySpec],
        runtime_env: dict[str, str],
        issued_integrations: list[str],
    ) -> RailwayExecutionResult:
        if self.pool_workspace_dir is not None:
            return self._deploy_into_pool(
                source_dir=source_dir,
                dependencies=dependencies,
                runtime_env=runtime_env,
                issued_integrations=issued_integrations,
            )
        return self._deploy_ephemeral(
            source_dir=source_dir,
            dependencies=dependencies,
            runtime_env=runtime_env,
            issued_integrations=issued_integrations,
        )

    def ensure_pool(
        self,
        *,
        dependencies: list[DependencySpec],
        ensure_domain: bool = True,
    ) -> RailwayExecutionResult:
        if self.pool_workspace_dir is None:
            raise RailwayExecutionError("Pool setup requires a linked Railway workspace directory.")

        cwd = self.pool_workspace_dir
        status = self._run_json(["status", "--json"], cwd)
        project_id, project_name = self._project_metadata(status)
        environment_name = self._ensure_environment(cwd, status)
        status = self._run_json(["status", "--json"], cwd)

        self._ensure_service(cwd, self.pool_service_name, status=status)
        dependency_services: list[str] = []
        notes = [
            "Reused a warm Railway pool instead of creating a fresh project.",
            f"Pool agent service '{self.pool_service_name}' is available in environment '{environment_name}'.",
        ]

        for dependency in dependencies:
            service_name, created = self._ensure_dependency_service(
                cwd,
                dependency,
                environment_name,
            )
            dependency_services.append(service_name)
            notes.append(
                f"{'Created' if created else 'Reused'} dependency service '{service_name}'."
            )

        public_url = ""
        if ensure_domain:
            public_url = self._ensure_domain(
                cwd,
                self.pool_service_name,
                runtime_env={"PORT": "8000"},
            )
            if public_url:
                notes.append(f"Pool agent service has a Railway domain at {public_url}.")

        return RailwayExecutionResult(
            workspace_dir=cwd,
            project_id=project_id,
            project_name=project_name,
            environment_name=environment_name,
            service_name=self.pool_service_name,
            public_url=public_url,
            dependency_services=dependency_services,
            issued_integrations=[],
            cleanup_project=False,
            cleanup_workspace_dir=False,
            reused_pool=True,
            notes=notes,
        )

    def _deploy_ephemeral(
        self,
        *,
        source_dir: Path,
        dependencies: list[DependencySpec],
        runtime_env: dict[str, str],
        issued_integrations: list[str],
    ) -> RailwayExecutionResult:
        temp_dir = Path(tempfile.mkdtemp(prefix="agentgate-railway-"))
        project_name = f"{self.project_name_prefix}-{temp_dir.name[-8:]}"

        init_args = ["init", "--name", project_name, "--json"]
        if self.workspace_id:
            init_args.extend(["--workspace", self.workspace_id])
        project_data = self._run_json(init_args, temp_dir)
        project_id = str(project_data.get("id") or project_data.get("projectId") or "").strip()
        project_name = str(project_data.get("name") or project_name).strip()
        if not project_id:
            raise RailwayExecutionError("Unable to create temporary Railway project.")

        environment_name = "production"
        service_name = "submission-agent"
        self._run_json(["add", "--service", service_name, "--json"], temp_dir)

        dependency_services: list[str] = []
        for dependency in dependencies:
            dependency_services.append(self._provision_dependency_service(temp_dir, dependency))

        deployment_runtime_env = self._build_application_runtime_env(
            dependencies=dependencies,
            runtime_env=runtime_env,
        )
        self._apply_runtime_env(
            temp_dir,
            service_name=service_name,
            environment_name=environment_name,
            runtime_env=deployment_runtime_env,
        )
        self._deploy_service(
            temp_dir,
            source_dir=source_dir,
            service_name=service_name,
            environment_name=environment_name,
        )
        status = self._wait_for_service_ready(temp_dir, service_name)
        public_url = self._ensure_domain(
            temp_dir,
            service_name,
            runtime_env=deployment_runtime_env,
            status=status,
        )
        if not public_url:
            raise RailwayExecutionError(
                "Unable to resolve a Railway public URL for the deployed submission."
            )

        return RailwayExecutionResult(
            workspace_dir=temp_dir,
            project_id=project_id,
            project_name=project_name,
            environment_name=environment_name,
            service_name=service_name,
            public_url=public_url,
            dependency_services=dependency_services,
            issued_integrations=list(issued_integrations),
            notes=["Created an ephemeral Railway project for this scan."],
        )

    def _deploy_into_pool(
        self,
        *,
        source_dir: Path,
        dependencies: list[DependencySpec],
        runtime_env: dict[str, str],
        issued_integrations: list[str],
    ) -> RailwayExecutionResult:
        cwd = self.pool_workspace_dir
        if cwd is None:
            raise RailwayExecutionError(
                "Pool deployment requires a linked Railway workspace directory."
            )

        status = self._run_json(["status", "--json"], cwd)
        project_id, project_name = self._project_metadata(status)
        environment_name = self._ensure_environment(cwd, status)
        status = self._run_json(["status", "--json"], cwd)

        service_name = self.pool_service_name
        self._ensure_service(cwd, service_name, status=status)

        dependency_services: list[str] = []
        notes = [
            "Reused a warm Railway pool instead of creating a fresh project.",
            f"Deployment targeted pool service '{service_name}' in environment '{environment_name}'.",
        ]
        for dependency in dependencies:
            dependency_service, created = self._ensure_dependency_service(
                cwd,
                dependency,
                environment_name,
            )
            dependency_services.append(dependency_service)
            notes.append(
                f"{'Created' if created else 'Reused'} dependency service '{dependency_service}'."
            )

        deployment_runtime_env = self._build_application_runtime_env(
            dependencies=dependencies,
            runtime_env=runtime_env,
        )
        deployment_runtime_env.setdefault("AGENTGATE_POOL_MODE", "true")
        self._apply_runtime_env(
            cwd,
            service_name=service_name,
            environment_name=environment_name,
            runtime_env=deployment_runtime_env,
        )
        self._deploy_service(
            cwd,
            source_dir=source_dir,
            service_name=service_name,
            environment_name=environment_name,
        )
        status = self._wait_for_service_ready(cwd, service_name)
        public_url = self._ensure_domain(
            cwd,
            service_name,
            runtime_env=deployment_runtime_env,
            status=status,
        )
        if not public_url:
            raise RailwayExecutionError(
                "Unable to resolve a Railway public URL for the deployed submission."
            )

        notes.append(
            "Dependency infrastructure was reused. If the agent persists state, reset or isolate backing services between scans."
        )

        return RailwayExecutionResult(
            workspace_dir=cwd,
            project_id=project_id,
            project_name=project_name,
            environment_name=environment_name,
            service_name=service_name,
            public_url=public_url,
            dependency_services=dependency_services,
            issued_integrations=list(issued_integrations),
            cleanup_project=False,
            cleanup_workspace_dir=False,
            reused_pool=True,
            notes=notes,
        )

    def _apply_runtime_env(
        self,
        cwd: Path,
        *,
        service_name: str,
        environment_name: str,
        runtime_env: dict[str, str],
    ) -> None:
        if not runtime_env:
            return
        variables = [f"{key}={value}" for key, value in sorted(runtime_env.items())]
        self._run_json(
            [
                "variable",
                "set",
                "--service",
                service_name,
                "--environment",
                environment_name,
                "--skip-deploys",
                "--json",
                *variables,
            ],
            cwd,
        )

    def _deploy_service(
        self,
        cwd: Path,
        *,
        source_dir: Path,
        service_name: str,
        environment_name: str,
    ) -> None:
        self._run_command(
            [
                "up",
                str(source_dir),
                "--service",
                service_name,
                "--environment",
                environment_name,
                "--path-as-root",
                "--ci",
                "--detach",
            ],
            cwd,
            timeout=600,
        )

    def _build_application_runtime_env(
        self,
        *,
        dependencies: list[DependencySpec],
        runtime_env: dict[str, str],
    ) -> dict[str, str]:
        deployment_runtime_env = dict(runtime_env)
        for dependency in dependencies:
            if dependency.service not in ALLOWED_SERVICES:
                continue
            deployment_runtime_env.update(
                build_dependency_runtime_env(
                    dependency.service,
                    service_name=dependency.service,
                    overrides=dependency.env,
                    railway_internal=True,
                )
            )
        deployment_runtime_env.setdefault("PORT", "8000")
        return deployment_runtime_env

    def _provision_dependency_service(self, cwd: Path, dependency: DependencySpec) -> str:
        service_name = dependency.service.strip().lower()
        service_def = ALLOWED_SERVICES.get(service_name)
        if service_def is None:
            raise RailwayExecutionError(
                f"Dependency '{dependency.service}' is not yet provisionable in the Railway execution path."
            )

        args = [
            "add",
            "--service",
            service_name,
            "--image",
            service_def.image,
            "--json",
        ]
        merged_env = dict(service_def.default_env)
        merged_env.update({str(key): str(value) for key, value in dependency.env.items()})
        for key, value in sorted(merged_env.items()):
            args.extend(["--variables", f"{key}={value}"])

        self._run_json(args, cwd)
        self._wait_for_service_ready(
            cwd,
            service_name,
            timeout_seconds=service_def.ready_timeout_seconds,
        )
        return service_name

    def _ensure_dependency_service(
        self,
        cwd: Path,
        dependency: DependencySpec,
        environment_name: str,
    ) -> tuple[str, bool]:
        service_name = dependency.service.strip().lower()
        status = self._run_json(["status", "--json"], cwd)
        if (
            _extract_service_node_for_environment(status, environment_name, service_name)
            is not None
        ):
            return service_name, False
        return self._provision_dependency_service(cwd, dependency), True

    def _ensure_service(self, cwd: Path, service_name: str, *, status: dict | None = None) -> None:
        current_status = status or self._run_json(["status", "--json"], cwd)
        if _extract_service_node(current_status, service_name) is not None:
            return
        self._run_json(["add", "--service", service_name, "--json"], cwd)

    def _ensure_environment(self, cwd: Path, status: dict) -> str:
        environment_name = self.pool_environment or "production"
        if _extract_environment_node(status, environment_name) is not None:
            return environment_name
        self._run_json(["environment", "new", environment_name, "--json"], cwd)
        return environment_name

    def _ensure_domain(
        self,
        cwd: Path,
        service_name: str,
        *,
        runtime_env: dict[str, str],
        status: dict | None = None,
    ) -> str:
        current_status = status or self._run_json(["status", "--json"], cwd)
        existing = _extract_public_url(current_status, service_name)
        if existing:
            return existing
        port = str(runtime_env.get("PORT", "8000"))
        domain_data = self._run_json(
            ["domain", "--service", service_name, "--port", port, "--json"],
            cwd,
        )
        return str(domain_data.get("domain") or "").strip() or _extract_public_url(
            self._run_json(["status", "--json"], cwd),
            service_name,
        )

    @staticmethod
    def _project_metadata(status: dict) -> tuple[str, str]:
        project_id = str(status.get("id") or status.get("projectId") or "").strip()
        project_name = str(status.get("name") or "").strip()
        if not project_id or not project_name:
            raise RailwayExecutionError(
                "Unable to resolve Railway project metadata from 'railway status --json'."
            )
        return project_id, project_name

    def cleanup(self, result: RailwayExecutionResult) -> None:
        try:
            if result.cleanup_project:
                self._run_json(
                    ["delete", "--project", result.project_id, "--yes", "--json"],
                    result.workspace_dir,
                )
        finally:
            if result.cleanup_workspace_dir:
                shutil.rmtree(result.workspace_dir, ignore_errors=True)

    def _wait_for_service_ready(
        self,
        cwd: Path,
        service_name: str,
        timeout_seconds: int = 180,
        poll_seconds: int = 5,
    ) -> dict:
        deadline = time.time() + timeout_seconds
        last_status: dict = {}
        while time.time() < deadline:
            last_status = self._run_json(["status", "--json"], cwd)
            service_node = _extract_service_node(last_status, service_name)
            latest_status = (
                str(((service_node or {}).get("latestDeployment", {}).get("status", "")))
                .strip()
                .upper()
            )
            if latest_status == "SUCCESS":
                return last_status
            if latest_status in {"FAILED", "CRASHED", "CANCELED", "REMOVED"}:
                raise RailwayExecutionError(
                    f"Railway deployment for service '{service_name}' failed with status {latest_status}."
                )
            time.sleep(poll_seconds)
        raise RailwayExecutionError(
            f"Timed out waiting for Railway service '{service_name}' to become ready."
        )

    def _run_json(self, args: list[str], cwd: Path) -> dict:
        output = self._run_command(args, cwd)
        try:
            parsed = json.loads(output)
        except Exception:
            parsed = None
            candidates = [line.strip() for line in output.splitlines() if line.strip()]
            for candidate in reversed(candidates):
                try:
                    parsed = json.loads(candidate)
                    break
                except Exception:
                    continue
            if parsed is None:
                raise RailwayExecutionError(f"Expected JSON from railway {' '.join(args)}.")
        if isinstance(parsed, list):
            return {"items": parsed}
        if not isinstance(parsed, dict):
            raise RailwayExecutionError(f"Unexpected Railway JSON shape for {' '.join(args)}.")
        return parsed

    def _run_command(self, args: list[str], cwd: Path, timeout: int = 120) -> str:
        proc = subprocess.run(
            ["railway", *args],
            cwd=str(cwd),
            env=railway_cli_env(self.project_token),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            message = (proc.stderr or "").strip() or (proc.stdout or "").strip()
            raise RailwayExecutionError(message or f"Railway command failed: {' '.join(args)}")
        return proc.stdout


def _extract_public_url(status: dict, service_name: str) -> str:
    service_node = _extract_service_node(status, service_name)
    if service_node is None:
        return ""
    domains = service_node.get("domains", {})
    if not isinstance(domains, dict):
        return ""
    for service_domain in domains.get("serviceDomains", []):
        domain = str(service_domain.get("domain") or "").strip()
        if domain:
            return f"https://{domain}"
    return ""


def _extract_environment_node(status: dict, environment_name: str) -> dict | None:
    environments = status.get("environments")
    if not isinstance(environments, dict):
        return None
    for edge in environments.get("edges", []):
        node = edge.get("node", {})
        if str(node.get("name") or "").strip() == environment_name:
            return node
    return None


def _extract_service_node_for_environment(
    status: dict,
    environment_name: str,
    service_name: str,
) -> dict | None:
    environment_node = _extract_environment_node(status, environment_name)
    if environment_node is None:
        return None
    service_instances = environment_node.get("serviceInstances", {})
    if not isinstance(service_instances, dict):
        return None
    for svc_edge in service_instances.get("edges", []):
        svc_node = svc_edge.get("node", {})
        if str(svc_node.get("serviceName") or "").strip() == service_name:
            return svc_node
    return None


def _extract_service_node(status: dict, service_name: str) -> dict | None:
    environments = status.get("environments")
    if not isinstance(environments, dict):
        return None
    for edge in environments.get("edges", []):
        node = edge.get("node", {})
        service_instances = node.get("serviceInstances", {})
        if not isinstance(service_instances, dict):
            continue
        for svc_edge in service_instances.get("edges", []):
            svc_node = svc_edge.get("node", {})
            if str(svc_node.get("serviceName") or "").strip() != service_name:
                continue
            return svc_node
    return None
