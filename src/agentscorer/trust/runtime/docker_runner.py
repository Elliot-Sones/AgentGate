from __future__ import annotations

import importlib.resources
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from agentscorer.trust.runtime.canary_bank import CanaryBank
from agentscorer.trust.runtime.container_inspector import ContainerInspector
from agentscorer.trust.runtime.http_prober import HttpProber
from agentscorer.trust.runtime.trace_collector import RuntimeTrace, TraceCollector


def _seccomp_profile_path() -> str | None:
    """Return the path to the bundled seccomp profile, or *None* if not found."""
    try:
        ref = importlib.resources.files("agentscorer.trust.runtime").joinpath(
            "seccomp_default.json"
        )
        path = str(ref)
        if Path(path).exists():
            return path
    except Exception:
        pass
    return None


@dataclass
class DockerRunner:
    image_ref: str
    runtime_seconds: int = 180
    enable_http_probing: bool = True

    def is_available(self) -> bool:
        return shutil.which("docker") is not None

    def inspect_image(self) -> tuple[bool, str]:
        if not self.is_available():
            return False, "docker binary is not available"

        cmd = ["docker", "image", "inspect", self.image_ref]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
            return True, ""
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            return False, stderr or "docker image inspect failed"
        except Exception as exc:  # pragma: no cover - defensive
            return False, str(exc)

    def run_profile(
        self,
        profile: str,
        network_mode: str,
        canary_profile: str,
        artifact_dir: Path,
    ) -> RuntimeTrace:
        collector = TraceCollector()

        if not self.is_available():
            return RuntimeTrace(
                profile=profile, status="unavailable", error="docker binary unavailable"
            )

        bank = CanaryBank(profile=canary_profile)
        env_args: list[str] = []
        for key, value in bank.tokens().items():
            env_args.extend(["-e", f"{key}={value}"])

        log_path = artifact_dir / f"runtime_{profile}.log"

        # --- Build docker create command ---
        cmd = [
            "docker",
            "create",
            "--network",
            network_mode,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "512m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--user",
            "65534:65534",
        ]

        # Seccomp profile: use bundled allowlist, fall back to Docker default
        seccomp_path = _seccomp_profile_path()
        if seccomp_path:
            cmd.extend(["--security-opt", f"seccomp={seccomp_path}"])

        # Publish exposed ports when network is enabled (for HTTP probing)
        if network_mode != "none":
            cmd.append("-P")

        cmd.extend(env_args)
        cmd.append(self.image_ref)

        container_id: str | None = None
        try:
            # --- Create phase ---
            create_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            if create_result.returncode != 0:
                err = (create_result.stderr or "").strip() or "docker create failed"
                return RuntimeTrace(profile=profile, status="error", error=err)
            container_id = create_result.stdout.strip()[:64]

            # --- Start phase ---
            subprocess.run(
                ["docker", "start", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # --- Probe phase (Finding 2) ---
            probe_log = ""
            probe_responses: list[dict] = []
            if network_mode != "none" and self.enable_http_probing:
                prober = HttpProber()
                port = prober.discover_port(container_id)
                if port and prober.wait_for_ready(port):
                    results = prober.probe(port)
                    for pr in results:
                        probe_responses.append(
                            {
                                "method": pr.method,
                                "path": pr.path,
                                "status_code": pr.status_code,
                                "body_snippet": pr.body_snippet,
                                "error": pr.error,
                            }
                        )
                        if pr.body_snippet:
                            probe_log += f"\n[PROBE {pr.method} {pr.path}] {pr.body_snippet}"

            # --- Wait phase ---
            try:
                subprocess.run(
                    ["docker", "wait", container_id],
                    capture_output=True,
                    text=True,
                    timeout=self.runtime_seconds,
                )
            except subprocess.TimeoutExpired:
                subprocess.run(
                    ["docker", "stop", "-t", "5", container_id],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )

            # --- Collect phase ---
            logs_result = subprocess.run(
                ["docker", "logs", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            combined = "\n".join(
                [logs_result.stdout or "", logs_result.stderr or ""]
            ).strip()
            if probe_log:
                combined += "\n" + probe_log.strip()
            log_path.write_text(combined)

            trace = collector.collect(profile=profile, logs=combined)
            trace.canary_hits = bank.detect_hits(combined)
            trace.probe_responses = probe_responses

            # Structured telemetry from docker inspect (Finding 1)
            inspector = ContainerInspector()
            inspection = inspector.inspect(container_id)
            trace.inspect_user = inspection.user
            trace.inspect_network_mode = inspection.network_mode
            trace.inspect_exit_code = inspection.exit_code
            trace.inspect_ports = inspection.ports
            trace.inspect_env_keys = inspection.env_keys
            trace.inspect_capabilities = inspection.capabilities_add
            trace.inspect_oom_killed = inspection.oom_killed
            trace.telemetry_source = "logs+inspect"

            # Check exit code from inspect
            if inspection.exit_code is not None and inspection.exit_code != 0:
                if trace.status == "ok":
                    trace.status = "error"
                    trace.error = f"container exited with code {inspection.exit_code}"

            return trace

        except subprocess.TimeoutExpired:
            # Timeout during wait phase
            combined = ""
            if container_id:
                try:
                    subprocess.run(
                        ["docker", "stop", "-t", "5", container_id],
                        capture_output=True,
                        timeout=15,
                    )
                    logs_result = subprocess.run(
                        ["docker", "logs", container_id],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    combined = "\n".join(
                        [logs_result.stdout or "", logs_result.stderr or ""]
                    ).strip()
                except Exception:
                    pass
            log_path.write_text(combined)
            trace = collector.collect(
                profile=profile, logs=combined, error="runtime timed out"
            )
            trace.status = "timeout"
            return trace

        except Exception as exc:  # pragma: no cover - defensive
            return RuntimeTrace(profile=profile, status="error", error=str(exc))

        finally:
            # --- Cleanup phase: always remove container ---
            if container_id:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", container_id],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                except Exception:
                    pass
