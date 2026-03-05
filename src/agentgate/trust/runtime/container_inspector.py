from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field


@dataclass
class ContainerInspection:
    user: str = ""
    network_mode: str = ""
    exit_code: int | None = None
    ports: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    capabilities_add: list[str] = field(default_factory=list)
    oom_killed: bool = False


class ContainerInspector:
    """Parse structured telemetry from ``docker inspect``."""

    def inspect(self, container_id: str) -> ContainerInspection:
        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return ContainerInspection()
            data = json.loads(result.stdout)
        except Exception:
            return ContainerInspection()

        if not data or not isinstance(data, list):
            return ContainerInspection()

        info = data[0]
        config = info.get("Config", {})
        host_config = info.get("HostConfig", {})
        state = info.get("State", {})
        network_settings = info.get("NetworkSettings", {})

        # Parse ports
        ports: list[str] = []
        raw_ports = network_settings.get("Ports") or {}
        for port_proto, bindings in raw_ports.items():
            if bindings:
                for b in bindings:
                    ports.append(f"{b.get('HostPort', '?')}->{port_proto}")
            else:
                ports.append(port_proto)

        # Parse env keys (names only, not values)
        env_keys: list[str] = []
        for entry in config.get("Env") or []:
            if "=" in entry:
                env_keys.append(entry.split("=", 1)[0])

        # Parse added capabilities
        cap_add = host_config.get("CapAdd") or []

        return ContainerInspection(
            user=config.get("User", ""),
            network_mode=host_config.get("NetworkMode", ""),
            exit_code=state.get("ExitCode"),
            ports=sorted(ports),
            env_keys=sorted(env_keys),
            capabilities_add=sorted(cap_add),
            oom_killed=state.get("OOMKilled", False),
        )
