from __future__ import annotations

import http.client
import socket
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class ProbeResult:
    method: str = ""
    path: str = ""
    status_code: int = 0
    body_snippet: str = ""
    error: str = ""


_DEFAULT_PROBES = [
    ("GET", "/"),
    ("GET", "/health"),
    ("POST", "/api/v1/chat"),
]

_MAX_BODY_SNIPPET = 2048


class HttpProber:
    """Send HTTP probes to a running container to exercise interaction-triggered behavior."""

    def discover_port(self, container_id: str) -> int | None:
        """Run ``docker port`` and return the first mapped host port, or *None*."""
        try:
            result = subprocess.run(
                ["docker", "port", container_id],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            # Output format: "8080/tcp -> 0.0.0.0:32768"
            for line in result.stdout.strip().splitlines():
                if "->" in line:
                    host_part = line.rsplit(":", 1)[-1].strip()
                    try:
                        return int(host_part)
                    except ValueError:
                        continue
        except Exception:
            pass
        return None

    def wait_for_ready(self, port: int, timeout: float = 3.0) -> bool:
        """Poll TCP connection with exponential backoff until *port* accepts."""
        deadline = time.monotonic() + timeout
        delay = 0.1
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(delay)
                delay = min(delay * 2, 1.0)
        return False

    def probe(self, port: int) -> list[ProbeResult]:
        """Send default HTTP probes and return results."""
        results: list[ProbeResult] = []
        for method, path in _DEFAULT_PROBES:
            pr = ProbeResult(method=method, path=path)
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                body = "" if method == "GET" else "{}"
                headers = {"Content-Type": "application/json"} if method == "POST" else {}
                conn.request(method, path, body=body or None, headers=headers)
                resp = conn.getresponse()
                pr.status_code = resp.status
                raw_body = resp.read(_MAX_BODY_SNIPPET)
                pr.body_snippet = raw_body.decode("utf-8", errors="replace")[:_MAX_BODY_SNIPPET]
                conn.close()
            except Exception as exc:
                pr.error = str(exc)
            results.append(pr)
        return results
