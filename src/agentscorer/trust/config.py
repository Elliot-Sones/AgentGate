from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrustScanConfig:
    source_dir: Path | None
    image_ref: str
    manifest_path: Path | None
    output_dir: Path
    profile: str = "both"  # review | prodlike | both
    runtime_seconds: int = 180
    egress_allowlist_path: Path | None = None
    canary_profile: str = "standard"  # minimal | standard | strict
    fail_on: str = "manual_review"  # allow_with_warnings | manual_review | block
    quiet: bool = False
    agentdojo_suite: Path | None = None

    # runtime knobs
    collect_runtime_traces: bool = True
    policy_version: str = "trust-policy-v1"
    review_network_mode: str = "none"
    prod_network_mode: str = "bridge"

    enable_http_probing: bool = True

    egress_allowlist: set[str] = field(default_factory=set)

    def load_allowlist(self) -> None:
        if not self.egress_allowlist_path:
            self.egress_allowlist = set()
            return

        path = self.egress_allowlist_path
        if not path.exists():
            self.egress_allowlist = set()
            return

        allowed: set[str] = set()
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            allowed.add(line.lower())
        self.egress_allowlist = allowed
