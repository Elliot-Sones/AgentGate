from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DependencySpec:
    service: str
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class TrustScanConfig:
    source_dir: Path | None
    image_ref: str
    manifest_path: Path | None
    output_dir: Path
    profile: str = "both"  # review | prodlike | both
    report_profile: str = "standard"  # standard | promptshop
    anthropic_api_key: str = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", "")
    )
    enable_report_enrichment: bool = True
    report_enrichment_model: str = "claude-3-5-haiku-latest"
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
    hosted_url: str = ""
    railway_workspace_dir: Path | None = None
    railway_workspace_id: str = ""
    railway_service: str = ""
    railway_environment: str = ""
    strict_production_contract: bool = False
    keep_environment_on_failure: bool = False

    egress_allowlist: set[str] = field(default_factory=set)
    dependencies: list[DependencySpec] = field(default_factory=list)
    runtime_env: dict[str, str] = field(default_factory=dict)
    dependency_validation_errors: list[str] = field(default_factory=list)
    dependency_inference_notes: list[str] = field(default_factory=list)

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
