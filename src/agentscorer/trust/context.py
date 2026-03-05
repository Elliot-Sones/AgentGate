from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from agentscorer.trust.config import TrustScanConfig
from agentscorer.trust.runtime.trace_collector import RuntimeTrace


@dataclass
class TrustScanContext:
    config: TrustScanConfig
    manifest: dict | None = None
    manifest_error: str = ""
    runtime_traces: dict[str, RuntimeTrace] = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    _artifact_dir: Path | None = None

    @property
    def source_dir(self) -> Path | None:
        return self.config.source_dir

    @property
    def manifest_path(self) -> Path | None:
        return self.config.manifest_path

    @property
    def output_dir(self) -> Path:
        return self.config.output_dir

    @property
    def artifact_dir(self) -> Path:
        if self._artifact_dir is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = self.output_dir / "trust_artifacts" / ts
            path.mkdir(parents=True, exist_ok=True)
            self._artifact_dir = path
        return self._artifact_dir

    def add_artifact(self, path: Path) -> None:
        if path.exists():
            self.artifacts.append(path)

    def load_manifest(self) -> None:
        path = self.manifest_path
        if path is None:
            self.manifest_error = "No manifest path provided"
            self.manifest = None
            return

        if not path.exists():
            self.manifest_error = f"Manifest not found: {path}"
            self.manifest = None
            return

        text = path.read_text()
        if not text.strip():
            self.manifest_error = "Manifest file is empty"
            self.manifest = None
            return

        # JSON first (deterministic, strict)
        try:
            self.manifest = json.loads(text)
            self.manifest_error = ""
            return
        except Exception:
            pass

        # YAML via optional dependency if present
        try:
            import yaml  # type: ignore

            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                self.manifest = parsed
                self.manifest_error = ""
                return
        except Exception:
            pass

        # Minimal fallback parser for simple key/list YAML
        try:
            self.manifest = _parse_simple_yaml(text)
            self.manifest_error = ""
            return
        except Exception as exc:
            self.manifest_error = f"Failed to parse manifest: {exc}"
            self.manifest = None


def _parse_simple_yaml(text: str) -> dict:
    data: dict = {}
    current_list_key: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue

        if line.startswith("  - ") and current_list_key:
            value = line[4:].strip()
            if isinstance(data.get(current_list_key), list):
                data[current_list_key].append(_coerce_scalar(value))
            continue

        if line.startswith("- ") and current_list_key:
            value = line[2:].strip()
            if isinstance(data.get(current_list_key), list):
                data[current_list_key].append(_coerce_scalar(value))
            continue

        if ":" not in line:
            raise ValueError(f"Invalid line: {line}")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value == "":
            data[key] = []
            current_list_key = key
        else:
            data[key] = _coerce_scalar(value)
            current_list_key = None

    if not isinstance(data, dict):
        raise ValueError("Parsed manifest was not an object")
    return data


def _coerce_scalar(value: str):
    stripped = value.strip().strip('"').strip("'")
    if stripped.lower() == "true":
        return True
    if stripped.lower() == "false":
        return False
    if stripped.isdigit():
        return int(stripped)
    return stripped
