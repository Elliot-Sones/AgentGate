from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from agentgate.trust.config import DependencySpec, TrustScanConfig
from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES
from agentgate.trust.runtime.dependency_inference import infer_runtime_dependencies
from agentgate.trust.runtime.railway_executor import RailwayExecutionResult
from agentgate.trust.runtime.submission_profile import (
    GeneratedRuntimeProfile,
    SubmissionSupportAssessment,
)
from agentgate.trust.runtime.trace_collector import RuntimeTrace


@dataclass
class TrustScanContext:
    config: TrustScanConfig
    manifest: dict | None = None
    manifest_error: str = ""
    runtime_traces: dict[str, RuntimeTrace] = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    hosted_runtime_context: dict[str, object] = field(default_factory=dict)
    submission_support_assessment: SubmissionSupportAssessment | None = None
    generated_runtime_profile: GeneratedRuntimeProfile | None = None
    deployment_result: RailwayExecutionResult | None = None
    _artifact_dir: Path | None = None
    _source_inference_applied: bool = False

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
            self.config.dependencies = []
            self.config.runtime_env = {}
            self.config.dependency_validation_errors = []
            self.config.dependency_inference_notes = []
            self._source_inference_applied = False
            return

        if not path.exists():
            self.manifest_error = f"Manifest not found: {path}"
            self.manifest = None
            self.config.dependencies = []
            self.config.runtime_env = {}
            self.config.dependency_validation_errors = []
            self.config.dependency_inference_notes = []
            self._source_inference_applied = False
            return

        text = path.read_text()
        if not text.strip():
            self.manifest_error = "Manifest file is empty"
            self.manifest = None
            self.config.dependencies = []
            self.config.runtime_env = {}
            self.config.dependency_validation_errors = []
            self.config.dependency_inference_notes = []
            self._source_inference_applied = False
            return

        # JSON first (deterministic, strict)
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                self.manifest = parsed
                self.manifest_error = ""
                self._load_manifest_runtime_config(parsed)
                return
            raise ValueError("Manifest root must be an object")
        except Exception:
            pass

        # YAML via optional dependency if present
        try:
            import yaml  # type: ignore

            parsed = yaml.safe_load(text)
            if isinstance(parsed, dict):
                self.manifest = parsed
                self.manifest_error = ""
                self._load_manifest_runtime_config(parsed)
                return
        except Exception:
            pass

        # Minimal fallback parser for nested key/list YAML
        try:
            parsed = _parse_simple_yaml(text)
            if not isinstance(parsed, dict):
                raise ValueError("Parsed manifest was not an object")
            self.manifest = parsed
            self.manifest_error = ""
            self._load_manifest_runtime_config(parsed)
            return
        except Exception:
            pass

        self.manifest_error = "Failed to parse manifest"
        self.manifest = None
        self.config.dependencies = []
        self.config.runtime_env = {}
        self.config.dependency_validation_errors = []
        self.config.dependency_inference_notes = []
        self._source_inference_applied = False

    def _load_manifest_runtime_config(self, manifest: dict) -> None:
        self.config.dependencies = []
        self.config.runtime_env = {}
        self.config.dependency_validation_errors = []
        self.config.dependency_inference_notes = []
        self._source_inference_applied = False

        runtime_env = manifest.get("runtime_env", {})
        if runtime_env in (None, ""):
            runtime_env = {}
        if not isinstance(runtime_env, dict):
            self.config.dependency_validation_errors.append(
                "Manifest field 'runtime_env' must be a mapping of environment variables."
            )
        else:
            normalized_runtime_env: dict[str, str] = {}
            for key, value in runtime_env.items():
                if not isinstance(key, str):
                    self.config.dependency_validation_errors.append(
                        "Manifest field 'runtime_env' keys must be strings."
                    )
                    continue
                normalized_runtime_env[key] = str(value)
            self.config.runtime_env = normalized_runtime_env

        dependencies = manifest.get("dependencies", [])
        if dependencies in (None, ""):
            dependencies = []
        if not isinstance(dependencies, list):
            self.config.dependency_validation_errors.append(
                "Manifest field 'dependencies' must be a list."
            )
            return

        normalized_dependencies: list[DependencySpec] = []
        for idx, raw_dep in enumerate(dependencies):
            if not isinstance(raw_dep, dict):
                self.config.dependency_validation_errors.append(
                    f"Dependency entry #{idx + 1} must be an object."
                )
                continue

            service = raw_dep.get("service")
            if not isinstance(service, str) or not service.strip():
                self.config.dependency_validation_errors.append(
                    f"Dependency entry #{idx + 1} is missing a valid 'service' value."
                )
                continue

            service_name = service.strip().lower()
            if service_name not in ALLOWED_SERVICES:
                self.config.dependency_validation_errors.append(
                    f"Dependency service '{service_name}' is not in the allowed service catalog."
                )
                continue

            env = raw_dep.get("env", {})
            if env in (None, ""):
                env = {}
            if not isinstance(env, dict):
                self.config.dependency_validation_errors.append(
                    f"Dependency '{service_name}' field 'env' must be a mapping."
                )
                continue

            normalized_env = {str(key): str(value) for key, value in env.items()}
            normalized_dependencies.append(
                DependencySpec(service=service_name, env=normalized_env)
            )

        self.config.dependencies = normalized_dependencies
        self.infer_runtime_config_from_source()

    def infer_runtime_config_from_source(self) -> None:
        if self._source_inference_applied:
            return
        dependencies, runtime_env, notes = infer_runtime_dependencies(
            source_dir=self.source_dir,
            existing_dependencies=self.config.dependencies,
            existing_runtime_env=self.config.runtime_env,
        )
        self.config.dependencies = dependencies
        self.config.runtime_env = runtime_env
        self.config.dependency_inference_notes = notes
        self._source_inference_applied = True


def _parse_simple_yaml(text: str) -> dict:
    lines = _tokenize_yaml_lines(text)
    if not lines:
        return {}
    parsed, next_index = _parse_yaml_block(lines, 0, lines[0][0])
    if next_index != len(lines):
        raise ValueError("Unexpected trailing YAML content")
    if not isinstance(parsed, dict):
        raise ValueError("Parsed manifest was not an object")
    return parsed


def _tokenize_yaml_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        lines.append((indent, raw_line[indent:].rstrip()))
    return lines


def _parse_yaml_block(
    lines: list[tuple[int, str]], start: int, indent: int
) -> tuple[object, int]:
    if start >= len(lines):
        return {}, start
    _, text = lines[start]
    if text.startswith("- "):
        return _parse_yaml_list(lines, start, indent)
    return _parse_yaml_dict(lines, start, indent)


def _parse_yaml_dict(
    lines: list[tuple[int, str]], start: int, indent: int
) -> tuple[dict, int]:
    data: dict = {}
    index = start

    while index < len(lines):
        line_indent, text = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise ValueError(f"Unexpected indentation near '{text}'")
        if text.startswith("- "):
            raise ValueError(f"Unexpected list item near '{text}'")
        if ":" not in text:
            raise ValueError(f"Invalid line: {text}")

        key, value = text.split(":", 1)
        key = key.strip()
        value = value.strip()
        index += 1

        if value:
            data[key] = _coerce_scalar(value)
            continue

        if index >= len(lines) or lines[index][0] <= indent:
            data[key] = {}
            continue

        child_indent = lines[index][0]
        child, index = _parse_yaml_block(lines, index, child_indent)
        data[key] = child

    return data, index


def _parse_yaml_list(
    lines: list[tuple[int, str]], start: int, indent: int
) -> tuple[list, int]:
    items: list = []
    index = start

    while index < len(lines):
        line_indent, text = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent:
            raise ValueError(f"Unexpected indentation near '{text}'")
        if not text.startswith("- "):
            break

        value = text[2:].strip()
        index += 1

        if not value:
            if index >= len(lines) or lines[index][0] <= indent:
                items.append("")
                continue
            child_indent = lines[index][0]
            child, index = _parse_yaml_block(lines, index, child_indent)
            items.append(child)
            continue

        if ":" in value:
            key, inline_value = value.split(":", 1)
            item: dict[str, object] = {}
            key = key.strip()
            inline_value = inline_value.strip()
            if inline_value:
                item[key] = _coerce_scalar(inline_value)
            elif index < len(lines) and lines[index][0] > indent:
                child_indent = lines[index][0]
                child, index = _parse_yaml_block(lines, index, child_indent)
                item[key] = child
            else:
                item[key] = {}

            if index < len(lines) and lines[index][0] > indent:
                extra_indent = lines[index][0]
                extra, index = _parse_yaml_dict(lines, index, extra_indent)
                item.update(extra)
            items.append(item)
            continue

        items.append(_coerce_scalar(value))

    return items, index


def _coerce_scalar(value: str):
    stripped = value.strip().strip('"').strip("'")
    if stripped.lower() == "true":
        return True
    if stripped.lower() == "false":
        return False
    if stripped.isdigit():
        return int(stripped)
    return stripped
