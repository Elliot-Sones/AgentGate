from __future__ import annotations

from abc import ABC, abstractmethod
import json
from typing import Any

import httpx

from agentgate.trust.runtime.adaptive.models import (
    ContextBundle,
    ProbeRequest,
    ProbeResult,
    SpecialistReport,
)

_MAX_RESPONSE_BODY = 2048
_INTERACTIVE_FIELDS = ("question", "query", "message", "text", "prompt", "input")
_DEFAULT_PREFERRED_PATHS = ("chat", "search", "query", "ask", "completion", "message", "memory")


class BaseSpecialist(ABC):
    name: str = "base"
    description: str = ""
    system_prompt: str = ""

    @abstractmethod
    def build_generation_prompt(self, context: ContextBundle) -> str:
        pass

    @abstractmethod
    def parse_probe_requests(self, llm_response: str) -> list[ProbeRequest]:
        pass

    @abstractmethod
    def build_analysis_prompt(
        self,
        context: ContextBundle,
        results: list[ProbeResult],
        railway_logs: str = "",
    ) -> str:
        pass

    def _format_prior_findings(self, context: ContextBundle) -> str:
        if not context.prior_specialist_findings:
            return ""
        lines = ["Previous specialist findings:"]
        for entry in context.prior_specialist_findings:
            specialist = entry.get("specialist", "unknown")
            severity = entry.get("severity", "info")
            for finding in entry.get("findings", []):
                lines.append(f"  - [{severity.upper()}] ({specialist}) {finding}")
        return "\n".join(lines) + "\n\n"

    def _format_logs_section(self, railway_logs: str) -> str:
        if not railway_logs.strip():
            return ""
        return (
            "\n\nRailway logs captured during probing "
            "(shows what the agent ACTUALLY did behind the scenes):\n"
            f"```\n{railway_logs.strip()}\n```\n\n"
            "IMPORTANT: These logs reveal the agent's real behavior — tool calls, "
            "network requests, errors — regardless of what the HTTP response said. "
            "Cross-reference the logs against the probe responses.\n"
        )

    @abstractmethod
    def parse_analysis(self, llm_response: str) -> SpecialistReport:
        pass

    def fallback_probe_requests(self, context: ContextBundle) -> list[ProbeRequest]:
        return []

    def preferred_path_keywords(self) -> tuple[str, ...]:
        return _DEFAULT_PREFERRED_PATHS

    def load_json_object(self, llm_response: str) -> dict[str, Any] | None:
        text = llm_response.strip()
        if not text:
            return None

        for candidate in (text, self._extract_json_block(text)):
            if not candidate:
                continue
            try:
                data = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(data, dict):
                return data
        return None

    def normalize_probe_requests(
        self,
        probes: list[ProbeRequest],
        context: ContextBundle,
    ) -> list[ProbeRequest]:
        normalized: list[ProbeRequest] = []
        seen: set[tuple[str, str, str]] = set()
        for probe in probes:
            candidate = self._normalize_single_probe(probe, context)
            if candidate is None:
                continue
            prompt_text = self._extract_prompt_text(candidate.body)
            dedupe_key = (
                candidate.method.upper(),
                candidate.path,
                prompt_text.strip().lower(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            normalized.append(candidate)
        return normalized

    def execute_probes(
        self, probes: list[ProbeRequest], base_url: str, timeout: int = 10
    ) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for probe in probes:
                url = f"{base_url.rstrip('/')}{probe.path}"
                try:
                    response = client.request(
                        probe.method, url, json=probe.body, headers=probe.headers or {}
                    )
                    results.append(
                        ProbeResult(
                            specialist=probe.specialist,
                            method=probe.method,
                            path=probe.path,
                            request_body=probe.body,
                            status_code=response.status_code,
                            response_body=response.text[:_MAX_RESPONSE_BODY],
                            content_type=response.headers.get("content-type", ""),
                        )
                    )
                except Exception as exc:
                    results.append(
                        ProbeResult(
                            specialist=probe.specialist,
                            method=probe.method,
                            path=probe.path,
                            request_body=probe.body,
                            status_code=0,
                            response_body="",
                            content_type="",
                            error=str(exc),
                        )
                    )
        return results

    def call_llm(
        self,
        client: object,
        user_prompt: str,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 4096,
    ) -> str:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=self.system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    def build_prompt_probes(
        self,
        context: ContextBundle,
        prompts: list[str],
        *,
        preferred_paths: tuple[str, ...] | None = None,
    ) -> list[ProbeRequest]:
        built: list[ProbeRequest] = []
        seen: set[tuple[str, str, str]] = set()
        for prompt in prompts:
            probe = self._build_probe_for_prompt(
                context,
                prompt,
                preferred_paths=preferred_paths,
            )
            if probe is None:
                continue
            dedupe_key = (
                probe.method.upper(),
                probe.path,
                prompt.strip().lower(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            built.append(probe)
        return built

    def _extract_json_block(self, text: str) -> str:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return text[start : end + 1]
        return ""

    def _normalize_single_probe(
        self,
        probe: ProbeRequest,
        context: ContextBundle,
    ) -> ProbeRequest | None:
        method = (probe.method or "POST").upper()
        path = probe.path if isinstance(probe.path, str) and probe.path.startswith("/") else ""
        prompt_text = self._extract_prompt_text(probe.body)

        targets = self._candidate_targets(context, preferred_paths=self.preferred_path_keywords())
        if path and any(target["path"] == path and target["method"] == method for target in targets):
            body = probe.body
            if method in {"POST", "PUT", "PATCH"} and prompt_text:
                body = self._build_body_for_target(self._find_target(targets, method, path), prompt_text)
            return ProbeRequest(
                specialist=probe.specialist,
                method=method,
                path=path,
                body=body,
                headers=dict(probe.headers or {}),
                rationale=probe.rationale,
            )

        if not prompt_text:
            return None

        rebuilt = self._build_probe_for_prompt(
            context,
            prompt_text,
            preferred_paths=self.preferred_path_keywords(),
            rationale=probe.rationale,
        )
        if rebuilt is not None:
            rebuilt.headers.update(probe.headers or {})
        return rebuilt

    def _build_probe_for_prompt(
        self,
        context: ContextBundle,
        prompt_text: str,
        *,
        preferred_paths: tuple[str, ...] | None = None,
        rationale: str = "",
    ) -> ProbeRequest | None:
        targets = self._candidate_targets(context, preferred_paths=preferred_paths)
        if not targets:
            return ProbeRequest(
                specialist=self.name,
                method="POST",
                path="/api/v1/chat",
                body={"question": prompt_text},
                rationale=rationale or "Fallback generic probe",
            )

        target = targets[0]
        body = self._build_body_for_target(target, prompt_text)
        if target["method"] == "GET":
            body = None
        return ProbeRequest(
            specialist=self.name,
            method=target["method"],
            path=target["path"],
            body=body,
            rationale=rationale or f"Fallback probe against {target['path']}",
        )

    def _find_target(
        self,
        targets: list[dict[str, Any]],
        method: str,
        path: str,
    ) -> dict[str, Any]:
        for target in targets:
            if target["method"] == method and target["path"] == path:
                return target
        return targets[0]

    def _candidate_targets(
        self,
        context: ContextBundle,
        *,
        preferred_paths: tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        preferred_paths = preferred_paths or self.preferred_path_keywords()
        spec = context.openapi_spec if isinstance(context.openapi_spec, dict) else {}
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return []

        targets: list[dict[str, Any]] = []
        for path, methods in paths.items():
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            if "{" in path or "}" in path:
                continue
            for method, spec_for_method in methods.items():
                if not isinstance(spec_for_method, dict):
                    continue
                method_upper = str(method).upper()
                if method_upper not in {"POST", "PUT", "PATCH", "GET"}:
                    continue
                target = {
                    "path": path,
                    "method": method_upper,
                    "schema": self._request_schema(context, spec_for_method),
                }
                targets.append(target)

        def rank(target: dict[str, Any]) -> tuple[int, int]:
            path = str(target["path"]).lower()
            method = str(target["method"]).upper()
            score = 0
            if method == "POST":
                score += 50
            elif method in {"PUT", "PATCH"}:
                score += 20
            for idx, keyword in enumerate(preferred_paths):
                if keyword in path:
                    score += 40 - idx
            if "reset" in path or "delete" in path:
                score -= 100
            if self._target_accepts_prompt(target):
                score += 20
            return (score, -len(path))

        targets.sort(key=rank, reverse=True)
        return targets

    def _request_schema(
        self,
        context: ContextBundle,
        method_spec: dict[str, Any],
    ) -> dict[str, Any] | None:
        request_body = method_spec.get("requestBody")
        if not isinstance(request_body, dict):
            return None
        content = request_body.get("content")
        if not isinstance(content, dict):
            return None
        json_content = content.get("application/json")
        if not isinstance(json_content, dict):
            return None
        schema = json_content.get("schema")
        if not isinstance(schema, dict):
            return None
        return self._resolve_schema(context, schema)

    def _resolve_schema(
        self,
        context: ContextBundle,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        if "$ref" in schema and isinstance(schema["$ref"], str):
            ref = schema["$ref"]
            prefix = "#/components/schemas/"
            if ref.startswith(prefix):
                name = ref[len(prefix) :]
                components = (context.openapi_spec or {}).get("components", {})
                schemas = components.get("schemas", {}) if isinstance(components, dict) else {}
                resolved = schemas.get(name)
                if isinstance(resolved, dict):
                    return self._resolve_schema(context, resolved)
        if "anyOf" in schema and isinstance(schema["anyOf"], list):
            for option in schema["anyOf"]:
                if isinstance(option, dict) and option.get("type") != "null":
                    return self._resolve_schema(context, option)
        return schema

    def _target_accepts_prompt(self, target: dict[str, Any]) -> bool:
        schema = target.get("schema")
        if not isinstance(schema, dict):
            return target.get("method") == "GET"
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return False
        if "messages" in properties:
            return True
        return any(field in properties for field in _INTERACTIVE_FIELDS)

    def _build_body_for_target(self, target: dict[str, Any], prompt_text: str) -> dict[str, Any] | None:
        schema = target.get("schema")
        if not isinstance(schema, dict):
            return {"question": prompt_text}
        body = self._sample_from_schema(schema, prompt_text)
        if isinstance(body, dict) and body:
            return body
        return {"question": prompt_text}

    def _sample_from_schema(self, schema: dict[str, Any], prompt_text: str) -> Any:
        schema = schema or {}
        schema_type = schema.get("type")
        if schema_type == "object" or "properties" in schema:
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                return {}
            required = schema.get("required", [])
            required_fields = required if isinstance(required, list) else []
            data: dict[str, Any] = {}
            if "messages" in properties:
                data["messages"] = [{"role": "user", "content": prompt_text}]
            else:
                for field in _INTERACTIVE_FIELDS:
                    if field in properties:
                        data[field] = prompt_text
                        break
            for name, prop_schema in properties.items():
                if name in data:
                    continue
                if name in required_fields or not data:
                    if isinstance(prop_schema, dict):
                        data[name] = self._sample_value(prop_schema, prompt_text)
            return data
        return self._sample_value(schema, prompt_text)

    def _sample_value(self, schema: dict[str, Any], prompt_text: str) -> Any:
        if not isinstance(schema, dict):
            return prompt_text
        if "anyOf" in schema and isinstance(schema["anyOf"], list):
            for option in schema["anyOf"]:
                if isinstance(option, dict) and option.get("type") != "null":
                    return self._sample_value(option, prompt_text)
            return None
        if "$ref" in schema:
            return prompt_text
        schema_type = schema.get("type")
        if schema_type == "string":
            return prompt_text
        if schema_type == "integer":
            return 3
        if schema_type == "number":
            return 0.8
        if schema_type == "boolean":
            return True
        if schema_type == "array":
            items = schema.get("items", {})
            if isinstance(items, dict) and items.get("$ref", "").endswith("/Message"):
                return [{"role": "user", "content": prompt_text}]
            return [self._sample_value(items if isinstance(items, dict) else {}, prompt_text)]
        if schema_type == "object" or "properties" in schema:
            return self._sample_from_schema(schema, prompt_text)
        return prompt_text

    def _extract_prompt_text(self, body: Any) -> str:
        if isinstance(body, dict):
            for field in _INTERACTIVE_FIELDS:
                value = body.get(field)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            messages = body.get("messages")
            if isinstance(messages, list):
                for item in messages:
                    if isinstance(item, dict):
                        content = item.get("content")
                        if isinstance(content, str) and content.strip():
                            return content.strip()
            for value in body.values():
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""
