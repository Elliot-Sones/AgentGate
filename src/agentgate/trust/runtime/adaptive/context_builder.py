from __future__ import annotations

import json
from pathlib import Path

from agentgate.trust.runtime.adaptive.models import ContextBundle

_SOURCE_EXTENSIONS = {".py", ".yaml", ".yml", ".toml", ".cfg", ".txt", ".json"}
_MAX_FILE_SIZE = 50_000

_SPECIALIST_KEYWORDS: dict[str, list[str]] = {
    "tool_exerciser": [
        "def ",
        "async def ",
        "@app.",
        "route",
        "endpoint",
        "tool",
        "process",
        "handle",
        "query",
        "search",
        "lookup",
        "TOOL_CALL",
    ],
    "egress_prober": [
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "urlopen",
        "fetch",
        "http://",
        "https://",
        ".get(",
        ".post(",
    ],
    "data_boundary": [
        "customer",
        "user",
        "tenant",
        "auth",
        "session",
        "token",
        "password",
        "secret",
        "private",
        "data_access",
        "permission",
        "os.environ",
        "getenv",
    ],
    "canary_stresser": [
        "os.environ",
        "getenv",
        "environ",
        "secret",
        "key",
        "token",
        "password",
        "credential",
        "api_key",
        "bearer",
    ],
    "behavior_consistency": [
        "if ",
        "mode",
        "debug",
        "test",
        "review",
        "prod",
        "environment",
        "flag",
        "feature",
        "toggle",
        "conditional",
    ],
}


class ContextBuilder:
    @staticmethod
    def build(
        source_dir: Path | None,
        manifest: dict | None,
        static_findings: list[str],
        live_url: str,
        canary_tokens: dict[str, str],
        probe_responses: list[dict] | None = None,
    ) -> ContextBundle:
        source_files: dict[str, str] = {}
        if source_dir is not None and source_dir.is_dir():
            for path in sorted(source_dir.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix not in _SOURCE_EXTENSIONS:
                    continue
                if path.stat().st_size > _MAX_FILE_SIZE:
                    continue
                try:
                    content = path.read_text(errors="replace")
                except Exception:
                    continue
                relative = str(path.relative_to(source_dir))
                source_files[relative] = content

        declared_tools: list[str] = []
        declared_domains: list[str] = []
        customer_data_access: list[str] = []
        permissions: list[str] = []

        if isinstance(manifest, dict):
            declared_tools = _str_list(manifest.get("declared_tools"))
            declared_domains = _str_list(manifest.get("declared_external_domains"))
            customer_data_access = _str_list(manifest.get("customer_data_access"))
            permissions = _str_list(manifest.get("permissions"))

        openapi_spec = _extract_openapi(probe_responses or [])

        return ContextBundle(
            source_files=source_files,
            manifest=manifest,
            static_findings=static_findings,
            live_url=live_url,
            canary_tokens=canary_tokens,
            declared_tools=declared_tools,
            declared_domains=declared_domains,
            customer_data_access=customer_data_access,
            permissions=permissions,
            openapi_spec=openapi_spec,
        )

    @staticmethod
    def slice_for_specialist(
        source_files: dict[str, str],
        specialist: str,
    ) -> dict[str, str]:
        keywords = _SPECIALIST_KEYWORDS.get(specialist, [])
        if not keywords:
            return dict(source_files)

        scored: list[tuple[str, str, int]] = []
        for filename, content in source_files.items():
            score = sum(1 for kw in keywords if kw in content)
            scored.append((filename, content, score))

        scored.sort(key=lambda x: x[2], reverse=True)
        return {filename: content for filename, content, _ in scored}


def _str_list(val: object) -> list[str]:
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _extract_openapi(probe_responses: list[dict]) -> dict | None:
    for response in probe_responses:
        if (
            response.get("path") == "/openapi.json"
            and response.get("status_code") == 200
        ):
            payload = response.get("body_full") or response.get("body_snippet")
            if not payload:
                continue
            try:
                spec = json.loads(payload)
                if isinstance(spec, dict) and "openapi" in spec:
                    return spec
            except (json.JSONDecodeError, TypeError):
                pass
    return None
