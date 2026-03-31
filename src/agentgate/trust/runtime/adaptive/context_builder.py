from __future__ import annotations

import json
import re
from pathlib import Path

from agentgate.trust.runtime.adaptive.models import ContextBundle, ProbeRequest

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

_ROUTE_DECORATOR_RE = re.compile(r'@(?:app|router)\.(get|post|put|patch|delete)\(["\']([^"\']+)["\']')
_ADD_API_ROUTE_RE = re.compile(
    r'add_api_route\(\s*["\']([^"\']+)["\']\s*,\s*methods=\[([^\]]+)\]',
    re.IGNORECASE,
)
_OPENAPI_METHOD_PRIORITY = ("GET", "POST", "PUT", "PATCH", "DELETE")
_ROUTE_HINTS = (
    "chat",
    "search",
    "query",
    "ask",
    "message",
    "completion",
    "invoke",
    "run",
    "agent",
    "tool",
    "health",
    "status",
)


class ContextBuilder:
    @staticmethod
    def build(
        source_dir: Path | None,
        manifest: dict | None,
        static_findings: list[str],
        live_url: str,
        canary_tokens: dict[str, str],
        probe_responses: list[dict] | None = None,
        prior_specialist_findings: list[dict] | None = None,
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
            prior_specialist_findings=list(prior_specialist_findings or []),
        )

    @staticmethod
    def build_specialist_bundle(bundle: ContextBundle, specialist: str) -> ContextBundle:
        """Return a specialist-scoped bundle that keeps the shared scan metadata intact."""
        return ContextBundle(
            source_files=ContextBuilder.slice_for_specialist(bundle.source_files, specialist),
            manifest=bundle.manifest,
            static_findings=list(bundle.static_findings),
            live_url=bundle.live_url,
            canary_tokens=dict(bundle.canary_tokens),
            declared_tools=list(bundle.declared_tools),
            declared_domains=list(bundle.declared_domains),
            customer_data_access=list(bundle.customer_data_access),
            permissions=list(bundle.permissions),
            openapi_spec=bundle.openapi_spec,
            prior_specialist_findings=list(bundle.prior_specialist_findings),
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

    @staticmethod
    def discover_health_probe_requests(
        context: ContextBundle,
        *,
        max_candidates: int = 3,
    ) -> list[ProbeRequest]:
        candidates = _discover_route_candidates(context)
        if not candidates:
            candidates = [
                ProbeRequest(
                    specialist="health_gate",
                    method="POST",
                    path="/api/v1/chat",
                    body={"question": "health check"},
                    rationale="Fallback route discovery",
                ),
                ProbeRequest(
                    specialist="health_gate",
                    method="GET",
                    path="/health",
                    rationale="Fallback health probe",
                ),
            ]
        return candidates[:max_candidates]

    @staticmethod
    def has_memory_surface(source_files: dict[str, str], manifest: dict | None) -> bool:
        haystack = "\n".join(source_files.values()).lower()
        if isinstance(manifest, dict):
            haystack += "\n" + json.dumps(manifest, sort_keys=True).lower()
        keywords = (
            "mem0",
            "memory",
            "session",
            "redis",
            "vector store",
            "vectorstore",
            "checkpoint",
            "persist",
            "state",
        )
        return any(keyword in haystack for keyword in keywords)


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


def _discover_route_candidates(context: ContextBundle) -> list[ProbeRequest]:
    scored: list[tuple[tuple[int, int, str, str], ProbeRequest]] = []
    if isinstance(context.openapi_spec, dict):
        paths = context.openapi_spec.get("paths", {})
        if isinstance(paths, dict):
            for path, methods in paths.items():
                if not isinstance(path, str) or not isinstance(methods, dict):
                    continue
                for method in _OPENAPI_METHOD_PRIORITY:
                    if method.lower() not in methods:
                        continue
                    scored.append((
                        (_route_score(path), _method_score(method), path, method),
                        _build_probe_request(path, method),
                    ))

    if not scored:
        for path, method in _discover_source_routes(context.source_files).items():
            scored.append((
                (_route_score(path), _method_score(method), path, method),
                _build_probe_request(path, method),
            ))

    if not scored:
        return []

    scored.sort(key=lambda item: item[0])
    deduped: list[ProbeRequest] = []
    seen: set[tuple[str, str]] = set()
    for _, probe in scored:
        key = (probe.method.upper(), probe.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(probe)
    return deduped


def _discover_source_routes(source_files: dict[str, str]) -> dict[str, str]:
    routes: dict[str, str] = {}
    for content in source_files.values():
        for match in _ROUTE_DECORATOR_RE.finditer(content):
            routes.setdefault(match.group(2), match.group(1).upper())
        for match in _ADD_API_ROUTE_RE.finditer(content):
            path = match.group(1)
            methods = match.group(2)
            method_match = re.search(r'"["\']([A-Za-z]+)["\']', methods)
            method = method_match.group(1).upper() if method_match else "GET"
            routes.setdefault(path, method)
    return routes


def _route_score(path: str) -> int:
    normalized = path.lower().strip()
    if normalized in {"/", ""}:
        return 100
    if any(hint in normalized for hint in ("chat", "search", "query", "ask", "message", "completion")):
        return 0
    if any(hint in normalized for hint in ("invoke", "run", "agent", "tool")):
        return 5
    if any(hint in normalized for hint in ("health", "status", "ready", "ping")):
        return 25
    return 15


def _method_score(method: str) -> int:
    upper = method.upper()
    if upper in {"POST", "GET"}:
        return 0
    if upper in {"PUT", "PATCH"}:
        return 1
    return 2


def _build_probe_request(path: str, method: str) -> ProbeRequest:
    body: dict | None = None
    upper = method.upper()
    if upper in {"POST", "PUT", "PATCH"}:
        body = {"question": "health check"}
        if any(hint in path.lower() for hint in ("search", "query")):
            body = {"query": "health check"}
        elif any(hint in path.lower() for hint in ("message", "chat", "ask", "completion")):
            body = {"question": "health check"}
        elif any(hint in path.lower() for hint in ("run", "invoke", "agent", "tool")):
            body = {"input": "health check"}
    return ProbeRequest(
        specialist="health_gate",
        method=upper,
        path=path,
        body=body,
        rationale="Discovered application route",
    )
