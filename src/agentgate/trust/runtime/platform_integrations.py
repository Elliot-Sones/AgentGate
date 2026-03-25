from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from agentgate.trust.runtime.allowed_services import ALLOWED_SERVICES

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".mypy_cache",
    ".pytest_cache",
}

_TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".txt",
    ".md",
    ".ini",
    ".cfg",
}


@dataclass(frozen=True)
class PlatformIntegrationSpec:
    name: str
    env_map: dict[str, str]
    allow_domains: tuple[str, ...]
    required_env_names: tuple[str, ...]


SUPPORTED_PLATFORM_INTEGRATIONS: dict[str, PlatformIntegrationSpec] = {
    "openai": PlatformIntegrationSpec(
        name="openai",
        env_map={"OPENAI_API_KEY": "AGENTGATE_PLATFORM_OPENAI_API_KEY"},
        allow_domains=("api.openai.com",),
        required_env_names=("OPENAI_API_KEY",),
    ),
    "anthropic": PlatformIntegrationSpec(
        name="anthropic",
        env_map={"ANTHROPIC_API_KEY": "AGENTGATE_PLATFORM_ANTHROPIC_API_KEY"},
        allow_domains=("api.anthropic.com",),
        required_env_names=("ANTHROPIC_API_KEY",),
    ),
    "slack": PlatformIntegrationSpec(
        name="slack",
        env_map={
            "SLACK_BOT_TOKEN": "AGENTGATE_PLATFORM_SLACK_BOT_TOKEN",
            "SLACK_SIGNING_SECRET": "AGENTGATE_PLATFORM_SLACK_SIGNING_SECRET",
        },
        allow_domains=("slack.com", "api.slack.com"),
        required_env_names=("SLACK_BOT_TOKEN",),
    ),
    "shopify": PlatformIntegrationSpec(
        name="shopify",
        env_map={
            "SHOPIFY_API_KEY": "AGENTGATE_PLATFORM_SHOPIFY_API_KEY",
            "SHOPIFY_API_SECRET": "AGENTGATE_PLATFORM_SHOPIFY_API_SECRET",
            "SHOPIFY_ACCESS_TOKEN": "AGENTGATE_PLATFORM_SHOPIFY_ACCESS_TOKEN",
            "SHOPIFY_STORE_DOMAIN": "AGENTGATE_PLATFORM_SHOPIFY_STORE_DOMAIN",
        },
        allow_domains=("shopify.com", "myshopify.com"),
        required_env_names=("SHOPIFY_ACCESS_TOKEN", "SHOPIFY_STORE_DOMAIN"),
    ),
    "webhook": PlatformIntegrationSpec(
        name="webhook",
        env_map={"WEBHOOK_URL": "AGENTGATE_PLATFORM_WEBHOOK_URL"},
        allow_domains=(),
        required_env_names=("WEBHOOK_URL",),
    ),
}

_INTEGRATION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "openai": (
        re.compile(r"\bOPENAI_API_KEY\b"),
        re.compile(r"\bfrom openai\b", re.IGNORECASE),
        re.compile(r"\bimport openai\b", re.IGNORECASE),
    ),
    "anthropic": (
        re.compile(r"\bANTHROPIC_API_KEY\b"),
        re.compile(r"\bimport anthropic\b", re.IGNORECASE),
    ),
    "slack": (
        re.compile(r"\bSLACK_(?:BOT_TOKEN|SIGNING_SECRET)\b"),
        re.compile(r"\bslack_sdk\b", re.IGNORECASE),
    ),
    "shopify": (
        re.compile(r"\bSHOPIFY_[A-Z_]+\b"),
        re.compile(r"\bshopify\b", re.IGNORECASE),
        re.compile(r"\bmyshopify\.com\b", re.IGNORECASE),
    ),
    "webhook": (
        re.compile(r"\bWEBHOOK_URL\b"),
        re.compile(r"\bCALLBACK_URL\b"),
    ),
}


def infer_platform_integrations(
    source_dir: Path | None,
    manifest: dict | None = None,
) -> tuple[list[str], list[str], list[str]]:
    requested: set[str] = set()
    notes: list[str] = []

    if isinstance(manifest, dict):
        integrations = manifest.get("integrations")
        if isinstance(integrations, list):
            for integration in integrations:
                if not isinstance(integration, str):
                    continue
                normalized = integration.strip().lower()
                if not normalized:
                    continue
                if normalized in SUPPORTED_PLATFORM_INTEGRATIONS:
                    requested.add(normalized)
                elif normalized in ALLOWED_SERVICES:
                    continue
                elif normalized == "railway":
                    continue
                else:
                    return [], [normalized], [f"Unsupported declared integration '{normalized}'."]

    if source_dir is not None and source_dir.exists():
        for path in _iter_candidate_files(source_dir):
            text = _safe_read_text(path)
            if not text:
                continue
            rel = str(path.relative_to(source_dir))
            for name, patterns in _INTEGRATION_PATTERNS.items():
                if name in requested:
                    continue
                if any(pattern.search(text) for pattern in patterns):
                    requested.add(name)
                    notes.append(f"Inferred integration '{name}' from {rel}.")

    supported = [name for name in SUPPORTED_PLATFORM_INTEGRATIONS if name in requested]
    unsupported = [name for name in requested if name not in SUPPORTED_PLATFORM_INTEGRATIONS]
    return supported, unsupported, notes


def issue_platform_credentials(
    integrations: list[str],
) -> tuple[dict[str, str], list[str], list[str]]:
    issued_env: dict[str, str] = {}
    missing: list[str] = []
    issued: list[str] = []

    for integration in integrations:
        spec = SUPPORTED_PLATFORM_INTEGRATIONS.get(integration)
        if spec is None:
            missing.append(integration)
            continue
        resolved: dict[str, str] = {}
        unresolved = False
        for runtime_key, platform_env in spec.env_map.items():
            value = os.environ.get(platform_env, "").strip()
            if value:
                resolved[runtime_key] = value
        for required in spec.required_env_names:
            if required not in resolved:
                unresolved = True
                break
        if unresolved:
            missing.append(integration)
            continue
        issued_env.update(resolved)
        issued.append(integration)

    return issued_env, issued, missing


def platform_allow_domains(integrations: list[str], issued_env: dict[str, str]) -> set[str]:
    domains: set[str] = set()
    for integration in integrations:
        spec = SUPPORTED_PLATFORM_INTEGRATIONS.get(integration)
        if spec is None:
            continue
        domains.update(spec.allow_domains)
        if integration == "webhook":
            webhook_url = issued_env.get("WEBHOOK_URL", "")
            if webhook_url:
                domains.add(re.sub(r"^https?://", "", webhook_url).split("/")[0].lower())
    return {domain for domain in domains if domain}


def _iter_candidate_files(source_dir: Path):
    count = 0
    for path in source_dir.rglob("*"):
        if count >= 250:
            break
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name not in {
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "requirements.txt",
            "pyproject.toml",
        }:
            continue
        count += 1
        yield path


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""
