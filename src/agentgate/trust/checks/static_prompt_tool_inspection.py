from __future__ import annotations

import re
from pathlib import Path

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity


HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "hidden instruction token",
        re.compile(r"(hidden\s+instruction|ai_instruction|system\s*:)", re.IGNORECASE),
    ),
    (
        "prompt override phrase",
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    ),
    (
        "secret exfil directive",
        re.compile(r"(exfiltrate|send\s+.*api\s*key|steal\s+credentials)", re.IGNORECASE),
    ),
]


class StaticPromptToolInspectionCheck(BaseTrustCheck):
    check_id = "static_prompt_tool_inspection"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        source = ctx.source_dir
        if source is None or not source.exists():
            return [
                self.finding(
                    title="Source directory missing for prompt/tool inspection",
                    category=TrustCategory.HIDDEN_BEHAVIOR,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Static prompt/tool inspection requires --source-dir.",
                    recommendation="Provide source directory to enable hidden instruction detection.",
                    location_path=str(source) if source else "",
                )
            ]

        findings: list[TrustFinding] = []
        scanned = 0
        for path in _iter_source_files(source):
            scanned += 1
            text = path.read_text(errors="ignore")
            for label, pattern in HIDDEN_INSTRUCTION_PATTERNS:
                match = pattern.search(text)
                if not match:
                    continue
                findings.append(
                    self.finding(
                        title=f"Suspicious prompt/tool content ({label})",
                        category=TrustCategory.HIDDEN_BEHAVIOR,
                        severity=TrustSeverity.HIGH,
                        passed=False,
                        summary=f"Matched suspicious pattern: {pattern.pattern}",
                        recommendation="Review prompt/tool descriptions for hidden or adversarial control text.",
                        location_path=str(path),
                        location_line=text[: match.start()].count("\n") + 1,
                        observed=match.group(0),
                    )
                )

        if not findings:
            findings.append(
                self.finding(
                    title="No hidden prompt/tool directives detected",
                    category=TrustCategory.HIDDEN_BEHAVIOR,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary=f"Scanned {scanned} files for hidden instruction markers.",
                )
            )

        return findings


def _iter_source_files(source_dir: Path):
    suffixes = {".py", ".md", ".txt", ".yaml", ".yml", ".json"}
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in suffixes:
            continue
        if any(part.startswith(".") for part in path.parts):
            continue
        # Avoid very large binary-ish files accidentally matched by suffix
        if path.stat().st_size > 2_000_000:
            continue
        yield path
