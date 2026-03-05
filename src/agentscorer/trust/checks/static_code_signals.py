from __future__ import annotations

import re

from agentscorer.trust.checks.base import BaseTrustCheck
from agentscorer.trust.context import TrustScanContext
from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity


PATTERNS: list[tuple[str, TrustSeverity, re.Pattern[str]]] = [
    ("dynamic exec/eval", TrustSeverity.HIGH, re.compile(r"\b(exec|eval)\s*\(", re.IGNORECASE)),
    (
        "shell command execution",
        TrustSeverity.HIGH,
        re.compile(r"subprocess\.(run|Popen)\(.*shell\s*=\s*True", re.IGNORECASE),
    ),
    (
        "outbound HTTP call",
        TrustSeverity.MEDIUM,
        re.compile(r"requests\.(post|get|put|patch)\(", re.IGNORECASE),
    ),
    (
        "base64 decode use",
        TrustSeverity.LOW,
        re.compile(r"base64\.(b64decode|urlsafe_b64decode)\(", re.IGNORECASE),
    ),
]


class StaticCodeSignalsCheck(BaseTrustCheck):
    check_id = "static_code_signals"

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        source = ctx.source_dir
        if source is None or not source.exists():
            return [
                self.finding(
                    title="Source directory missing for code signal scan",
                    category=TrustCategory.HIDDEN_BEHAVIOR,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Code signal scanning requires --source-dir.",
                    recommendation="Provide source directory to run static code checks.",
                )
            ]

        findings: list[TrustFinding] = []
        scanned = 0

        for path in source.rglob("*.py"):
            if not path.is_file():
                continue
            if any(part.startswith(".") for part in path.parts):
                continue
            scanned += 1
            text = path.read_text(errors="ignore")
            for label, severity, pattern in PATTERNS:
                for match in pattern.finditer(text):
                    findings.append(
                        self.finding(
                            title=f"Suspicious code signal: {label}",
                            category=TrustCategory.HIDDEN_BEHAVIOR,
                            severity=severity,
                            passed=False,
                            summary=f"Pattern matched: {pattern.pattern}",
                            recommendation="Review necessity and constrain risky execution/network behavior.",
                            location_path=str(path),
                            location_line=text[: match.start()].count("\n") + 1,
                            observed=match.group(0),
                        )
                    )

        if not findings:
            findings.append(
                self.finding(
                    title="No suspicious code signals detected",
                    category=TrustCategory.HIDDEN_BEHAVIOR,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary=f"Scanned {scanned} Python files with no risky pattern matches.",
                )
            )

        return findings
