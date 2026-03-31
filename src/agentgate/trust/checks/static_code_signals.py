from __future__ import annotations

import re

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity
from agentgate.trust.normalizer import TrustSignal, normalize_finding


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
    (
        "dynamic import via __import__",
        TrustSeverity.HIGH,
        re.compile(r"__import__\s*\("),
    ),
    (
        "dynamic import via importlib",
        TrustSeverity.HIGH,
        re.compile(r"importlib\.import_module\s*\("),
    ),
    (
        "direct shell execution via os.system",
        TrustSeverity.HIGH,
        re.compile(r"os\.system\s*\("),
    ),
    (
        "raw socket connection",
        TrustSeverity.MEDIUM,
        re.compile(r"socket\.connect\s*\("),
    ),
    (
        "stdlib HTTP call via urllib",
        TrustSeverity.MEDIUM,
        re.compile(r"urllib\.request\.urlopen\s*\("),
    ),
]


class StaticCodeSignalsCheck(BaseTrustCheck):
    check_id = "static_code_signals"
    description = "Scans source code for obfuscation, anti-analysis, and suspicious patterns."

    def scan_signals(self, ctx: TrustScanContext) -> list[TrustSignal]:
        source = ctx.source_dir
        if source is None or not source.exists():
            return []

        signals: list[TrustSignal] = []
        for path in source.rglob("*.py"):
            if not path.is_file():
                continue
            relative = path.relative_to(source)
            if any(part.startswith(".") for part in relative.parts):
                continue

            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue

            lines = text.splitlines()
            for label, severity, pattern in PATTERNS:
                for match in pattern.finditer(text):
                    line_no = text[: match.start()].count("\n") + 1
                    line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else match.group(0)
                    signals.append(
                        TrustSignal(
                            check_id=self.check_id,
                            signal_type="pattern_match",
                            title=f"Suspicious code signal: {label}",
                            summary=(
                                f"Pattern matched: {pattern.pattern} in {relative.as_posix()}:{line_no}"
                            ),
                            raw_evidence=line[:200],
                            detection_method="heuristic",
                            source_location=f"{relative.as_posix()}:{line_no}",
                            base_severity=severity,
                            category=TrustCategory.HIDDEN_BEHAVIOR,
                            recommendation="Review necessity and constrain risky execution/network behavior.",
                        )
                    )
        return signals

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

        signals = self.scan_signals(ctx)
        findings: list[TrustFinding] = []
        file_map = getattr(ctx, "file_classification_map", None) or getattr(
            ctx, "file_classification", {}
        ) or {}
        reachability_map = getattr(ctx, "reachability_graph", {}) or {}

        if signals:
            for signal in signals:
                findings.append(
                    normalize_finding(
                        signal,
                        file_map=file_map,
                        reachability_map=reachability_map,
                    )
                )
            return findings

        scanned = 0
        for path in source.rglob("*.py"):
            if path.is_file() and not any(part.startswith(".") for part in path.relative_to(source).parts):
                scanned += 1

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
