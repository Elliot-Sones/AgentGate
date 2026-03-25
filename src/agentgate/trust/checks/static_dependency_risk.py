from __future__ import annotations

import re
import shutil
import tomllib
from pathlib import Path

from agentgate.trust.checks.base import BaseTrustCheck
from agentgate.trust.context import TrustScanContext
from agentgate.trust.models import TrustCategory, TrustFinding, TrustSeverity


SUSPICIOUS_PACKAGE_NAMES = {
    "request",
    "reqeusts",
    "urlib3",
    "pyyaml-loader",
    "setup-tools",
    "opena1",
    "anthr0pic",
}


class StaticDependencyRiskCheck(BaseTrustCheck):
    check_id = "static_dependency_risk"
    description = "Checks Python dependencies for known malicious or vulnerable packages."

    async def run(self, ctx: TrustScanContext) -> list[TrustFinding]:
        source = ctx.source_dir
        if source is None or not source.exists():
            return [
                self.finding(
                    title="Source directory missing for dependency scan",
                    category=TrustCategory.SUPPLY_CHAIN,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Dependency risk checks require --source-dir.",
                    recommendation="Provide source directory and dependency files.",
                )
            ]

        findings: list[TrustFinding] = []

        lockfiles = [
            source / "uv.lock",
            source / "poetry.lock",
            source / "Pipfile.lock",
            source / "requirements.txt",
            source / "requirements-dev.txt",
        ]
        present_lockfiles = [p for p in lockfiles if p.exists()]
        if not present_lockfiles:
            findings.append(
                self.finding(
                    title="No lockfile or requirements file detected",
                    category=TrustCategory.SUPPLY_CHAIN,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary="Submission did not include common dependency lock files.",
                    recommendation="Provide pinned dependency lock file for reproducible and auditable builds.",
                )
            )

        deps = _collect_dependency_names(source)
        for dep in sorted(deps):
            if dep in SUSPICIOUS_PACKAGE_NAMES:
                findings.append(
                    self.finding(
                        title=f"Potential typosquat dependency: {dep}",
                        category=TrustCategory.SUPPLY_CHAIN,
                        severity=TrustSeverity.HIGH,
                        passed=False,
                        summary=f"Dependency '{dep}' matched suspicious package name list.",
                        recommendation="Manually review package provenance and replace with trusted package.",
                    )
                )

        for tool in ("syft", "trivy", "grype", "pip-audit", "osv-scanner"):
            if shutil.which(tool) is None:
                findings.append(
                    self.finding(
                        title=f"Optional supply-chain tool unavailable: {tool}",
                        category=TrustCategory.SUPPLY_CHAIN,
                        severity=TrustSeverity.INFO,
                        passed=True,
                        summary=f"Tool '{tool}' not found in PATH; deep scanner step skipped.",
                        recommendation="Install optional scanner for stronger dependency coverage.",
                    )
                )

        if not any(not f.passed for f in findings):
            findings.append(
                self.finding(
                    title="Dependency risk checks passed",
                    category=TrustCategory.SUPPLY_CHAIN,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary=f"Scanned {len(deps)} dependency identifiers with no high-confidence malicious matches.",
                )
            )

        return findings


def _collect_dependency_names(source: Path) -> set[str]:
    names: set[str] = set()

    # Parse requirements.txt files with regex
    req_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
    for req_file in ("requirements.txt", "requirements-dev.txt"):
        path = source / req_file
        if not path.exists() or not path.is_file():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            if not line.strip() or line.strip().startswith("#") or line.strip().startswith("-"):
                continue
            match = req_re.match(line)
            if match:
                names.add(match.group(1).lower())

    # Parse pyproject.toml with proper TOML parser
    pyproject = source / "pyproject.toml"
    if pyproject.exists() and pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(errors="ignore"))
            # [project] dependencies
            for dep in data.get("project", {}).get("dependencies", []):
                name = re.split(r"[>=<!\[;@\s]", dep, maxsplit=1)[0].strip()
                if name:
                    names.add(name.lower())
            # [project.optional-dependencies]
            for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
                for dep in group_deps:
                    name = re.split(r"[>=<!\[;@\s]", dep, maxsplit=1)[0].strip()
                    if name:
                        names.add(name.lower())
        except Exception:
            pass  # Fall through if TOML is malformed

    # Parse setup.py with regex (best-effort)
    setup_py = source / "setup.py"
    if setup_py.exists() and setup_py.is_file():
        for line in setup_py.read_text(errors="ignore").splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            match = req_re.match(line)
            if match:
                token = match.group(1).lower()
                if token not in {"import", "from", "def", "class", "if", "for", "return", "name",
                                 "version", "description", "setup", "find_packages", "install_requires"}:
                    names.add(token)

    return names
