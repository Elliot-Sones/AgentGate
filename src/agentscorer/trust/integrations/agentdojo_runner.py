from __future__ import annotations

import json
import logging
from pathlib import Path

from agentscorer.trust.models import TrustCategory, TrustFinding, TrustSeverity

logger = logging.getLogger(__name__)


class AgentDojoRunner:
    """Optional bridge for trust scenarios defined in AgentDojo suites."""

    def run(self, suite_path: Path | None) -> list[TrustFinding]:
        if suite_path is None:
            return []

        if not suite_path.exists():
            return [
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="AgentDojo suite path not found",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=f"Configured AgentDojo suite path does not exist: {suite_path}",
                    recommendation="Provide a valid suite file/directory or omit --agentdojo-suite.",
                    location_path=str(suite_path),
                )
            ]

        try:
            __import__("agentdojo")
        except Exception:
            return [
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="AgentDojo package unavailable but suite requested",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=(
                        "AgentDojo suite was explicitly requested via --agentdojo-suite "
                        "but the agentdojo package is not installed."
                    ),
                    recommendation="Install agentdojo to enable benchmark-backed trust scenarios.",
                    location_path=str(suite_path),
                )
            ]

        return self._execute_suite(suite_path)

    def _execute_suite(self, suite_path: Path) -> list[TrustFinding]:
        """Load and execute an AgentDojo benchmark suite."""
        suite_config = self._load_suite_config(suite_path)
        if suite_config is None:
            return [
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="Failed to load AgentDojo suite config",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=f"Could not parse suite configuration at: {suite_path}",
                    recommendation="Ensure the suite file is valid JSON or YAML.",
                    location_path=str(suite_path),
                )
            ]

        suite_name = suite_config.get("suite", "")
        task_filter = suite_config.get("tasks")  # optional list of task IDs

        # Import agentdojo API at point-of-use with defensive wrapping
        try:
            from agentdojo.default_suites import get_suite  # type: ignore
        except (ImportError, AttributeError):
            return [
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="AgentDojo API mismatch",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.LOW,
                    passed=False,
                    summary="Could not import agentdojo.default_suites.get_suite — API may have changed.",
                    recommendation="Upgrade agentdojo to a compatible version.",
                    location_path=str(suite_path),
                )
            ]

        try:
            suite = get_suite(suite_name)
        except Exception as exc:
            return [
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="AgentDojo suite not found",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.MEDIUM,
                    passed=False,
                    summary=f"Suite '{suite_name}' could not be loaded: {exc}",
                    recommendation="Check suite name in config file and available agentdojo suites.",
                    location_path=str(suite_path),
                )
            ]

        # Collect injectable tasks
        try:
            tasks = list(suite.injectable_tasks)  # type: ignore
        except AttributeError:
            try:
                tasks = list(suite.tasks)  # type: ignore
            except AttributeError:
                return [
                    TrustFinding(
                        check_id="agentdojo_integration",
                        title="AgentDojo API mismatch (tasks)",
                        category=TrustCategory.SANDBOX_EVASION,
                        severity=TrustSeverity.LOW,
                        passed=False,
                        summary="Suite object lacks 'injectable_tasks' or 'tasks' attribute.",
                        recommendation="Upgrade agentdojo to a compatible version.",
                        location_path=str(suite_path),
                    )
                ]

        # Filter tasks if config specifies a subset
        if task_filter:
            filter_set = set(task_filter)
            tasks = [t for t in tasks if getattr(t, "id", getattr(t, "task_id", None)) in filter_set]

        findings: list[TrustFinding] = []
        for task in tasks:
            task_id = getattr(task, "id", getattr(task, "task_id", "unknown"))
            try:
                result = suite.run_task(task_id)  # type: ignore
                attack_succeeded = getattr(result, "attack_succeeded", False)
                if attack_succeeded:
                    findings.append(
                        TrustFinding(
                            check_id="agentdojo_integration",
                            title=f"AgentDojo attack succeeded: {task_id}",
                            category=TrustCategory.SANDBOX_EVASION,
                            severity=TrustSeverity.HIGH,
                            passed=False,
                            summary=f"Task '{task_id}' attack succeeded — agent was manipulated.",
                            recommendation="Review agent defenses against injection and manipulation.",
                            location_path=str(suite_path),
                            observed=f"attack_succeeded=True for task {task_id}",
                        )
                    )
                else:
                    findings.append(
                        TrustFinding(
                            check_id="agentdojo_integration",
                            title=f"AgentDojo task passed: {task_id}",
                            category=TrustCategory.SANDBOX_EVASION,
                            severity=TrustSeverity.INFO,
                            passed=True,
                            summary=f"Task '{task_id}' completed without attack success.",
                            location_path=str(suite_path),
                        )
                    )
            except Exception as exc:
                logger.warning("AgentDojo task %s failed: %s", task_id, exc)
                findings.append(
                    TrustFinding(
                        check_id="agentdojo_integration",
                        title=f"AgentDojo task error: {task_id}",
                        category=TrustCategory.SANDBOX_EVASION,
                        severity=TrustSeverity.LOW,
                        passed=False,
                        summary=f"Task '{task_id}' raised an error: {exc}",
                        recommendation="Check agentdojo compatibility and task configuration.",
                        location_path=str(suite_path),
                    )
                )

        if not findings:
            findings.append(
                TrustFinding(
                    check_id="agentdojo_integration",
                    title="AgentDojo suite completed with no tasks",
                    category=TrustCategory.SANDBOX_EVASION,
                    severity=TrustSeverity.INFO,
                    passed=True,
                    summary="Suite was loaded but contained no matching tasks.",
                    location_path=str(suite_path),
                )
            )

        return findings

    def _load_suite_config(self, suite_path: Path) -> dict | None:
        """Parse a suite config file (JSON or YAML)."""
        text = suite_path.read_text().strip()
        if not text:
            return None

        # Try JSON first
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        # Try YAML via optional dependency
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

        return None
