from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from agentgate.adapters.base import AgentAdapter
from agentgate.adapters.http import HTTPAdapter
from agentgate.attacker.adaptive import ATTACK_OBJECTIVES, AdaptiveAttacker
from agentgate.progress import ScanProgressDisplay
from agentgate.attacker.agent import AttackerAgent
from agentgate.attacker.strategies import STRATEGY_REGISTRY
from agentgate.config import ScanConfig
from agentgate.detectors import DETECTOR_REGISTRY
from agentgate.models.agent import AgentConfig
from agentgate.models.result import TestResult
from agentgate.models.score import ScoreCard
from agentgate.models.test_case import AttackVector, TestCase
from agentgate.scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)

# Maps AttackVector enum values to detector registry keys (identity mapping).
ATTACK_VECTOR_TO_DETECTOR: dict[str, str] = {
    "prompt_injection": "prompt_injection",
    "system_prompt_leak": "system_prompt_leak",
    "data_exfiltration": "data_exfiltration",
    "hallucination": "hallucination",
    "input_validation": "input_validation",
    "tool_misuse": "tool_misuse",
    "goal_hijacking": "goal_hijacking",
    "xpia": "xpia",
    "harmful_content": "harmful_content",
    "policy_violation": "policy_violation",
    "reliability": "reliability",
    "scope_adherence": "scope_adherence",
}


class ProbeError(Exception):
    """Raised when the initial probe of the target agent fails."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        target_url: str = "",
        response_excerpt: str = "",
        headers: dict[str, str] | None = None,
        reachable_before_timeout: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.target_url = target_url
        self.response_excerpt = response_excerpt
        self.headers = headers or {}
        self.reachable_before_timeout = reachable_before_timeout


@dataclass
class ScanResult:
    """Container for complete scan output."""

    scorecard: ScoreCard
    results_by_detector: dict[str, list[TestResult]]
    duration: float
    errors: dict[str, str] = field(default_factory=dict)


class Scanner:
    """Orchestrates the full scanning pipeline."""

    def __init__(
        self,
        agent_config: AgentConfig,
        scan_config: ScanConfig,
        adapter: AgentAdapter | None = None,
        progress: ScanProgressDisplay | None = None,
    ) -> None:
        self.agent_config = agent_config
        self.scan_config = scan_config
        self._adapter = adapter
        self._progress = progress

    async def _probe(self, adapter: AgentAdapter) -> None:
        """Send a health-check message before scanning.

        Raises ProbeError if the agent is unreachable or returns an error.
        """
        start = time.monotonic()
        try:
            response = await adapter.send("hello")
            self.scan_config.budget.record_agent_call()
        except Exception as exc:
            raise ProbeError(f"Connection error: {exc}") from exc

        elapsed_ms = (time.monotonic() - start) * 1000

        if response.error:
            raise ProbeError(f"Agent returned error: {response.error}")
        if response.status_code >= 400:
            raise ProbeError(f"Agent returned HTTP {response.status_code}: {response.text[:200]}")
        if not response.text.strip():
            raise ProbeError("Agent returned an empty response")

        logger.info(
            "Probe OK: status=%d, length=%d, time=%.0fms",
            response.status_code,
            len(response.text),
            elapsed_ms,
        )

    async def _generate_attacker_tests(
        self, detector_names: list[str]
    ) -> dict[str, list[TestCase]]:
        """Generate LLM-crafted attack test cases and route them to detectors.

        Returns a mapping of ``{detector_name: [TestCase, ...]}``.
        Skips silently if the API key is missing or budget is exhausted.
        """
        if not self.scan_config.anthropic_api_key:
            return {}
        if not self.scan_config.budget.can_call_attacker():
            return {}

        try:
            attacker = AttackerAgent(self.scan_config)
            test_cases = await attacker.generate_tests(self.agent_config)
        except Exception:
            logger.warning("AttackerAgent failed, skipping", exc_info=True)
            return {}

        routed: dict[str, list[TestCase]] = {}
        for tc in test_cases:
            detector_key = ATTACK_VECTOR_TO_DETECTOR.get(tc.attack_vector.value)
            if detector_key and detector_key in detector_names:
                routed.setdefault(detector_key, []).append(tc)

        logger.info(
            "AttackerAgent generated %d test cases across %d detectors",
            len(test_cases),
            len(routed),
        )
        return routed

    async def _run_adaptive_attacks(
        self,
        adapter: AgentAdapter,
        detector,
        attack_vector: AttackVector,
    ) -> list[TestResult]:
        """Run PAIR-style adaptive attacks for a single detector.

        Returns evaluated results. Skips silently if disabled or no budget.
        """
        if not self.scan_config.enable_adaptive_attacks:
            return []
        if not self.scan_config.anthropic_api_key:
            return []
        if not self.scan_config.budget.can_call_attacker():
            return []

        objective = ATTACK_OBJECTIVES.get(attack_vector, "")
        if not objective:
            return []

        strategy_name = self.scan_config.attack_strategy
        try:
            if strategy_name in STRATEGY_REGISTRY:
                strategy = STRATEGY_REGISTRY[strategy_name](self.scan_config)
                attack_result = await strategy.execute(
                    adapter=adapter,
                    objective=objective,
                    attack_vector=attack_vector,
                    agent_description=self.agent_config.description,
                    max_turns=self.scan_config.adaptive_max_turns,
                )
            else:
                attacker = AdaptiveAttacker(self.scan_config)
                attack_result = await attacker.attack(
                    adapter=adapter,
                    objective=objective,
                    attack_vector=attack_vector,
                    agent_description=self.agent_config.description,
                    max_turns=self.scan_config.adaptive_max_turns,
                )
        except Exception:
            logger.warning("Adaptive attack failed for %s", attack_vector.value, exc_info=True)
            return []

        if not attack_result.responses:
            return []

        # Evaluate the attack results through the detector
        tc = attack_result.test_case
        tc_results = detector.evaluate(tc, attack_result.responses)
        for r in tc_results:
            r.test_name = tc.name
            r.input_payload = tc.payload

        tc_lookup = {tc.id: tc}
        tc_results = await detector._refine_with_judge(tc_results, tc_lookup)
        return tc_results

    async def _run_attacker_tests(self, detector, test_cases: list[TestCase]) -> list[TestResult]:
        """Execute and evaluate attacker-generated tests through a detector."""
        executed = await detector.execute(test_cases)
        results: list[TestResult] = []
        test_case_lookup = {tc.id: tc for tc in test_cases}
        for test_case, responses in executed:
            tc_results = detector.evaluate(test_case, responses)
            for r in tc_results:
                r.test_name = test_case.name
                r.input_payload = test_case.payload
            results.extend(tc_results)

        # Apply judge refinement for consistency with static tests
        results = await detector._refine_with_judge(results, test_case_lookup)
        return results

    async def _run_single_detector(
        self,
        name: str,
        adapter: AgentAdapter,
        attacker_tests: dict[str, list[TestCase]],
    ) -> tuple[str, list[TestResult], str | None]:
        """Run a single detector end-to-end. Returns (name, results, error)."""
        detector_cls = DETECTOR_REGISTRY[name]
        detector = detector_cls(adapter=adapter, config=self.scan_config)

        if self._progress is not None:
            self._progress.mark_running(name)
            detector._on_test_progress = lambda done, total: self._progress.update_tests(
                name, done, total=total
            )

        try:
            detector_results = await detector.run(self.agent_config, detector_name=name)

            # Run attacker-generated tests for this detector
            extra_tests = attacker_tests.get(name, [])
            if extra_tests:
                attacker_results = await self._run_attacker_tests(detector, extra_tests)
                detector_results.extend(attacker_results)

            # Run adaptive PAIR-style attacks
            vector = AttackVector(name) if name in AttackVector._value2member_map_ else None
            if vector:
                adaptive_results = await self._run_adaptive_attacks(adapter, detector, vector)
                detector_results.extend(adaptive_results)

            # Count per-test-case (matching ScoringEngine logic)
            by_case: dict[str, list[TestResult]] = {}
            for r in detector_results:
                by_case.setdefault(r.test_case_id, []).append(r)
            cases_run = len(by_case)
            cases_failed = sum(
                1 for case_results in by_case.values() if any(not r.passed for r in case_results)
            )
            if self._progress is not None:
                self._progress.mark_completed(name, total=cases_run, failed=cases_failed)
            logger.info("Detector %s completed: %d results", name, len(detector_results))
            return name, detector_results, None

        except Exception as exc:
            if self._progress is not None:
                self._progress.mark_error(name, str(exc))
            logger.error("Detector %s failed: %s", name, exc, exc_info=True)
            return name, [], str(exc)

    async def run(self) -> ScanResult:
        start = time.monotonic()

        if self._adapter is not None:
            adapter = self._adapter
        else:
            adapter = HTTPAdapter(
                config=self.agent_config,
                timeout=self.scan_config.timeout_seconds,
                max_retries=self.scan_config.max_retries,
            )

        # Probe the endpoint before scanning
        await self._probe(adapter)

        detector_names = self.scan_config.detectors or list(DETECTOR_REGISTRY.keys())
        results_by_detector: dict[str, list[TestResult]] = {}
        errors: dict[str, str] = {}

        try:
            # Filter to valid detector names
            valid_names = []
            for name in detector_names:
                if name not in DETECTOR_REGISTRY:
                    logger.warning("Unknown detector '%s', skipping", name)
                    errors[name] = f"Unknown detector: {name}"
                else:
                    valid_names.append(name)

            # Generate attacker tests up front (routed per-detector)
            attacker_tests = await self._generate_attacker_tests(valid_names)

            # Run all detectors in parallel
            tasks = [
                self._run_single_detector(name, adapter, attacker_tests) for name in valid_names
            ]
            completed = await asyncio.gather(*tasks)

            for name, detector_results, error in completed:
                results_by_detector[name] = detector_results
                if error:
                    errors[name] = error

            # Score results — just pass/fail counts, no hidden math
            engine = ScoringEngine()
            scorecard = engine.calculate_scorecard(results_by_detector)

        finally:
            if self._adapter is None and hasattr(adapter, "close"):
                await adapter.close()

        duration = time.monotonic() - start
        return ScanResult(
            scorecard=scorecard,
            results_by_detector=results_by_detector,
            duration=duration,
            errors=errors,
        )
