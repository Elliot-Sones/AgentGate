from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod

from agentgate.adapters.base import AdapterResponse, AgentAdapter
from agentgate.config import ScanConfig
from agentgate.evaluation.llm_judge import LLMJudge
from agentgate.models.agent import AgentConfig
from agentgate.models.result import EvaluationMethod, TestResult
from agentgate.models.test_case import TestCase

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Abstract base class for all security detectors."""

    def __init__(self, adapter: AgentAdapter, config: ScanConfig) -> None:
        self.adapter = adapter
        self.config = config

    @abstractmethod
    def generate(self, agent_config: AgentConfig) -> list[TestCase]:
        """Generate test cases for this detector given the target agent config."""

    async def execute(
        self, test_cases: list[TestCase]
    ) -> list[tuple[TestCase, list[AdapterResponse]]]:
        """Execute test cases against the target agent via the adapter.

        Each test case is sent `test_case.runs` times (budget permitting).
        Returns a list of (test_case, responses) tuples.
        """
        results: list[tuple[TestCase, list[AdapterResponse]]] = []

        for test_case in test_cases:
            responses: list[AdapterResponse] = []

            for _ in range(test_case.runs):
                if not self.config.budget.can_call_agent():
                    logger.warning("Agent call budget exhausted, stopping execution")
                    break

                try:
                    if test_case.conversation:
                        conv_responses = await self.adapter.send_conversation(
                            test_case.conversation
                        )
                        self.config.budget.agent_calls_used += len(conv_responses)
                        # Use the last response as the primary one
                        if conv_responses:
                            responses.append(conv_responses[-1])
                    else:
                        response = await self.adapter.send(test_case.payload)
                        self.config.budget.record_agent_call()
                        responses.append(response)
                except Exception as e:
                    logger.error("Error executing test case %s: %s", test_case.id, e)
                    responses.append(
                        AdapterResponse(text="", status_code=500, error=str(e))
                    )
                    self.config.budget.record_agent_call()

                await self.adapter.reset()

            results.append((test_case, responses))

        return results

    @abstractmethod
    def evaluate(
        self, test_case: TestCase, responses: list[AdapterResponse]
    ) -> list[TestResult]:
        """Evaluate adapter responses against the test case expectations.

        Returns one TestResult per response/run.
        """

    async def _refine_with_judge(
        self,
        results: list[TestResult],
        test_case_lookup: dict[str, TestCase],
    ) -> list[TestResult]:
        """Re-evaluate low-confidence heuristic results with LLM Judge.

        Skips entirely when no Anthropic API key is configured or when the
        judge budget is exhausted.
        """
        if not self.config.anthropic_api_key:
            return results

        judge = LLMJudge(self.config)
        refined: list[TestResult] = []

        for result in results:
            should_judge = (
                self.config.evaluation_mode == "judge"
                or (
                    result.evaluation_method == EvaluationMethod.HEURISTIC
                    and result.confidence < 0.8
                )
            )
            if (
                should_judge
                and result.error is None
                and self.config.budget.can_call_judge()
            ):
                tc = test_case_lookup.get(result.test_case_id)
                if tc is None:
                    refined.append(result)
                    continue

                try:
                    passed, confidence, evidence = await judge.evaluate(
                        input_payload=result.input_payload,
                        response=result.response,
                        expected_behavior=tc.expected_behavior,
                        attack_vector=tc.attack_vector,
                    )
                    refined.append(
                        result.model_copy(
                            update={
                                "passed": passed,
                                "confidence": confidence,
                                "evidence": evidence,
                                "evaluation_method": EvaluationMethod.LLM_JUDGE,
                            }
                        )
                    )
                except Exception:
                    logger.warning(
                        "LLM judge failed for %s, keeping heuristic result",
                        result.test_case_id,
                        exc_info=True,
                    )
                    refined.append(result)
            else:
                refined.append(result)

        return refined

    async def run(self, agent_config: AgentConfig) -> list[TestResult]:
        """Full detector pipeline: generate -> [convert] -> execute -> evaluate -> judge."""
        test_cases = self.generate(agent_config)
        logger.info(
            "%s generated %d test cases", self.__class__.__name__, len(test_cases)
        )

        # Expand test cases with encoded/obfuscated variants
        if self.config.enable_converters:
            from agentgate.converters import get_converters

            converters = get_converters(self.config.converter_names)
            converted_cases = []
            for tc in test_cases:
                for conv in converters:
                    converted_cases.append(
                        tc.model_copy(
                            update={
                                "id": uuid.uuid4().hex[:8],
                                "payload": conv.convert(tc.payload),
                                "name": f"{tc.name} [{conv.name}]",
                                "is_static": False,
                            }
                        )
                    )
            test_cases.extend(converted_cases)
            logger.info(
                "%s expanded to %d test cases with %d converters",
                self.__class__.__name__,
                len(test_cases),
                len(converters),
            )

        executed = await self.execute(test_cases)

        test_case_lookup = {tc.id: tc for tc in test_cases}
        all_results: list[TestResult] = []
        for test_case, responses in executed:
            results = self.evaluate(test_case, responses)
            for r in results:
                r.test_name = test_case.name
                r.input_payload = test_case.payload
            all_results.extend(results)

        # Refine low-confidence heuristic results with LLM Judge
        all_results = await self._refine_with_judge(all_results, test_case_lookup)

        logger.info(
            "%s produced %d results", self.__class__.__name__, len(all_results)
        )
        return all_results
