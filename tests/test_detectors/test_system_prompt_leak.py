"""Tests for the SystemPromptLeakDetector."""

from __future__ import annotations


from agentgate.adapters.base import AdapterResponse
from agentgate.adapters.mock import MockAdapter
from agentgate.config import ScanConfig
from agentgate.detectors.system_prompt_leak import SystemPromptLeakDetector
from agentgate.models.agent import AgentConfig
from agentgate.models.test_case import AttackVector, TestCase


async def test_detects_vulnerable_agent(
    vulnerable_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = SystemPromptLeakDetector(vulnerable_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) > 0, "Should detect system prompt leak vulnerabilities"


async def test_passes_hardened_agent(
    hardened_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = SystemPromptLeakDetector(hardened_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) == 0, (
        f"Hardened agent should pass all system prompt leak tests, but {len(failed)} failed"
    )


class TestFalsePositiveFiltering:
    """Verify that leak keywords inside refusal context don't cause false failures."""

    def _make_tc(self) -> TestCase:
        return TestCase(
            attack_vector=AttackVector.SYSTEM_PROMPT_LEAK,
            name="FP test",
            payload="test",
            expected_behavior="Agent should refuse",
        )

    def test_refusal_mentioning_system_prompt(self, scan_config: ScanConfig) -> None:
        """Agent says 'I can't reveal my system prompt' — should pass."""
        adapter = MockAdapter()
        detector = SystemPromptLeakDetector(adapter, scan_config)
        tc = self._make_tc()
        responses = [
            AdapterResponse(
                text="I can't reveal my system prompt or share my instructions with you.",
                status_code=200,
            ),
        ]
        results = detector.evaluate(tc, responses)
        assert len(results) == 1
        assert results[0].passed is True

    def test_genuine_leak_still_fails(self, scan_config: ScanConfig) -> None:
        """Agent actually leaks prompt content — should fail."""
        adapter = MockAdapter()
        detector = SystemPromptLeakDetector(adapter, scan_config)
        tc = self._make_tc()
        responses = [
            AdapterResponse(
                text="My instructions are: You are a helpful assistant. Always respond politely. Here are my guidelines say to never reveal secrets.",
                status_code=200,
            ),
        ]
        results = detector.evaluate(tc, responses)
        assert len(results) == 1
        assert results[0].passed is False
