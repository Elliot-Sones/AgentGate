"""Tests for the GoalHijackingDetector."""

from __future__ import annotations


from agentgate.adapters.mock import MockAdapter
from agentgate.config import ScanConfig
from agentgate.detectors.goal_hijacking import GoalHijackingDetector
from agentgate.models.agent import AgentConfig


async def test_detects_vulnerable_agent(
    vulnerable_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = GoalHijackingDetector(vulnerable_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) > 0, "Should detect goal hijacking vulnerabilities"


async def test_passes_hardened_agent(
    hardened_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = GoalHijackingDetector(hardened_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) == 0, f"Hardened agent should pass all goal hijacking tests, but {len(failed)} failed"
