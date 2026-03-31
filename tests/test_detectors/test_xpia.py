"""Tests for the XPIADetector."""

from __future__ import annotations


from agentgate.adapters.mock import MockAdapter
from agentgate.config import ScanConfig
from agentgate.detectors.xpia import XPIADetector
from agentgate.models.agent import AgentConfig


async def test_detects_vulnerable_agent(
    vulnerable_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = XPIADetector(vulnerable_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) > 0, "Should detect XPIA vulnerabilities"


async def test_passes_hardened_agent(
    hardened_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = XPIADetector(hardened_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    # With an API key set, ambiguous (low-confidence) results now correctly fail
    # as a fail-safe; only check high-confidence failures which indicate real issues
    high_confidence_failed = [r for r in results if not r.passed and r.confidence > 0.7]
    assert len(high_confidence_failed) == 0, (
        f"Hardened agent should pass all high-confidence XPIA tests, but {len(high_confidence_failed)} failed"
    )
