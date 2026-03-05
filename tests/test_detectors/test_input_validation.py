"""Tests for the InputValidationDetector."""

from __future__ import annotations

import pytest

from agentscorer.adapters.mock import MockAdapter
from agentscorer.config import ScanConfig
from agentscorer.detectors.input_validation import InputValidationDetector
from agentscorer.models.agent import AgentConfig


async def test_detects_vulnerable_agent(
    vulnerable_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = InputValidationDetector(vulnerable_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) > 0, "Should detect input validation vulnerabilities"


async def test_passes_hardened_agent(
    hardened_adapter: MockAdapter,
    scan_config: ScanConfig,
    agent_config: AgentConfig,
) -> None:
    detector = InputValidationDetector(hardened_adapter, scan_config)
    results = await detector.run(agent_config)

    assert len(results) > 0
    failed = [r for r in results if not r.passed]
    assert len(failed) == 0, f"Hardened agent should pass all input validation tests, but {len(failed)} failed"
