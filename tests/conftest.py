"""Shared test fixtures for agentscorer tests."""

from __future__ import annotations

import pytest

from agentscorer.adapters.mock import MockAdapter
from agentscorer.config import ScanBudget, ScanConfig
from agentscorer.models.agent import AgentConfig


@pytest.fixture
def vulnerable_adapter() -> MockAdapter:
    return MockAdapter.vulnerable()


@pytest.fixture
def hardened_adapter() -> MockAdapter:
    return MockAdapter.hardened()


@pytest.fixture
def scan_config() -> ScanConfig:
    return ScanConfig(
        anthropic_api_key="test-key-not-real",
        timeout_seconds=10.0,
        max_retries=1,
        budget=ScanBudget(
            max_agent_calls=200,
            max_llm_judge_calls=0,
            max_attacker_calls=0,
        ),
    )


@pytest.fixture
def agent_config() -> AgentConfig:
    return AgentConfig(
        url="http://localhost:8000/api/insights",
        name="Test Insights Agent",
        description="A test agent for Shopify product and revenue data analysis.",
        agent_type="chat",
        capabilities=["search_products", "get_revenue", "get_customers"],
        request_field="question",
        response_field="answer",
    )
