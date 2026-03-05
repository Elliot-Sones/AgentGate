from __future__ import annotations

from abc import ABC, abstractmethod

from agentscorer.adapters.base import AgentAdapter
from agentscorer.attacker.adaptive import AttackResult
from agentscorer.config import ScanConfig
from agentscorer.models.test_case import AttackVector


class AttackStrategy(ABC):
    """Base class for attack strategies."""

    name: str

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    @abstractmethod
    async def execute(
        self,
        adapter: AgentAdapter,
        objective: str,
        attack_vector: AttackVector,
        agent_description: str = "",
        max_turns: int = 5,
    ) -> AttackResult:
        """Run the full attack strategy and return the result."""
