from __future__ import annotations

from abc import ABC, abstractmethod

from agentgate.adapters.base import AgentAdapter
from agentgate.attacker.adaptive import AttackResult
from agentgate.config import ScanConfig
from agentgate.models.test_case import AttackVector


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
