from __future__ import annotations

from agentgate.adapters.base import AgentAdapter
from agentgate.attacker.adaptive import AdaptiveAttacker, AttackResult
from agentgate.attacker.strategies.base import AttackStrategy
from agentgate.config import ScanConfig
from agentgate.models.test_case import AttackVector


class PAIRStrategy(AttackStrategy):
    """Standard PAIR (Prompt Automatic Iterative Refinement) strategy.

    This is the default strategy. It delegates directly to AdaptiveAttacker's
    built-in PAIR loop.
    """

    name = "pair"

    async def execute(
        self,
        adapter: AgentAdapter,
        objective: str,
        attack_vector: AttackVector,
        agent_description: str = "",
        max_turns: int = 5,
    ) -> AttackResult:
        attacker = AdaptiveAttacker(self._config)
        return await attacker.attack(
            adapter=adapter,
            objective=objective,
            attack_vector=attack_vector,
            agent_description=agent_description,
            max_turns=max_turns,
        )
