from __future__ import annotations

from agentgate.attacker.strategies.base import AttackStrategy
from agentgate.attacker.strategies.crescendo import CrescendoStrategy
from agentgate.attacker.strategies.pair import PAIRStrategy
from agentgate.attacker.strategies.tap import TAPStrategy

STRATEGY_REGISTRY: dict[str, type[AttackStrategy]] = {
    "pair": PAIRStrategy,
    "crescendo": CrescendoStrategy,
    "tap": TAPStrategy,
}

__all__ = [
    "AttackStrategy",
    "PAIRStrategy",
    "CrescendoStrategy",
    "TAPStrategy",
    "STRATEGY_REGISTRY",
]
