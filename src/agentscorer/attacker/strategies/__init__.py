from __future__ import annotations

from agentscorer.attacker.strategies.base import AttackStrategy
from agentscorer.attacker.strategies.crescendo import CrescendoStrategy
from agentscorer.attacker.strategies.pair import PAIRStrategy
from agentscorer.attacker.strategies.tap import TAPStrategy

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
