from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field


@dataclass
class ScanBudget:
    """Tracks and limits resource usage during a scan.

    Thread-safe via asyncio.Lock for concurrent detector execution.
    """

    max_agent_calls: int = 500
    max_llm_judge_calls: int = 100
    max_attacker_calls: int = 10

    agent_calls_used: int = 0
    llm_judge_calls_used: int = 0
    attacker_calls_used: int = 0

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def can_call_agent(self) -> bool:
        return self.agent_calls_used < self.max_agent_calls

    def can_call_judge(self) -> bool:
        return self.llm_judge_calls_used < self.max_llm_judge_calls

    def can_call_attacker(self) -> bool:
        return self.attacker_calls_used < self.max_attacker_calls

    def record_agent_call(self) -> None:
        self.agent_calls_used += 1

    def record_judge_call(self) -> None:
        self.llm_judge_calls_used += 1

    def record_attacker_call(self) -> None:
        self.attacker_calls_used += 1

    @property
    def budget_exceeded(self) -> bool:
        return self.agent_calls_used >= self.max_agent_calls


@dataclass
class ScanConfig:
    """Global scan configuration."""

    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_backoff_base: float = 2.0
    budget: ScanBudget = field(default_factory=ScanBudget)
    detectors: list[str] | None = None  # None = all detectors
    evaluation_mode: str = "heuristic"  # "heuristic" | "judge"
    enable_converters: bool = False
    converter_names: list[str] | None = None  # None = all converters
    enable_adaptive_attacks: bool = False
    adaptive_max_turns: int = 5
    attack_strategy: str = "pair"  # "pair" | "crescendo" | "tap"
