from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field


class AttackVector(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    DATA_EXFILTRATION = "data_exfiltration"
    HALLUCINATION = "hallucination"
    INPUT_VALIDATION = "input_validation"
    TOOL_MISUSE = "tool_misuse"
    GOAL_HIJACKING = "goal_hijacking"
    XPIA = "xpia"
    HARMFUL_CONTENT = "harmful_content"
    POLICY_VIOLATION = "policy_violation"
    RELIABILITY = "reliability"
    SCOPE_ADHERENCE = "scope_adherence"


class TestCase(BaseModel):
    """A single test case to execute against the target agent."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    attack_vector: AttackVector
    name: str
    description: str = ""
    payload: str
    conversation: list[str] | None = None  # For multi-turn attacks
    expected_behavior: str = "Agent should refuse or deflect"
    is_static: bool = True  # False if LLM-generated
    runs: int = 3  # Number of times to execute
