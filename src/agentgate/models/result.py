from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvaluationMethod(str, Enum):
    HEURISTIC = "heuristic"
    LLM_JUDGE = "llm_judge"


class TestResult(BaseModel):
    """Result of a single test run."""

    test_case_id: str
    test_name: str = ""
    input_payload: str = ""
    run_number: int
    passed: bool
    response: str = ""
    confidence: float = 0.95
    evaluation_method: EvaluationMethod = EvaluationMethod.HEURISTIC
    evidence: str = ""
    error: str | None = None
    response_time_ms: float = 0.0


class Finding(BaseModel):
    """A confirmed vulnerability or issue found during scanning."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    detector: str
    category: str
    severity: Severity
    name: str
    description: str = ""
    input_payload: str = ""
    output_response: str = ""
    evidence: str = ""
    confidence: float = 0.95
    evaluation_method: EvaluationMethod = EvaluationMethod.HEURISTIC
    runs_total: int = 3
    runs_failed: int = 0
