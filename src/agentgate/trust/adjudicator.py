from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
from typing import Any

try:  # pragma: no cover - optional dependency for test-only environments
    import anthropic
except Exception:  # pragma: no cover - optional dependency fallback
    anthropic = None

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are AgentGate's trust adjudicator for borderline findings in the Phase 2 trust scanner.
You do not perform a general repository safety review.

Your job is to review one specific borderline finding and decide whether its severity should
be adjusted based on the provided evidence and context. Keep the response narrowly focused on
that one finding.

Return ONLY valid JSON with this exact schema:
{
  "finding_id": "string",
  "original_severity": "info|low|medium|high|critical",
  "adjusted_severity": "info|low|medium|high|critical",
  "confidence": 0.0,
  "rationale": "one sentence",
  "evidence_cited": ["string", "string"]
}

If the evidence is insufficient, preserve the original severity.
"""

_USER_TEMPLATE = """\
Finding ID: {finding_id}
Original severity: {original_severity}
Question: {question}

Context:
{context_block}

Evidence:
{evidence_block}

Return ONLY valid JSON matching the requested schema.
"""

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_SEVERITY_SET = set(_SEVERITY_ORDER)


@dataclass(slots=True)
class TrustAdjudicationCase:
    finding_id: str
    original_severity: str
    question: str
    evidence: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AdjudicatorResult:
    finding_id: str
    original_severity: str
    adjusted_severity: str
    confidence: float
    rationale: str
    evidence_cited: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AdjudicatorBudget:
    max_calls: int = 5
    calls_used: int = 0

    def can_call(self) -> bool:
        return self.calls_used < max(self.max_calls, 0)

    def record_call(self) -> None:
        self.calls_used += 1


class TrustAdjudicator:
    """Trust-specific LLM adjudicator for borderline findings."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        max_calls: int = 5,
        client: Any | None = None,
    ) -> None:
        self.api_key = api_key or ""
        self.model = model
        self.client = client
        self.budget = AdjudicatorBudget(max_calls=max_calls)

    async def adjudicate(self, case: TrustAdjudicationCase) -> AdjudicatorResult | None:
        if not self.budget.can_call():
            return None

        try:
            client = self._get_client()
            self.budget.record_call()
            response = client.messages.create(
                model=self.model,
                max_tokens=512,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": self._build_user_prompt(case)}],
            )
            text = self._extract_response_text(response)
            if not text.strip():
                return None
            return self._parse_response(text, case)
        except Exception:
            logger.exception("Trust adjudicator call failed")
            return None

    def _get_client(self) -> Any:
        if self.client is not None:
            return self.client
        if anthropic is None:  # pragma: no cover - defensive fallback
            raise RuntimeError("anthropic is not installed")
        return anthropic.Anthropic(api_key=self.api_key)

    @staticmethod
    def _build_user_prompt(case: TrustAdjudicationCase) -> str:
        context_items = case.context or {}
        context_block = (
            "\n".join(f"- {key}: {value}" for key, value in sorted(context_items.items()))
            if context_items
            else "(none)"
        )
        evidence_block = "\n".join(f"- {item}" for item in case.evidence) if case.evidence else "(none)"
        return _USER_TEMPLATE.format(
            finding_id=case.finding_id,
            original_severity=case.original_severity,
            question=case.question,
            context_block=context_block,
            evidence_block=evidence_block,
        )

    @staticmethod
    def _extract_response_text(response: Any) -> str:
        content = getattr(response, "content", response)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                text = getattr(item, "text", None)
                if text is None and isinstance(item, dict):
                    text = item.get("text")
                if text:
                    parts.append(str(text))
            return "".join(parts)
        return str(content)

    def _parse_response(
        self, text: str, case: TrustAdjudicationCase
    ) -> AdjudicatorResult | None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None

        try:
            data = json.loads(match.group())
        except json.JSONDecodeError:
            return None

        finding_id = str(data.get("finding_id") or case.finding_id).strip() or case.finding_id
        original = _normalize_severity_with_fallback(data.get("original_severity"), case.original_severity)
        adjusted = _normalize_severity_with_fallback(data.get("adjusted_severity"), original)

        confidence = _coerce_confidence(data.get("confidence", 0.0))
        rationale = str(data.get("rationale") or "").strip() or "No rationale provided."
        evidence_cited = _normalize_evidence_cited(data.get("evidence_cited"))

        return AdjudicatorResult(
            finding_id=finding_id,
            original_severity=original,
            adjusted_severity=adjusted,
            confidence=confidence,
            rationale=rationale,
            evidence_cited=evidence_cited,
        )


def _normalize_severity_with_fallback(value: Any, fallback: str) -> str:
    severity = str(value or "").strip().lower()
    if severity in _SEVERITY_SET:
        return severity
    fallback_severity = str(fallback or "").strip().lower()
    if fallback_severity in _SEVERITY_SET:
        return fallback_severity
    return "info"


def _coerce_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = 0.0
    return min(max(confidence, 0.0), 1.0)


def _normalize_evidence_cited(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        items = [value]
    return [str(item).strip() for item in items if str(item).strip()]


__all__ = [
    "AdjudicatorBudget",
    "AdjudicatorResult",
    "TrustAdjudicationCase",
    "TrustAdjudicator",
]
