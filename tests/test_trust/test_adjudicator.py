from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentgate.trust.adjudicator import (
    AdjudicatorBudget,
    AdjudicatorResult,
    TrustAdjudicationCase,
    TrustAdjudicator,
)


class _FakeMessages:
    def __init__(self, *, response_text: str | None = None, error: Exception | None = None) -> None:
        self.response_text = response_text or ""
        self.error = error
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(content=[SimpleNamespace(text=self.response_text)])


class _FakeClient:
    def __init__(self, *, response_text: str | None = None, error: Exception | None = None) -> None:
        self.messages = _FakeMessages(response_text=response_text, error=error)


@pytest.mark.asyncio
async def test_trust_adjudicator_returns_result_from_json_response() -> None:
    client = _FakeClient(
        response_text=(
            "Here is the review:\n"
            "{"
            '"finding_id":"finding-1",'
            '"original_severity":"high",'
            '"adjusted_severity":"medium",'
            '"confidence":0.82,'
            '"rationale":"The matched line is in a test fixture, not shipped runtime code.",'
            '"evidence_cited":["tests/test_security.py:12","pytest fixture context"]'
            "}"
        )
    )
    adjudicator = TrustAdjudicator(client=client, max_calls=3)
    case = TrustAdjudicationCase(
        finding_id="finding-1",
        original_severity="high",
        question="Is this test string in a live code path?",
        evidence=["tests/test_security.py:12", "assertion-only fixture"],
        context={"file_class": "test", "reachability": "not_reached"},
    )

    result = await adjudicator.adjudicate(case)

    assert isinstance(result, AdjudicatorResult)
    assert result.finding_id == "finding-1"
    assert result.original_severity == "high"
    assert result.adjusted_severity == "medium"
    assert result.confidence == pytest.approx(0.82)
    assert result.evidence_cited == ["tests/test_security.py:12", "pytest fixture context"]
    assert "trust adjudicator" in client.messages.calls[0]["system"].lower()
    assert "Question: Is this test string in a live code path?" in client.messages.calls[0]["messages"][0]["content"]


@pytest.mark.asyncio
async def test_trust_adjudicator_respects_budget_cap() -> None:
    client = _FakeClient(
        response_text=(
            "{"
            '"finding_id":"finding-2",'
            '"original_severity":"critical",'
            '"adjusted_severity":"high",'
            '"confidence":0.7,'
            '"rationale":"Downgraded after context review.",'
            '"evidence_cited":["context"]'
            "}"
        )
    )
    adjudicator = TrustAdjudicator(client=client, max_calls=1)
    case = TrustAdjudicationCase(
        finding_id="finding-2",
        original_severity="critical",
        question="Should this finding be downgraded?",
    )

    first = await adjudicator.adjudicate(case)
    second = await adjudicator.adjudicate(case)

    assert first is not None
    assert second is None
    assert len(client.messages.calls) == 1
    assert adjudicator.budget.calls_used == 1


@pytest.mark.asyncio
async def test_trust_adjudicator_handles_client_errors() -> None:
    client = _FakeClient(error=RuntimeError("anthropic unavailable"))
    adjudicator = TrustAdjudicator(client=client, max_calls=2)
    case = TrustAdjudicationCase(
        finding_id="finding-3",
        original_severity="medium",
        question="Is this domain framework telemetry?",
    )

    result = await adjudicator.adjudicate(case)

    assert result is None
    assert adjudicator.budget.calls_used == 1


@pytest.mark.asyncio
async def test_trust_adjudicator_keeps_original_severity_on_invalid_adjustment() -> None:
    client = _FakeClient(
        response_text=(
            "{"
            '"finding_id":"finding-4",'
            '"original_severity":"high",'
            '"adjusted_severity":"definitely-not-a-severity",'
            '"confidence":1.2,'
            '"rationale":"Model tried to improvise.",'
            '"evidence_cited":"test fixture path"'
            "}"
        )
    )
    adjudicator = TrustAdjudicator(client=client, max_calls=2)
    case = TrustAdjudicationCase(
        finding_id="finding-4",
        original_severity="high",
        question="Does this remain a high-severity finding?",
    )

    result = await adjudicator.adjudicate(case)

    assert result is not None
    assert result.original_severity == "high"
    assert result.adjusted_severity == "high"
    assert result.confidence == 1.0
    assert result.evidence_cited == ["test fixture path"]


@pytest.mark.asyncio
async def test_trust_adjudicator_returns_none_when_budget_is_exhausted_before_call() -> None:
    client = _FakeClient(
        response_text=(
            "{"
            '"finding_id":"finding-5",'
            '"original_severity":"medium",'
            '"adjusted_severity":"low",'
            '"confidence":0.5,'
            '"rationale":"Should not be used.",'
            '"evidence_cited":["unused"]'
            "}"
        )
    )
    adjudicator = TrustAdjudicator(client=client, max_calls=0)
    case = TrustAdjudicationCase(
        finding_id="finding-5",
        original_severity="medium",
        question="Will this call be skipped?",
    )

    result = await adjudicator.adjudicate(case)

    assert result is None
    assert client.messages.calls == []
    assert adjudicator.budget.calls_used == 0


def test_budget_helpers() -> None:
    budget = AdjudicatorBudget(max_calls=2)
    assert budget.can_call() is True
    budget.record_call()
    assert budget.can_call() is True
    budget.record_call()
    assert budget.can_call() is False
