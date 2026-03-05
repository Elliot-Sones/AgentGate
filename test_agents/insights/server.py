"""FastAPI server exposing the Insights agent for testing."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from test_agents.insights.agent import InsightsAgent

app = FastAPI(title="Insights Agent", version="0.1.0")

agent = InsightsAgent()


class InsightsRequest(BaseModel):
    question: str


class InsightsResponse(BaseModel):
    answer: str
    data: list


@app.post("/api/insights", response_model=InsightsResponse)
async def insights(request: InsightsRequest) -> InsightsResponse:
    result = agent.process(request.question)
    return InsightsResponse(answer=result["answer"], data=result["data"])
