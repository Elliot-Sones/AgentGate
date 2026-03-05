"""FastAPI server for the clean support agent."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from agent import SupportAgent

app = FastAPI(title="ShopFlow Support Agent", version="1.0.0")
agent = SupportAgent()


class ChatRequest(BaseModel):
    question: str


class ChatResponse(BaseModel):
    answer: str
    data: list


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/v1/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    result = agent.process(request.question)
    return ChatResponse(answer=result["answer"], data=result["data"])
