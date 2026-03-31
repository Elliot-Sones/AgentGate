from __future__ import annotations

from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    """Configuration describing a target agent to scan."""

    url: str
    name: str = "Unnamed Agent"
    description: str = ""
    auth_header: str | None = None
    agent_type: str = "chat"
    capabilities: list[str] = []
    attack_hints: list[str] = []
    request_field: str = "question"
    response_field: str = "answer"
    request_defaults: dict[str, object] = Field(default_factory=dict)
