from __future__ import annotations

from pydantic import BaseModel


class AgentConfig(BaseModel):
    """Configuration describing a target agent to scan."""

    url: str
    name: str = "Unnamed Agent"
    description: str = ""
    auth_header: str | None = None
    agent_type: str = "chat"
    capabilities: list[str] = []
    request_field: str = "question"
    response_field: str = "answer"
