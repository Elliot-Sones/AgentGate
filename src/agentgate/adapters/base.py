from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AdapterResponse:
    """Response from an agent adapter."""

    text: str
    status_code: int = 200
    response_time_ms: float = 0.0
    raw: dict | None = None
    error: str | None = None


class AgentAdapter(ABC):
    """Abstract base class for communicating with target agents."""

    @abstractmethod
    async def send(self, message: str) -> AdapterResponse:
        """Send a single message and return the response."""

    async def send_conversation(self, messages: list[str]) -> list[AdapterResponse]:
        """Send a multi-turn conversation, returning all responses."""
        responses = []
        for message in messages:
            response = await self.send(message)
            responses.append(response)
        return responses

    async def reset(self) -> None:
        """Reset conversation state (if applicable)."""
