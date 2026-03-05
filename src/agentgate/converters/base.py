from __future__ import annotations

from abc import ABC, abstractmethod


class PayloadConverter(ABC):
    """Base class for payload encoding/obfuscation converters."""

    name: str

    @abstractmethod
    def convert(self, payload: str) -> str:
        """Transform a payload string into an obfuscated variant."""
