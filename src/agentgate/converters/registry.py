from __future__ import annotations

from agentgate.converters.base import PayloadConverter
from agentgate.converters.encodings import (
    Base64Converter,
    CharSplitConverter,
    MarkdownEscapeConverter,
    ROT13Converter,
    UnicodeHomoglyphConverter,
)

CONVERTER_REGISTRY: dict[str, type[PayloadConverter]] = {
    "base64": Base64Converter,
    "rot13": ROT13Converter,
    "unicode_homoglyph": UnicodeHomoglyphConverter,
    "char_split": CharSplitConverter,
    "markdown_escape": MarkdownEscapeConverter,
}


def get_converters(names: list[str] | None = None) -> list[PayloadConverter]:
    """Return converter instances. None = all converters."""
    if names is None:
        return [cls() for cls in CONVERTER_REGISTRY.values()]
    return [CONVERTER_REGISTRY[n]() for n in names if n in CONVERTER_REGISTRY]
