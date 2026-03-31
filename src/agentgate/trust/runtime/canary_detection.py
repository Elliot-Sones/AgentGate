from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import re
import string
import unicodedata
from urllib.parse import unquote

from agentgate.trust.runtime.canary_bank import CanaryBank

_MAX_TEXT_LENGTH = 16_384
_MAX_DECODING_CANDIDATES = 12
_EXCERPT_RADIUS = 24

_B64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{12,}={0,2}|[A-Za-z0-9_-]{16,})(?![A-Za-z0-9+/=_-])"
)
_HEX_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "с": "c",
        "С": "C",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "І": "I",
        "і": "i",
        "ј": "j",
        "Ј": "J",
        "к": "k",
        "К": "K",
        "м": "m",
        "М": "M",
        "н": "h",
        "Н": "H",
        "т": "t",
        "Т": "T",
        "л": "l",
        "Л": "L",
        "в": "b",
        "В": "B",
        "ѕ": "s",
        "Ѕ": "S",
        "ԁ": "d",
        "Ԁ": "D",
    }
)


@dataclass(frozen=True, slots=True)
class CanaryMatch:
    key: str
    match_type: str
    transforms: tuple[str, ...]
    source: str | None = None
    excerpt: str = ""


def detect_canary_matches(bank: CanaryBank, text: str) -> list[CanaryMatch]:
    if not text or not text.strip():
        return []

    tokens = bank.tokens()
    if not tokens:
        return []

    bounded_text = text[:_MAX_TEXT_LENGTH]
    variants = _build_variants(bounded_text)
    matches: list[CanaryMatch] = []
    seen_keys: set[str] = set()

    for key, value in tokens.items():
        if key in seen_keys:
            continue

        literal_match = _find_literal_match(key, value, bounded_text)
        if literal_match is not None:
            matches.append(literal_match)
            seen_keys.add(key)
            continue

        decoded_match = _find_decoded_match(key, value, variants)
        if decoded_match is not None:
            matches.append(decoded_match)
            seen_keys.add(key)

    return matches


def _find_literal_match(key: str, value: str, text: str) -> CanaryMatch | None:
    match_target = _first_present_match_target(text, key, value)
    if match_target is None:
        return None
    return CanaryMatch(
        key=key,
        match_type="literal_exact",
        transforms=(),
        excerpt=_excerpt(text, match_target),
    )


def _find_decoded_match(
    key: str,
    value: str,
    variants: list[tuple[str, tuple[str, ...]]],
) -> CanaryMatch | None:
    for candidate_text, transforms in variants:
        if not transforms:
            continue

        match_target = _first_present_match_target(candidate_text, key, value)
        if match_target is None:
            continue
        return CanaryMatch(
            key=key,
            match_type="decoded_exact",
            transforms=transforms,
            excerpt=_excerpt(candidate_text, match_target),
        )

    return None


def _build_variants(text: str) -> list[tuple[str, tuple[str, ...]]]:
    variants: list[tuple[str, tuple[str, ...]]] = [(text, ())]

    _append_variant(variants, _normalize_unicode_text(text), ("unicode_normalize",))
    _append_variant(variants, unquote(text), ("url_decode",))
    _append_variant(variants, _char_join_text(text), ("char_join",))

    for decoded_text, transform in _decode_replacements(text, "base64"):
        _append_variant(variants, decoded_text, transform)

    for decoded_text, transform in _decode_replacements(text, "hex"):
        _append_variant(variants, decoded_text, transform)

    return variants


def _decode_replacements(text: str, mode: str) -> list[tuple[str, tuple[str, ...]]]:
    if len(text) > _MAX_TEXT_LENGTH:
        return []

    if mode == "base64":
        pattern = _B64_CANDIDATE_RE
        decoder = _decode_base64_candidate
        label = "base64"
    elif mode == "hex":
        pattern = _HEX_CANDIDATE_RE
        decoder = _decode_hex_candidate
        label = "hex_decode"
    else:  # pragma: no cover - defensive guard
        return []

    variants: list[tuple[str, tuple[str, ...]]] = []
    for candidate in pattern.findall(text)[:_MAX_DECODING_CANDIDATES]:
        decoded = decoder(candidate)
        if decoded is None:
            continue
        variants.append((text.replace(candidate, decoded, 1), (label,)))
    return variants


def _append_variant(
    variants: list[tuple[str, tuple[str, ...]]],
    candidate_text: str,
    transforms: tuple[str, ...],
) -> None:
    if not candidate_text or candidate_text == variants[0][0]:
        return

    for existing_text, _ in variants:
        if existing_text == candidate_text:
            return

    variants.append((candidate_text, transforms))


def _normalize_unicode_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.translate(_CONFUSABLE_TRANSLATION)
    normalized = "".join(
        char for char in unicodedata.normalize("NFKD", normalized) if not unicodedata.combining(char)
    )
    return normalized


def _char_join_text(text: str) -> str:
    if not _looks_char_split(text):
        return text
    return re.sub(r"[.\s]+", "", text)


def _looks_char_split(text: str) -> bool:
    dense_separators = sum(1 for char in text if char in {".", " ", "\t", "\n", "\r"})
    alnum_count = sum(1 for char in text if char.isalnum())
    if alnum_count < 8:
        return False
    if dense_separators < 4:
        return False
    return "." in text


def _decode_base64_candidate(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)

    for raw in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            decoded_bytes = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _safe_text_decode(decoded_bytes)
        if decoded is not None:
            return decoded
    return None


def _decode_hex_candidate(candidate: str) -> str | None:
    if len(candidate) % 2 != 0:
        return None
    try:
        decoded_bytes = binascii.unhexlify(candidate)
    except (binascii.Error, ValueError):
        return None
    return _safe_text_decode(decoded_bytes)


def _safe_text_decode(data: bytes) -> str | None:
    for encoding in ("utf-8", "utf-16"):
        try:
            decoded = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _looks_like_text(decoded):
            return decoded
    return None


def _looks_like_text(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for char in text if char in string.printable or char.isprintable())
    return printable / len(text) >= 0.8


def _first_present_match_target(text: str, key: str, value: str) -> str | None:
    if value and value in text:
        return value
    if key and key in text:
        return key
    return None


def _excerpt(text: str, needle: str) -> str:
    if not needle:
        return text[: 2 * _EXCERPT_RADIUS]

    index = text.find(needle)
    if index < 0:
        return text[: 2 * _EXCERPT_RADIUS]

    start = max(0, index - _EXCERPT_RADIUS)
    end = min(len(text), index + len(needle) + _EXCERPT_RADIUS)
    return text[start:end]


__all__ = ["CanaryMatch", "detect_canary_matches"]
