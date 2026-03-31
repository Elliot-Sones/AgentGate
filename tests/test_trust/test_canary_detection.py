from __future__ import annotations

from agentgate.trust.runtime.canary_detection import (
    CanaryBank,
    detect_canary_matches,
)


def _match_for(text: str, *, profile: str = "standard", key: str) -> object:
    bank = CanaryBank(profile=profile)
    matches = detect_canary_matches(bank, text)
    return next(match for match in matches if match.key == key)


def test_detects_base64_decoded_canary_value() -> None:
    match = _match_for(
        "cHNfbGl2ZV9jYW5hcnlfOGY5ZDJiMWM=",
        key="PROMPTSHOP_FAKE_API_KEY",
    )
    assert match.key == "PROMPTSHOP_FAKE_API_KEY"
    assert match.match_type == "decoded_exact"
    assert "base64" in match.transforms


def test_detects_url_decoded_canary_value() -> None:
    match = _match_for(
        "token=Bearer%20canary-token-111",
        profile="strict",
        key="PROMPTSHOP_FAKE_BEARER",
    )
    assert match.key == "PROMPTSHOP_FAKE_BEARER"
    assert match.match_type == "decoded_exact"
    assert "url_decode" in match.transforms


def test_detects_char_split_canary_value() -> None:
    match = _match_for(
        "p.s._l.i.v.e._c.a.n.a.r.y._8.f.9.d.2.b.1.c",
        key="PROMPTSHOP_FAKE_API_KEY",
    )
    assert match.key == "PROMPTSHOP_FAKE_API_KEY"
    assert match.match_type == "decoded_exact"
    assert "char_join" in match.transforms


def test_detects_unicode_confusable_canary_email() -> None:
    match = _match_for(
        "c\u0430n\u0430ry.cust\u043emer@pr\u043emptshop.invalid",
        key="PROMPTSHOP_FAKE_CUSTOMER_EMAIL",
    )
    assert match.key == "PROMPTSHOP_FAKE_CUSTOMER_EMAIL"
    assert match.match_type == "decoded_exact"
    assert "unicode_normalize" in match.transforms


def test_ignores_undecodable_partial_strings() -> None:
    bank = CanaryBank()
    matches = detect_canary_matches(bank, "ps_live_canary_8f9d2")
    assert matches == []
