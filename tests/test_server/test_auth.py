import pytest

from agentgate.server.auth import parse_api_key, generate_api_key, hash_secret, verify_secret


def test_parse_api_key_valid():
    key_id, secret = parse_api_key("agk_live_ps001.xK9mW2vR7nQ4pL8sT1abc")
    assert key_id == "ps001"
    assert secret == "xK9mW2vR7nQ4pL8sT1abc"


def test_parse_api_key_invalid_prefix():
    with pytest.raises(ValueError, match="Invalid API key format"):
        parse_api_key("bad_key_ps001.secret")


def test_parse_api_key_missing_dot():
    with pytest.raises(ValueError, match="Invalid API key format"):
        parse_api_key("agk_live_ps001secret")


def test_generate_api_key():
    key_id, raw_key, secret_hash = generate_api_key()
    assert raw_key.startswith("agk_live_")
    assert "." in raw_key
    parsed_id, parsed_secret = parse_api_key(raw_key)
    assert parsed_id == key_id
    assert verify_secret(parsed_secret, secret_hash)


def test_hash_and_verify():
    hashed = hash_secret("my_secret")
    assert verify_secret("my_secret", hashed)
    assert not verify_secret("wrong_secret", hashed)
