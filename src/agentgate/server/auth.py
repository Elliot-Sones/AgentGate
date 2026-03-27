from __future__ import annotations

import secrets
import string

import bcrypt

_PREFIX = "agk_live_"
_KEY_ID_LENGTH = 8
_SECRET_LENGTH = 32
_ALPHABET = string.ascii_letters + string.digits


def generate_api_key() -> tuple[str, str, str]:
    """Returns (key_id, raw_api_key, bcrypt_hash_of_secret)."""
    key_id = "".join(secrets.choice(_ALPHABET) for _ in range(_KEY_ID_LENGTH))
    secret = "".join(secrets.choice(_ALPHABET) for _ in range(_SECRET_LENGTH))
    raw_key = f"{_PREFIX}{key_id}.{secret}"
    secret_hash = hash_secret(secret)
    return key_id, raw_key, secret_hash


def parse_api_key(raw_key: str) -> tuple[str, str]:
    """Parse raw API key into (key_id, secret). Raises ValueError if malformed."""
    if not raw_key.startswith(_PREFIX):
        raise ValueError("Invalid API key format: missing prefix")
    body = raw_key[len(_PREFIX):]
    if "." not in body:
        raise ValueError("Invalid API key format: missing separator")
    key_id, secret = body.split(".", 1)
    if not key_id or not secret:
        raise ValueError("Invalid API key format: empty key_id or secret")
    return key_id, secret


def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def verify_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode(), hashed.encode())
