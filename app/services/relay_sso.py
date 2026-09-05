from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

TOKEN_TTL_SECONDS = 60


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_relay_sso_token(secret: str, *, now: int | None = None) -> str:
    issued_at = int(time.time() if now is None else now)
    payload = _encode(
        json.dumps(
            {"exp": issued_at + TOKEN_TTL_SECONDS, "nonce": secrets.token_urlsafe(12)},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signature = _encode(hmac.new(str(secret).encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def verify_relay_sso_token(token: str, secret: str, *, now: int | None = None) -> bool:
    try:
        payload, supplied_signature = str(token or "").split(".", 1)
        expected_signature = _encode(
            hmac.new(str(secret).encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
        )
        if not secret or not hmac.compare_digest(supplied_signature, expected_signature):
            return False
        decoded = json.loads(_decode(payload))
        current = int(time.time() if now is None else now)
        return int(decoded.get("exp", 0)) >= current
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return False
