from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet() -> Fernet:
    configured = str(current_app.config.get("FERNET_KEY") or "").encode("ascii")
    if not configured:
        configured = base64.urlsafe_b64encode(hashlib.sha256(current_app.secret_key.encode()).digest())
    return Fernet(configured)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(str(value or "").encode()).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(str(value or "").encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Proxy credential could not be decrypted") from exc
