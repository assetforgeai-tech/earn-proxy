"""Least-privilege encryption for Proxiware worker material.

The web/API encryption key remains the authority for the existing inventory
columns.  Browser/swap workers receive only this separate key and read only
the worker ciphertext columns.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

WORKER_PREFIX = "pwk1:"


def _worker_fernet() -> Fernet:
    configured = str(current_app.config.get("PROXIWARE_WORKER_FERNET_KEY") or "").strip()
    if not configured and current_app.testing:
        configured = str(current_app.config.get("FERNET_KEY") or "").strip()
    try:
        return Fernet(configured.encode("ascii"))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Proxiware worker encryption key is unavailable") from exc


def worker_profile() -> bool:
    try:
        return str(current_app.config.get("RUNTIME_PROFILE") or "web").strip().lower() == "proxiware_worker"
    except RuntimeError:
        return False


def encrypt_worker_secret(value: str) -> str:
    return WORKER_PREFIX + _worker_fernet().encrypt(str(value or "").encode()).decode("ascii")


def decrypt_worker_secret(value: object) -> str:
    encoded = str(value or "")
    if not encoded.startswith(WORKER_PREFIX):
        raise ValueError("Proxiware worker secret is unavailable")
    try:
        return _worker_fernet().decrypt(encoded[len(WORKER_PREFIX) :].encode()).decode()
    except (InvalidToken, UnicodeError) as exc:
        raise ValueError("Proxiware worker secret could not be decrypted") from exc


def decrypt_worker_json(value: object) -> dict[str, Any] | list[Any]:
    try:
        decoded = json.loads(decrypt_worker_secret(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("Proxiware worker session is invalid") from exc
    if not isinstance(decoded, (dict, list)):
        raise ValueError("Proxiware worker session is invalid")
    return decoded


def assignment_secret_columns(column: str) -> tuple[str, str]:
    """Return global and worker columns for one assignment secret."""

    value = str(column or "").strip()
    if value not in {"username_encrypted", "password_encrypted"}:
        raise ValueError("Unknown assignment secret")
    return value, "worker_" + value


def encrypt_assignment_secret(value: str) -> tuple[str, str]:
    from app.crypto import encrypt_secret

    text = str(value or "")
    return encrypt_secret(text), encrypt_worker_secret(text)


def decrypt_assignment_secret(row, column: str) -> str:
    global_column, worker_column = assignment_secret_columns(column)
    if worker_profile():
        value = str(row[worker_column] or "")
        if not value:
            raise ValueError("Proxiware worker assignment secret is unavailable")
        return decrypt_worker_secret(value)
    from app.crypto import decrypt_secret

    value = str(row[global_column] or "")
    if not value:
        return ""
    return decrypt_secret(value)


def _columns(db, table: str) -> set[str]:
    return {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _add_columns(db, table: str, definitions: dict[str, str]) -> None:
    existing = _columns(db, table)
    for name, definition in definitions.items():
        if name not in existing:
            db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}')


def ensure_worker_columns(db) -> None:
    """Additive schema step; safe on old releases and fresh databases."""

    _add_columns(db, "provider_sessions", {"worker_cookie_encrypted": "TEXT NOT NULL DEFAULT ''"})
    _add_columns(
        db,
        "provider_assignments",
        {
            "worker_username_encrypted": "TEXT NOT NULL DEFAULT ''",
            "worker_password_encrypted": "TEXT NOT NULL DEFAULT ''",
        },
    )


def migrate_provider_worker_secrets(db) -> int:
    """Copy legacy global-key ciphertext into worker-key columns once.

    The original ciphertext stays intact for web/API consumers.  Rows that
    cannot be decrypted are left blank, which keeps workers fail-closed.
    """

    from app.crypto import decrypt_secret

    ensure_worker_columns(db)
    migrated = 0
    for row in db.execute(
        "SELECT provider,cookie_encrypted,worker_cookie_encrypted FROM provider_sessions "
        "WHERE provider='proxiware' AND COALESCE(cookie_encrypted,'')<>''"
    ).fetchall():
        try:
            decrypt_worker_secret(row["worker_cookie_encrypted"])
            continue
        except ValueError:
            pass
        try:
            worker_value = encrypt_worker_secret(decrypt_secret(row["cookie_encrypted"]))
        except (TypeError, ValueError):
            continue
        db.execute(
            "UPDATE provider_sessions SET worker_cookie_encrypted=? WHERE provider='proxiware'",
            (worker_value,),
        )
        migrated += 1
    for row in db.execute(
        "SELECT id,username_encrypted,password_encrypted,worker_username_encrypted,worker_password_encrypted "
        "FROM provider_assignments WHERE provider='proxiware'"
    ).fetchall():
        updates: dict[str, str] = {}
        for source, target in (
            ("username_encrypted", "worker_username_encrypted"),
            ("password_encrypted", "worker_password_encrypted"),
        ):
            if str(row[target] or ""):
                try:
                    decrypt_worker_secret(row[target])
                    continue
                except ValueError:
                    pass
            try:
                updates[target] = encrypt_worker_secret(decrypt_secret(row[source])) if row[source] else ""
            except (TypeError, ValueError):
                updates = {}
                break
        if updates:
            db.execute(
                "UPDATE provider_assignments SET worker_username_encrypted=?,worker_password_encrypted=? WHERE id=?",
                (updates.get("worker_username_encrypted", ""), updates.get("worker_password_encrypted", ""), row["id"]),
            )
            migrated += 1
    return migrated


__all__ = [
    "WORKER_PREFIX",
    "assignment_secret_columns",
    "decrypt_assignment_secret",
    "decrypt_worker_json",
    "decrypt_worker_secret",
    "encrypt_assignment_secret",
    "encrypt_worker_secret",
    "ensure_worker_columns",
    "migrate_provider_worker_secrets",
    "worker_profile",
]
