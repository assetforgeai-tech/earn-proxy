from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta

from app.crypto import decrypt_secret, encrypt_secret

TOKEN_PREFIX = "ep_live_"
TOKEN_BYTES = 32
PUBLIC_ID_BYTES = 12
MAX_NAME_LENGTH = 80
LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)
REVEAL_TTL = timedelta(minutes=10)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_prefix(token: str) -> str:
    return f"{token[: len(TOKEN_PREFIX) + 8]}..."


def _normalise_name(name: str) -> str:
    value = " ".join(str(name or "").split())
    if not value:
        raise ValueError("API key name is required")
    if len(value) > MAX_NAME_LENGTH:
        raise ValueError(f"API key name must be {MAX_NAME_LENGTH} characters or fewer")
    if any(ord(char) < 32 for char in value):
        raise ValueError("API key name contains an invalid control character")
    return value


def _new_material() -> tuple[str, str, str]:
    token = TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)
    public_id = "key_" + secrets.token_urlsafe(PUBLIC_ID_BYTES)
    return public_id, token, _token_prefix(token)


def _insert_key(
    db,
    name: str,
    *,
    created_by_user_id: int | None,
    source: str,
    now: str,
) -> tuple[int, str]:
    normalised_name = _normalise_name(name)
    source_value = str(source or "managed").strip().lower() or "managed"
    for _attempt in range(5):
        public_id, token, prefix = _new_material()
        savepoint = f"api_key_insert_{_attempt}"
        db.execute(f"SAVEPOINT {savepoint}")
        try:
            cursor = db.execute(
                """
                INSERT INTO api_keys(
                    public_id, name, token_prefix, token_hash, source,
                    created_by_user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    public_id,
                    normalised_name,
                    prefix,
                    _token_hash(token),
                    source_value,
                    created_by_user_id,
                    now,
                ),
            )
            db.execute(f"RELEASE SAVEPOINT {savepoint}")
            return int(cursor.lastrowid), token
        except sqlite3.IntegrityError:
            # Random collisions are extraordinarily unlikely; retry without
            # exposing the database error to the caller.
            db.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            db.execute(f"RELEASE SAVEPOINT {savepoint}")
    raise RuntimeError("Could not allocate a unique API key")


def create_api_key(
    db,
    name: str,
    *,
    created_by_user_id: int | None = None,
    source: str = "managed",
    now: datetime | None = None,
) -> tuple[int, str]:
    current = now or datetime.now(UTC)
    key_id, token = _insert_key(
        db,
        name,
        created_by_user_id=created_by_user_id,
        source=source,
        now=current.isoformat(),
    )
    db.commit()
    return key_id, token


def ensure_legacy_api_key(db, token: str, *, now: datetime | None = None) -> int | None:
    """Keep the configured environment token as the sole active legacy key."""
    value = str(token or "")
    current = now or datetime.now(UTC)
    if not value:
        # An explicitly removed setting is a revocation signal.  Managed keys
        # are intentionally untouched so administrators can migrate clients
        # before disabling the legacy credential.
        db.execute(
            "UPDATE api_keys SET revoked_at=? WHERE source='legacy' AND revoked_at IS NULL",
            (current.isoformat(),),
        )
        db.commit()
        return None
    digest = _token_hash(value)
    db.execute(
        "UPDATE api_keys SET revoked_at=? WHERE source='legacy' AND token_hash<>? AND revoked_at IS NULL",
        (current.isoformat(), digest),
    )
    existing = db.execute(
        "SELECT id FROM api_keys WHERE token_hash=? AND source='legacy'",
        (digest,),
    ).fetchone()
    if existing is not None:
        db.commit()
        return int(existing["id"])
    # A deterministic public id makes startup migration idempotent while the
    # token digest remains the only lookup material persisted for auth.
    public_id = f"legacy_{digest[:24]}"
    db.execute(
        """
        INSERT OR IGNORE INTO api_keys(
            public_id, name, token_prefix, token_hash, source, created_at
        ) VALUES (?, 'Legacy environment key', ?, ?, 'legacy', ?)
        """,
        (public_id, _token_prefix(value), digest, current.isoformat()),
    )
    db.commit()
    row = db.execute(
        "SELECT id FROM api_keys WHERE token_hash=? AND source='legacy'",
        (digest,),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def authenticate_api_key(db, supplied: str):
    value = str(supplied or "")
    if not value or len(value) > 512:
        return None
    digest = _token_hash(value)
    row = db.execute(
        "SELECT * FROM api_keys WHERE token_hash=? AND revoked_at IS NULL",
        (digest,),
    ).fetchone()
    if row is None or not hmac.compare_digest(str(row["token_hash"]), digest):
        return None
    current = _utcnow()
    last_used_at = None
    if row["last_used_at"]:
        try:
            last_used_at = datetime.fromisoformat(str(row["last_used_at"]))
        except ValueError:
            last_used_at = None
        if last_used_at is not None and last_used_at.tzinfo is None:
            last_used_at = last_used_at.replace(tzinfo=UTC)
    if last_used_at is not None and current - last_used_at < LAST_USED_WRITE_INTERVAL:
        return row
    try:
        db.execute(
            "UPDATE api_keys SET last_used_at=? WHERE id=? AND revoked_at IS NULL",
            (current.isoformat(), row["id"]),
        )
        db.commit()
    except sqlite3.Error:
        # Usage telemetry must not turn a valid read-only API request into a
        # 5xx when another process briefly holds SQLite's write lock.
        if db.in_transaction:
            db.rollback()
    return row


def list_api_keys(db):
    return db.execute(
        """
        SELECT id, public_id, name, token_prefix, source, created_at,
               last_used_at, revoked_at
        FROM api_keys
        ORDER BY CASE WHEN revoked_at IS NULL THEN 0 ELSE 1 END, created_at DESC, id DESC
        """
    ).fetchall()


def get_api_key_by_public_id(db, public_id: str):
    value = str(public_id or "").strip()
    if not value or len(value) > 80:
        return None
    return db.execute(
        "SELECT id, public_id, name, token_prefix, source, created_at, last_used_at, revoked_at "
        "FROM api_keys WHERE public_id=?",
        (value,),
    ).fetchone()


def create_api_key_reveal(db, token: str, message: str, *, now: datetime | None = None) -> str:
    current = now or _utcnow()
    db.execute(
        "DELETE FROM api_key_reveals WHERE consumed_at IS NOT NULL OR expires_at <= ?",
        (current.isoformat(),),
    )
    for _attempt in range(5):
        reveal_id = "reveal_" + secrets.token_urlsafe(18)
        try:
            db.execute(
                "INSERT INTO api_key_reveals(reveal_id,token_encrypted,message,created_at,expires_at) VALUES(?,?,?,?,?)",
                (
                    reveal_id,
                    encrypt_secret(token),
                    str(message or "")[:200],
                    current.isoformat(),
                    (current + REVEAL_TTL).isoformat(),
                ),
            )
            db.commit()
            return reveal_id
        except sqlite3.IntegrityError:
            if db.in_transaction:
                db.rollback()
    raise RuntimeError("Could not allocate a one-time reveal")


def consume_api_key_reveal(db, reveal_id: str, *, now: datetime | None = None):
    value = str(reveal_id or "").strip()
    if not value or len(value) > 80:
        return None
    current = now or _utcnow()
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute(
            "SELECT * FROM api_key_reveals WHERE reveal_id=? AND consumed_at IS NULL AND expires_at > ?",
            (value, current.isoformat()),
        ).fetchone()
        if row is None:
            db.commit()
            return None
        cursor = db.execute(
            "UPDATE api_key_reveals SET consumed_at=? WHERE reveal_id=? AND consumed_at IS NULL",
            (current.isoformat(), value),
        )
        if cursor.rowcount != 1:
            db.rollback()
            return None
        db.commit()
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise
    try:
        token = decrypt_secret(row["token_encrypted"])
    except ValueError:
        return None
    return token, str(row["message"])


def revoke_api_key(db, key_id: int, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    cursor = db.execute(
        "UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
        (current.isoformat(), int(key_id)),
    )
    if cursor.rowcount != 1:
        raise LookupError("API key not found or already revoked")
    db.commit()


def rotate_api_key(
    db,
    key_id: int,
    *,
    created_by_user_id: int | None = None,
    now: datetime | None = None,
) -> tuple[int, str]:
    current = now or datetime.now(UTC)
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            db.execute("BEGIN IMMEDIATE")
        old = db.execute(
            "SELECT id, name, source FROM api_keys WHERE id=? AND revoked_at IS NULL",
            (int(key_id),),
        ).fetchone()
        if old is None:
            raise LookupError("API key not found or already revoked")
        new_id, token = _insert_key(
            db,
            str(old["name"]),
            created_by_user_id=created_by_user_id,
            source="managed",
            now=current.isoformat(),
        )
        db.execute(
            "UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (current.isoformat(), int(key_id)),
        )
        if owns_transaction:
            db.commit()
        return new_id, token
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise
