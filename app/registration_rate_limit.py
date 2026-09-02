from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_WINDOW_SECONDS = 900
DEFAULT_GLOBAL_MAX_ATTEMPTS = 100
MAX_WINDOW_SECONDS = 24 * 60 * 60
DEFAULT_LOGIN_IP_MAX_ATTEMPTS = 30
DEFAULT_LOGIN_GLOBAL_MAX_ATTEMPTS = 1000


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def request_identity(request) -> str:
    """Return the address ProxyFix obtained from the trusted reverse proxy."""
    return _valid_ip(request.remote_addr) or "unknown"


def _int_setting(config: Mapping[str, object], key: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def admit_registration_attempt(
    db,
    identity: str,
    config: Mapping[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    """Reserve one registration slot atomically across every web worker."""
    current = now or datetime.now(UTC)
    max_attempts = _int_setting(config, "REGISTRATION_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS, 1, 1000)
    window = _int_setting(
        config,
        "REGISTRATION_RATE_WINDOW_SECONDS",
        DEFAULT_WINDOW_SECONDS,
        60,
        MAX_WINDOW_SECONDS,
    )
    global_max = _int_setting(
        config,
        "REGISTRATION_GLOBAL_MAX_ATTEMPTS",
        DEFAULT_GLOBAL_MAX_ATTEMPTS,
        1,
        100_000,
    )
    cutoff = (current - timedelta(seconds=window)).isoformat()
    identity_hash = hashlib.sha256(str(identity or "unknown").encode()).hexdigest()
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM registration_attempts WHERE attempted_at <= ?", (cutoff,))
        global_count = int(db.execute("SELECT COUNT(*) AS count FROM registration_attempts").fetchone()["count"])
        identity_count = int(
            db.execute(
                "SELECT COUNT(*) AS count FROM registration_attempts WHERE identity_hash=?",
                (identity_hash,),
            ).fetchone()["count"]
        )
        if global_count >= global_max or identity_count >= max_attempts:
            if owns_transaction:
                db.commit()
            return False
        db.execute(
            "INSERT INTO registration_attempts(identity_hash,attempted_at) VALUES(?,?)",
            (identity_hash, current.isoformat()),
        )
        if owns_transaction:
            db.commit()
        return True
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise


def admit_login_attempt(
    db,
    identity: str,
    account: str,
    config: Mapping[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    """Reserve a login slot atomically without making an account lockout oracle.

    The pre-hash gate is intentionally scoped to the client address and the
    shared service budget. An account-wide bucket would let an unauthenticated
    caller lock a known account by submitting wrong passwords.
    """
    current = now or datetime.now(UTC)
    identity_max = _int_setting(
        config,
        "LOGIN_IP_MAX_ATTEMPTS",
        DEFAULT_LOGIN_IP_MAX_ATTEMPTS,
        1,
        100_000,
    )
    window = _int_setting(
        config,
        "LOGIN_RATE_WINDOW_SECONDS",
        DEFAULT_WINDOW_SECONDS,
        60,
        MAX_WINDOW_SECONDS,
    )
    global_max = _int_setting(
        config,
        "LOGIN_GLOBAL_MAX_ATTEMPTS",
        DEFAULT_LOGIN_GLOBAL_MAX_ATTEMPTS,
        1,
        1_000_000,
    )
    cutoff = (current - timedelta(seconds=window)).isoformat()
    identity_hash = hashlib.sha256(str(identity or "unknown").encode()).hexdigest()
    account_hash = hashlib.sha256(str(account or "unknown").strip().lower().encode()).hexdigest()
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM login_attempts WHERE attempted_at <= ?", (cutoff,))
        global_count = int(db.execute("SELECT COUNT(*) AS count FROM login_attempts").fetchone()["count"])
        identity_count = int(
            db.execute(
                "SELECT COUNT(*) AS count FROM login_attempts WHERE identity_hash=?",
                (identity_hash,),
            ).fetchone()["count"]
        )
        if global_count >= global_max or identity_count >= identity_max:
            if owns_transaction:
                db.commit()
            return False
        db.execute(
            "INSERT INTO login_attempts(identity_hash,account_hash,attempted_at) VALUES(?,?,?)",
            (identity_hash, account_hash, current.isoformat()),
        )
        if owns_transaction:
            db.commit()
        return True
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise
