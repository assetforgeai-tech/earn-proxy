"""Encrypted Proxiware credentials and browser-session adapter boundary.

The service stores only encrypted material and safe metadata.  Browser and
CAPTCHA implementations are injected; no network, CDP, or CAPTCHA calls live
here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from app.crypto import decrypt_secret, encrypt_secret

PROVIDER = "proxiware"
SECRET_NAMES = frozenset({"login_email", "login_password", "api_key", "captcha_api_key"})
SAFE_SESSION_ERROR_CODES = frozenset(
    {
        "captcha_required",
        "captcha_timeout",
        "csrf_failed",
        "fingerprint_failed",
        "login_failed",
        "manual_action_required",
        "session_expired",
        "provider_error",
    }
)
_SAFE_AUDIT_VALUE = re.compile(r"^[a-z0-9_.:/-]{1,120}$")
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "login_password",
        "api_key",
        "captcha_api_key",
        "cookie",
        "cookies",
        "token",
        "captcha_token",
        "fp",
        "fpr",
        "fingerprint",
        "fingerprint_payload",
    }
)


def _iso(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    current = current.astimezone(UTC) if current.tzinfo else current.replace(tzinfo=UTC)
    return current.isoformat()


def ensure_proxiware_security_schema(db) -> None:
    # Imported lazily by callers so this module remains usable outside Flask.
    from app.services.proxiware_swap import ensure_proxiware_swap_schema

    ensure_proxiware_swap_schema(db)


def _validate_secret_name(name: str) -> str:
    value = str(name or "").strip().lower()
    if value not in SECRET_NAMES:
        raise ValueError("Unknown provider secret")
    return value


def save_provider_secret(db, name: str, value: str, *, now: datetime | None = None) -> None:
    key = _validate_secret_name(name)
    value = str(value or "")
    if not value:
        # Blank form fields intentionally preserve an existing secret.
        return
    if len(value) > 4096 or any(ord(ch) < 32 and ch not in "\t" for ch in value):
        raise ValueError("Provider secret is invalid")
    ensure_proxiware_security_schema(db)
    db.execute(
        "INSERT INTO provider_credentials(name,provider,secret_encrypted,updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_at=excluded.updated_at "
        "WHERE provider=excluded.provider",
        (key, PROVIDER, encrypt_secret(value), _iso(now)),
    )
    db.commit()


def save_provider_credentials(
    db,
    values: dict[str, object],
    *,
    now: datetime | None = None,
) -> None:
    ensure_proxiware_security_schema(db)
    # Each secret is independently validated and encrypted.  A transaction
    # makes multi-field admin saves all-or-nothing.
    owns = not db.in_transaction
    if owns:
        db.execute("BEGIN IMMEDIATE")
    try:
        for key in SECRET_NAMES:
            value = str(values.get(key) or "")
            if value:
                if len(value) > 4096 or any(ord(ch) < 32 and ch not in "\t" for ch in value):
                    raise ValueError("Provider secret is invalid")
                db.execute(
                    "INSERT INTO provider_credentials(name,provider,secret_encrypted,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_at=excluded.updated_at "
                    "WHERE provider=excluded.provider",
                    (key, PROVIDER, encrypt_secret(value), _iso(now)),
                )
        if owns:
            db.commit()
    except Exception:
        if owns and db.in_transaction:
            db.rollback()
        raise


def clear_provider_secret(db, name: str, *, now: datetime | None = None) -> bool:
    key = _validate_secret_name(name)
    ensure_proxiware_security_schema(db)
    cursor = db.execute("DELETE FROM provider_credentials WHERE provider=? AND name=?", (PROVIDER, key))
    db.commit()
    return cursor.rowcount == 1


def get_provider_secret(db, name: str) -> str | None:
    key = _validate_secret_name(name)
    ensure_proxiware_security_schema(db)
    row = db.execute(
        "SELECT secret_encrypted FROM provider_credentials WHERE provider=? AND name=?", (PROVIDER, key)
    ).fetchone()
    if row is None or not row["secret_encrypted"]:
        return None
    return decrypt_secret(row["secret_encrypted"])


def _last_four(secret: str) -> str:
    return secret[-4:] if len(secret) >= 4 else ""


def get_provider_secret_metadata(db) -> dict[str, dict[str, object]]:
    ensure_proxiware_security_schema(db)
    rows = db.execute(
        "SELECT name,secret_encrypted,updated_at FROM provider_credentials WHERE provider=?", (PROVIDER,)
    ).fetchall()
    values: dict[str, dict[str, object]] = {
        key: {"configured": False, "last_four": "", "updated_at": None} for key in SECRET_NAMES
    }
    for row in rows:
        name = str(row["name"])
        if name not in SECRET_NAMES:
            continue
        # Decrypt only to derive non-sensitive metadata.  Never return value.
        try:
            secret = decrypt_secret(row["secret_encrypted"])
        except ValueError:
            secret = ""
        values[name] = {
            "configured": bool(secret),
            "last_four": _last_four(secret) if name in {"api_key"} else "",
            "updated_at": row["updated_at"],
        }
    return values


def _redact(value: Any, *, key: str = "") -> Any:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS or any(marker in lowered for marker in ("secret", "credential", "cookie")):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, key=key) for item in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


def redact_provider_payload(payload: Any) -> Any:
    """Return safe structured data for logs/audit; never stringify secrets."""

    return _redact(payload)


def record_provider_audit(
    db,
    *,
    action: str,
    result: str,
    actor_id: int | None = None,
    target_id: str = "",
    error_code: str = "",
    now: datetime | None = None,
) -> None:
    ensure_proxiware_security_schema(db)
    action_value = str(action or "provider_action").strip().lower()
    result_value = str(result or "").strip().lower()
    target_value = str(target_id or "").strip()
    error_value = str(error_code or "").strip().lower()
    # Audit rows are a safe allowlist, not a general-purpose log sink.
    if not _SAFE_AUDIT_VALUE.fullmatch(action_value):
        action_value = "provider_action"
    if not _SAFE_AUDIT_VALUE.fullmatch(result_value):
        result_value = "recorded"
    if not _SAFE_AUDIT_VALUE.fullmatch(target_value):
        target_value = "redacted"
    if not _SAFE_AUDIT_VALUE.fullmatch(error_value):
        error_value = ""
    db.execute(
        "INSERT INTO provider_audit_events(provider,actor_id,action,target_id,result,error_code,created_at) VALUES(?,?,?,?,?,?,?)",
        (PROVIDER, actor_id, action_value, target_value, result_value, error_value, _iso(now)),
    )
    db.commit()


class BrowserSessionAdapter(Protocol):
    def renew(self, *, email: str, password: str, captcha_token: str) -> dict[str, Any]: ...


class CaptchaAdapter(Protocol):
    def solve_hcaptcha(self, *, site_key: str, page_url: str) -> str: ...


@dataclass(frozen=True)
class SessionRenewalResult:
    state: str
    error_code: str = ""
    expires_at: str | None = None


@dataclass(frozen=True)
class ConnectionCheckResult:
    api_ok: bool
    captcha_ok: bool
    captcha_balance: float | None = None
    error_code: str = ""


def store_provider_session(
    db,
    cookies: dict[str, Any] | list[dict[str, Any]],
    *,
    expires_at: datetime | str | None = None,
    now: datetime | None = None,
) -> None:
    ensure_proxiware_security_schema(db)
    if not isinstance(cookies, (dict, list)):
        raise ValueError("Session cookies are invalid")
    # Cookies are encrypted as one opaque blob; no raw cookie values enter DB.
    encoded = json.dumps(cookies, separators=(",", ":"), ensure_ascii=True)
    expiry = expires_at
    if isinstance(expiry, datetime):
        expiry = _iso(expiry)
    elif expiry is not None:
        expiry = str(expiry)[:64]
    db.execute(
        "INSERT INTO provider_sessions(provider,cookie_encrypted,expires_at,state,last_error_code,renewed_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET cookie_encrypted=excluded.cookie_encrypted,"
        "expires_at=excluded.expires_at,state=excluded.state,last_error_code='',renewed_at=excluded.renewed_at,updated_at=excluded.updated_at",
        (PROVIDER, encrypt_secret(encoded), expiry, "active", "", _iso(now), _iso(now)),
    )
    db.commit()


def load_provider_session(db) -> dict[str, Any] | list[dict[str, Any]] | None:
    ensure_proxiware_security_schema(db)
    row = db.execute("SELECT cookie_encrypted FROM provider_sessions WHERE provider=?", (PROVIDER,)).fetchone()
    if row is None or not row["cookie_encrypted"]:
        return None
    raw = decrypt_secret(row["cookie_encrypted"])
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("Provider session is invalid") from exc
    if not isinstance(decoded, (dict, list)):
        raise ValueError("Provider session is invalid")
    return decoded


def mark_manual_action_required(db, error_code: str, *, now: datetime | None = None) -> None:
    ensure_proxiware_security_schema(db)
    candidate = str(error_code or "manual_action_required").strip().lower()
    safe = candidate if candidate in SAFE_SESSION_ERROR_CODES else "manual_action_required"
    timestamp = _iso(now)
    owns = not db.in_transaction
    if owns:
        db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(
            "INSERT INTO provider_sessions(provider,state,last_error_code,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET state='manual_action_required',"
            "last_error_code=excluded.last_error_code,updated_at=excluded.updated_at",
            (PROVIDER, "manual_action_required", safe, timestamp),
        )
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES('proxiware_auto_swap','0',?) "
            "ON CONFLICT(key) DO UPDATE SET value='0',updated_at=excluded.updated_at",
            (timestamp,),
        )
        if owns:
            db.commit()
    except Exception:
        if owns and db.in_transaction:
            db.rollback()
        raise


def renew_provider_session(
    db,
    browser_adapter: BrowserSessionAdapter,
    captcha_adapter: CaptchaAdapter,
    *,
    site_key: str,
    page_url: str,
    now: datetime | None = None,
) -> SessionRenewalResult:
    """Renew through injected real-browser adapters; fail closed on any challenge error."""

    email = get_provider_secret(db, "login_email")
    password = get_provider_secret(db, "login_password")
    if not email or not password:
        mark_manual_action_required(db, "login_failed", now=now)
        return SessionRenewalResult("manual_action_required", "login_failed")
    try:
        captcha_token = captcha_adapter.solve_hcaptcha(site_key=site_key, page_url=page_url)
        if not captcha_token:
            raise ValueError("captcha timeout")
        # The adapter obtains fp/fpr from its isolated real browser context;
        # this service never accepts or fabricates fingerprint values.
        result = browser_adapter.renew(email=email, password=password, captcha_token=captcha_token)
        if not isinstance(result, dict) or not result.get("cookies") or not result.get("fingerprint_observed"):
            if isinstance(result, dict) and result.get("cookies"):
                raise ValueError("fingerprint failed")
            raise ValueError("login failed")
        store_provider_session(db, result["cookies"], expires_at=result.get("expires_at"), now=now)
        record_provider_audit(db, action="renew_session", result="success", now=now)
        return SessionRenewalResult("active", expires_at=str(result.get("expires_at") or "") or None)
    except Exception as exc:  # noqa: BLE001 - adapter boundary must fail closed
        message = str(exc).lower()
        if getattr(exc, "error_code", "") == "manual_action_required":
            code = "manual_action_required"
        elif "captcha" in message:
            code = "captcha_timeout"
        elif "fingerprint" in message or "fp" in message:
            code = "fingerprint_failed"
        elif "csrf" in message:
            code = "csrf_failed"
        else:
            code = "login_failed"
        mark_manual_action_required(db, code, now=now)
        record_provider_audit(db, action="renew_session", result="blocked", error_code=code, now=now)
        return SessionRenewalResult("manual_action_required", code)


def test_provider_connections(db, api_client, captcha_adapter) -> ConnectionCheckResult:
    """Perform only read-only dependency checks; never sync or mutate provider state."""

    api_ok = False
    captcha_ok = False
    balance: float | None = None
    error_code = ""
    try:
        account = api_client.get_account()
        api_ok = isinstance(account, dict)
    except Exception:  # noqa: BLE001 - read-only adapter failures map to safe status
        error_code = "provider_error"
    try:
        getter = getattr(captcha_adapter, "get_balance", None)
        if getter is None:
            raise RuntimeError("captcha balance unavailable")
        balance = float(getter())
        captcha_ok = balance >= 0
    except Exception:  # noqa: BLE001 - read-only adapter failures map to safe status
        error_code = error_code or "captcha_timeout"
    return ConnectionCheckResult(api_ok, captcha_ok, balance, error_code)


__all__ = [
    "BrowserSessionAdapter",
    "CaptchaAdapter",
    "ConnectionCheckResult",
    "SessionRenewalResult",
    "clear_provider_secret",
    "ensure_proxiware_security_schema",
    "get_provider_secret",
    "get_provider_secret_metadata",
    "load_provider_session",
    "mark_manual_action_required",
    "record_provider_audit",
    "redact_provider_payload",
    "renew_provider_session",
    "save_provider_credentials",
    "save_provider_secret",
    "store_provider_session",
    "test_provider_connections",
]
