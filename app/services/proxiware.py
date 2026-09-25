from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Any

import requests

from app.crypto import decrypt_secret, encrypt_secret


class ProxiwareAPIError(RuntimeError):
    """Safe, provider-facing error with no response or credential contents."""

    def __init__(self, code: str, message: str = "Proxiware request failed", *, status_code: int | None = None):
        self.code = str(code)
        self.status_code = status_code
        super().__init__(message)


class SyncAlreadyRunning(RuntimeError):
    code = "already_running"


class SyncCancelled(RuntimeError):
    code = "canceled"


class SyncLeaseLost(RuntimeError):
    code = "lease_lost"


def _decrypted_assignment_secret(row, column: str) -> str:
    try:
        value = str(row[column] or "")
    except (IndexError, KeyError, TypeError):
        value = ""
    if not value:
        return ""
    try:
        return decrypt_secret(value)
    except ValueError:
        return ""


def assignment_identity(
    host: object, port: object, username: object = "", password: object = ""
) -> tuple[str, int, str, str]:
    """Normalize the fields whose replacement invalidates probe trust."""

    return (
        str(host or "").strip().lower(),
        int(port or 0),
        str(username or ""),
        str(password or ""),
    )


def assignment_identity_from_row(row) -> tuple[str, int, str, str]:
    return assignment_identity(
        row["host"],
        row["port"],
        _decrypted_assignment_secret(row, "username_encrypted"),
        _decrypted_assignment_secret(row, "password_encrypted"),
    )


def assignment_identity_fingerprint(host: object, port: object, username: object = "", password: object = "") -> str:
    """Return a non-reversible identity key for one provider credential."""

    normalized = "\0".join(str(value) for value in assignment_identity(host, port, username, password))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


_STATUS_CODES = {
    400: "bad_request",
    401: "authentication_error",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    429: "rate_limited",
}


class ProxiwareClient:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.proxiware.com/v1",
        timeout: tuple[float, float] = (5, 20),
        *,
        session: requests.Session | None = None,
    ):
        if (
            not str(api_key or "").strip()
            or "\n" in str(api_key)
            or "\r" in str(api_key)
            or len(str(api_key).strip()) > 512
        ):
            raise ValueError("A single-line Proxiware API key is required")
        self.api_key = str(api_key).strip()
        self.base_url = str(base_url or "").strip().rstrip("/")
        if not self.base_url:
            raise ValueError("Proxiware API base URL is required")
        try:
            connect, read = timeout
            self.timeout = (max(0.1, float(connect)), max(0.1, float(read)))
        except (TypeError, ValueError):
            raise ValueError("Proxiware timeout must be a connect/read pair") from None
        self.session = session or requests.Session()

    def _get(self, path: str) -> Any:
        url = f"{self.base_url}/{str(path).lstrip('/')}"
        try:
            response = self.session.get(
                url,
                headers={"API-KEY": self.api_key, "Accept": "application/json"},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise ProxiwareAPIError("timeout", "Proxiware request timed out") from exc
        except requests.RequestException as exc:
            raise ProxiwareAPIError("network_error", "Proxiware request failed") from exc

        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            code = _STATUS_CODES.get(status, "provider_error" if status >= 500 else "http_error")
            raise ProxiwareAPIError(code, "Proxiware request failed", status_code=status)
        try:
            return response.json()
        except (TypeError, ValueError) as exc:
            raise ProxiwareAPIError("payload_error", "Proxiware returned invalid JSON", status_code=status) from exc

    @staticmethod
    def _list_payload(payload: Any) -> list[dict[str, Any]]:
        value = payload
        if isinstance(payload, dict):
            for key in ("data", "items", "results", "proxies", "subscriptions"):
                if key in payload:
                    value = payload[key]
                    break
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ProxiwareAPIError("payload_error", "Proxiware returned an invalid list")
        return value

    def get_account(self) -> dict[str, Any]:
        payload = self._get("/account")
        if not isinstance(payload, dict):
            raise ProxiwareAPIError("payload_error", "Proxiware returned an invalid account")
        return payload

    def list_subscriptions(self, network: str = "isp") -> list[dict[str, Any]]:
        if str(network).strip().lower() != "isp":
            raise ValueError("Only the ISP static network is supported")
        return self._list_payload(self._get(f"/static/networks/{network}/subscriptions"))

    def list_subscription_proxies(self, subscription_id: int) -> list[dict[str, Any]]:
        try:
            identifier = int(subscription_id)
        except (TypeError, ValueError):
            raise ValueError("Subscription ID must be an integer") from None
        if identifier <= 0:
            raise ValueError("Subscription ID must be positive")
        return self._list_payload(self._get(f"/static/subscriptions/{identifier}/proxies"))


def load_api_key_file(path: str | Path) -> str:
    """Read one API key without accepting multiline or oversized secret files."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("Proxiware API key file could not be read") from exc
    value = raw.strip()
    if len(value) > 512 or not value or "\n" in value or "\r" in value:
        raise ValueError("Proxiware API key file must contain one short line")
    if value.startswith("PROXIWARE_API_KEY="):
        value = value.split("=", 1)[1].strip()
    if not value or "\n" in value or "\r" in value or len(value) > 512:
        raise ValueError("Proxiware API key file must contain one API key")
    return value


@dataclass(frozen=True)
class SyncResult:
    run_id: int
    added: int
    updated: int
    missing: int
    errors: int


def enqueue_sync_run(db, *, now: datetime | None = None) -> dict[str, object] | None:
    """Queue one durable sync request without contacting the provider."""

    ensure_proxiware_inventory_schema(db)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    timestamp = current.astimezone(UTC).isoformat()
    db.execute("BEGIN IMMEDIATE")
    try:
        active = db.execute(
            "SELECT id,status FROM provider_sync_runs WHERE provider='proxiware' "
            "AND status IN ('queued','running') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if active is not None:
            db.rollback()
            return None
        cursor = db.execute(
            "INSERT INTO provider_sync_runs(provider,started_at,status,error_code,error_message) "
            "VALUES('proxiware',?,'queued','','')",
            (timestamp,),
        )
        run_id = int(cursor.lastrowid)
        db.commit()
        return {"run_id": run_id, "status": "queued"}
    except Exception:
        db.rollback()
        raise


def claim_sync_run(
    db,
    *,
    now: datetime | None = None,
    lease_seconds: int = 1800,
    create_if_missing: bool = True,
) -> dict[str, object] | None:
    """Claim the sole Proxiware sync lease, preferring an existing queue item."""

    ensure_proxiware_inventory_schema(db)
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    timestamp = current.isoformat()
    lease_seconds = max(60, int(lease_seconds))
    claimed_until = (current + timedelta(seconds=lease_seconds)).isoformat()
    token = secrets.token_urlsafe(18)
    db.execute("BEGIN IMMEDIATE")
    try:
        # Legacy/crashed rows may have no lease at all.  Treat both a missing
        # lease and an expired lease as abandoned before checking ownership;
        # otherwise one historical row can block every future sync forever.
        db.execute(
            "UPDATE provider_sync_runs SET status='failed', finished_at=?, error_code='lease_expired', "
            "error_message='Sync lease expired', claim_token=NULL, claimed_until=NULL "
            "WHERE provider='proxiware' AND status='running' "
            "AND (claimed_until IS NULL OR claimed_until<=?)",
            (timestamp, timestamp),
        )
        active = db.execute(
            "SELECT id FROM provider_sync_runs WHERE provider='proxiware' AND status='running' "
            "AND claimed_until>? ORDER BY id DESC LIMIT 1",
            (timestamp,),
        ).fetchone()
        if active is not None:
            db.rollback()
            return None
        queued = db.execute(
            "SELECT id FROM provider_sync_runs WHERE provider='proxiware' AND status='queued' ORDER BY id LIMIT 1"
        ).fetchone()
        if queued is not None:
            run_id = int(queued["id"])
            db.execute(
                "UPDATE provider_sync_runs SET status='running',claim_token=?,claimed_until=? WHERE id=?",
                (token, claimed_until, run_id),
            )
        elif create_if_missing:
            cursor = db.execute(
                "INSERT INTO provider_sync_runs(provider,started_at,status,error_code,error_message,claim_token,claimed_until) "
                "VALUES('proxiware',?,'running','','',?,?)",
                (timestamp, token, claimed_until),
            )
            run_id = int(cursor.lastrowid)
        else:
            db.rollback()
            return None
        db.commit()
        return {
            "run_id": run_id,
            "claim_token": token,
            "claimed_until": claimed_until,
            "lease_seconds": lease_seconds,
        }
    except Exception:
        db.rollback()
        raise


def request_sync_cancel(db, run_id: int) -> bool:
    ensure_proxiware_inventory_schema(db)
    cursor = db.execute(
        "UPDATE provider_sync_runs SET cancel_requested=1, status=CASE WHEN status='queued' THEN 'canceled' ELSE status END, "
        "finished_at=CASE WHEN status='queued' THEN datetime('now') ELSE finished_at END, "
        "error_code=CASE WHEN status='queued' THEN 'canceled' ELSE error_code END "
        "WHERE id=? AND provider='proxiware' AND status IN ('queued','running') "
        "AND COALESCE(cancel_requested,0)=0",
        (int(run_id),),
    )
    db.commit()
    return cursor.rowcount == 1


def _raise_if_sync_cancelled(
    db,
    run_id: int,
    claim_token: str,
    *,
    lease_seconds: int = 1800,
    now: datetime | None = None,
) -> None:
    _renew_sync_lease(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
    row = db.execute(
        "SELECT cancel_requested FROM provider_sync_runs WHERE id=? AND provider='proxiware' "
        "AND status='running' AND claim_token=?",
        (int(run_id), str(claim_token)),
    ).fetchone()
    if row and int(row["cancel_requested"] or 0):
        timestamp = _iso(now)
        cursor = db.execute(
            "UPDATE provider_sync_runs SET status='canceled', finished_at=?, error_code='canceled', "
            "claim_token=NULL, claimed_until=NULL WHERE id=? AND provider='proxiware' "
            "AND status='running' AND claim_token=?",
            (timestamp, int(run_id), str(claim_token)),
        )
        db.commit()
        if cursor.rowcount == 1:
            raise SyncCancelled("Proxiware sync canceled")
    if row is None:
        raise SyncLeaseLost("Proxiware sync lease is no longer owned")


def ensure_proxiware_inventory_schema(db) -> None:
    """Create the read/sync tables without requiring a separate migration CLI."""
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS provider_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            external_id TEXT NOT NULL,
            network TEXT NOT NULL DEFAULT 'isp',
            location TEXT NOT NULL DEFAULT '',
            quantity INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            auto_renew INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            eligible_count INTEGER NOT NULL DEFAULT 0,
            connections INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            raw_metadata TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL DEFAULT '',
            last_seen_at TEXT NOT NULL DEFAULT '',
            missing_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(provider, external_id)
        );
        CREATE TABLE IF NOT EXISTS provider_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscription_id INTEGER NOT NULL REFERENCES provider_subscriptions(id) ON DELETE CASCADE,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            external_id TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            port INTEGER NOT NULL DEFAULT 0,
            username_encrypted TEXT NOT NULL DEFAULT '',
            password_encrypted TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            qualification TEXT NOT NULL DEFAULT 'pending',
            provider_eligible INTEGER NOT NULL DEFAULT 0,
            live_status TEXT NOT NULL DEFAULT 'pending',
            exit_ip TEXT,
            assigned_at TEXT,
            last_seen_at TEXT,
            missing_at TEXT,
             replacement_ready_at TEXT,
             identity_fingerprint TEXT NOT NULL DEFAULT '',
             identity_generation INTEGER NOT NULL DEFAULT 1,
             created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(provider, external_id)
        );
        CREATE TABLE IF NOT EXISTS provider_sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            added_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            missing_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            error_code TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '',
            claim_token TEXT,
            claimed_until TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            total_count INTEGER NOT NULL DEFAULT 0,
            processed_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS provider_sync_runs_idx ON provider_sync_runs(provider, started_at);
        """
    )
    # The swap service may create an older compatible shape first. Add only
    # missing columns; never rewrite existing provider credentials or metadata.
    for table, definitions in {
        "provider_subscriptions": {
            "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            "raw_metadata": "TEXT NOT NULL DEFAULT '{}'",
            "missing_at": "TEXT",
            "first_seen_at": "TEXT NOT NULL DEFAULT ''",
            "last_seen_at": "TEXT NOT NULL DEFAULT ''",
        },
        "provider_assignments": {
            "missing_at": "TEXT",
            "last_seen_at": "TEXT",
            "exit_ip": "TEXT",
            "identity_fingerprint": "TEXT NOT NULL DEFAULT ''",
            "identity_generation": "INTEGER NOT NULL DEFAULT 1",
        },
        "provider_sync_runs": {
            "claim_token": "TEXT",
            "claimed_until": "TEXT",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
            "total_count": "INTEGER NOT NULL DEFAULT 0",
            "processed_count": "INTEGER NOT NULL DEFAULT 0",
        },
    }.items():
        existing = {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()}
        for name, definition in definitions.items():
            if name not in existing:
                db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}')
    db.commit()


def _iso(now: datetime | None) -> str:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat()


def _renew_sync_lease(
    db,
    run_id: int,
    claim_token: str,
    *,
    lease_seconds: int = 1800,
    now: datetime | None = None,
) -> None:
    """Extend an owned lease; never resurrect an expired/reclaimed run."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    timestamp = current.isoformat()
    claimed_until = (current + timedelta(seconds=max(60, int(lease_seconds)))).isoformat()
    was_in_transaction = db.in_transaction
    cursor = db.execute(
        "UPDATE provider_sync_runs SET claimed_until=? WHERE id=? AND provider='proxiware' "
        "AND status='running' AND claim_token=? AND claimed_until>?",
        (claimed_until, int(run_id), str(claim_token), timestamp),
    )
    if not was_in_transaction:
        db.commit()
    if cursor.rowcount != 1:
        raise SyncLeaseLost("Proxiware sync lease is no longer owned")


def _assert_sync_owner(
    db,
    run_id: int,
    claim_token: str,
    *,
    now: datetime | None = None,
) -> None:
    """Check ownership without changing or committing the current transaction."""

    timestamp = _iso(now)
    row = db.execute(
        "SELECT status,claim_token,claimed_until FROM provider_sync_runs WHERE id=? AND provider='proxiware'",
        (int(run_id),),
    ).fetchone()
    if (
        row is None
        or str(row["status"] or "") != "running"
        or str(row["claim_token"] or "") != str(claim_token)
        or not row["claimed_until"]
        or str(row["claimed_until"]) <= timestamp
    ):
        raise SyncLeaseLost("Proxiware sync lease is no longer owned")


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, str):
        return int(value.strip().lower() in {"1", "true", "yes", "on", "active"})
    return int(bool(value))


def _safe_metadata(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    values = {
        key: payload[key] for key in keys if key in payload and key not in {"username", "password", "token", "key"}
    }
    return json.dumps(values, sort_keys=True, separators=(",", ":"), default=str)


def _required_id(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get("id", payload.get("external_id"))
    if value is None or str(value).strip() == "":
        return None
    return str(value).strip()


def sync_proxiware_inventory(db, client: ProxiwareClient, *, now: datetime | None = None) -> SyncResult:
    """Fetch and atomically upsert the provider's static ISP inventory."""
    ensure_proxiware_inventory_schema(db)
    claim = claim_sync_run(db, now=now)
    if claim is None:
        raise SyncAlreadyRunning("Proxiware sync is already running")
    run_id = int(claim["run_id"])
    claim_token = str(claim["claim_token"])
    lease_seconds = int(claim.get("lease_seconds") or 1800)
    started_monotonic = monotonic()
    added = updated = missing = errors = 0
    seen_subscriptions: set[str] = set()
    seen_assignments: set[str] = set()
    try:
        subscriptions = client.list_subscriptions("isp")
        _raise_if_sync_cancelled(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
        if not isinstance(subscriptions, list):
            raise ProxiwareAPIError("payload_error", "Proxiware returned an invalid subscription list")
        db.execute("UPDATE provider_sync_runs SET total_count=? WHERE id=?", (len(subscriptions), run_id))
        db.commit()
        for index, raw_subscription in enumerate(subscriptions, 1):
            _raise_if_sync_cancelled(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
            external_id = _required_id(raw_subscription)
            subscription_id = _int_or_none(raw_subscription.get("id")) if isinstance(raw_subscription, dict) else None
            if external_id is None or subscription_id is None or subscription_id <= 0:
                errors += 1
                db.execute("UPDATE provider_sync_runs SET processed_count=? WHERE id=?", (index, run_id))
                db.commit()
                continue
            proxies = client.list_subscription_proxies(subscription_id)
            if not isinstance(proxies, list):
                raise ProxiwareAPIError("payload_error", "Proxiware returned an invalid proxy list")
            db.execute("BEGIN IMMEDIATE")
            _renew_sync_lease(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
            subscription = raw_subscription
            seen_subscriptions.add(external_id)
            now_iso = _iso(now)
            values = (
                "proxiware",
                external_id,
                str(subscription.get("network") or "isp"),
                str(subscription.get("location") or ""),
                _int_or_none(subscription.get("quantity")) or 0,
                _int_or_none(subscription.get("expires_at")),
                _bool_int(subscription.get("auto_renew")),
                str(subscription.get("status") or "active"),
                _int_or_none(subscription.get("eligible_count", subscription.get("eligible"))),
                _int_or_none(subscription.get("connections", subscription.get("connections_count"))),
                _safe_metadata(subscription, ("network", "location", "quantity", "expires_at", "auto_renew", "status")),
                now_iso,
                now_iso,
                None,
                now_iso,
                now_iso,
            )
            existing = db.execute(
                "SELECT * FROM provider_subscriptions WHERE provider=? AND external_id=?",
                ("proxiware", external_id),
            ).fetchone()
            if existing is None:
                db.execute(
                    """
                    INSERT INTO provider_subscriptions(
                        provider, external_id, network, location, quantity, expires_at, auto_renew, status,
                        eligible_count, connections, metadata_json, first_seen_at, last_seen_at, missing_at,
                        created_at, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    values,
                )
                added += 1
            else:
                changed = any(
                    existing[key] != value
                    for key, value in zip(
                        (
                            "provider",
                            "external_id",
                            "network",
                            "location",
                            "quantity",
                            "expires_at",
                            "auto_renew",
                            "status",
                            "eligible_count",
                            "connections",
                            "metadata_json",
                        ),
                        values[:11],
                        strict=True,
                    )
                )
                db.execute(
                    """
                    UPDATE provider_subscriptions SET network=?, location=?, quantity=?, expires_at=?, auto_renew=?,
                        status=?, eligible_count=?, connections=?, metadata_json=?, last_seen_at=?, missing_at=NULL,
                        updated_at=? WHERE provider=? AND external_id=?
                    """,
                    (*values[2:11], now_iso, now_iso, "proxiware", external_id),
                )
                updated += int(changed)
            subscription_id = db.execute(
                "SELECT id FROM provider_subscriptions WHERE provider=? AND external_id=?",
                ("proxiware", external_id),
            ).fetchone()[0]
            for raw_proxy in proxies:
                proxy_id = _required_id(raw_proxy)
                host = str(raw_proxy.get("host") or "").strip() if isinstance(raw_proxy, dict) else ""
                port = _int_or_none(raw_proxy.get("port")) if isinstance(raw_proxy, dict) else None
                if proxy_id is None or not host or port is None or not 1 <= port <= 65535:
                    errors += 1
                    continue
                seen_assignments.add(proxy_id)
                existing_proxy = db.execute(
                    "SELECT * FROM provider_assignments WHERE provider=? AND external_id=?",
                    ("proxiware", proxy_id),
                ).fetchone()
                country = (
                    str(raw_proxy.get("country") or "").upper()[:8]
                    if "country" in raw_proxy
                    else str(existing_proxy["country"] if existing_proxy else "")
                )
                status = (
                    str(raw_proxy.get("status") or "active")
                    if "status" in raw_proxy
                    else str(existing_proxy["status"] if existing_proxy else "active")
                )
                qualification = (
                    str(raw_proxy.get("qualification") or "pending")
                    if "qualification" in raw_proxy
                    else str(existing_proxy["qualification"] if existing_proxy else "pending")
                )
                if "provider_eligible" in raw_proxy:
                    provider_eligible = _bool_int(raw_proxy.get("provider_eligible"))
                elif "eligible" in raw_proxy:
                    provider_eligible = _bool_int(raw_proxy.get("eligible"))
                else:
                    provider_eligible = int(existing_proxy["provider_eligible"] or 0) if existing_proxy else 0
                live_status = (
                    str(raw_proxy.get("live_status") or "pending")
                    if "live_status" in raw_proxy
                    else str(existing_proxy["live_status"] if existing_proxy else "pending")
                )
                username_encrypted = (
                    encrypt_secret(str(raw_proxy.get("username") or ""))
                    if "username" in raw_proxy
                    else str(existing_proxy["username_encrypted"] if existing_proxy else "")
                )
                password_encrypted = (
                    encrypt_secret(str(raw_proxy.get("password") or ""))
                    if "password" in raw_proxy
                    else str(existing_proxy["password_encrypted"] if existing_proxy else "")
                )
                username = (
                    str(raw_proxy.get("username") or "")
                    if "username" in raw_proxy
                    else _decrypted_assignment_secret(existing_proxy, "username_encrypted")
                    if existing_proxy
                    else ""
                )
                password = (
                    str(raw_proxy.get("password") or "")
                    if "password" in raw_proxy
                    else _decrypted_assignment_secret(existing_proxy, "password_encrypted")
                    if existing_proxy
                    else ""
                )
                identity_fingerprint = assignment_identity_fingerprint(host, port, username, password)
                identity_changed = bool(
                    existing_proxy
                    and assignment_identity_from_row(existing_proxy)
                    != assignment_identity(host, port, username, password)
                )
                identity_generation = (
                    int(existing_proxy["identity_generation"] or 1) + int(identity_changed) if existing_proxy else 1
                )
                if identity_changed:
                    qualification = "pending"
                    live_status = "pending"
                proxy_values = (
                    "proxiware",
                    int(subscription_id),
                    proxy_id,
                    host,
                    port,
                    username_encrypted,
                    password_encrypted,
                    country,
                    status,
                    qualification,
                    provider_eligible,
                    live_status,
                    str(raw_proxy.get("exit_ip") or "") or None if "exit_ip" in raw_proxy else None,
                    now_iso,
                    now_iso,
                    None,
                    None,
                    identity_fingerprint,
                    identity_generation,
                    now_iso,
                    now_iso,
                )
                if existing_proxy is None:
                    db.execute(
                        """
                        INSERT INTO provider_assignments(
                            provider, subscription_id, external_id, host, port, username_encrypted, password_encrypted,
                            country, status, qualification, provider_eligible, live_status, exit_ip, assigned_at,
                            last_seen_at, missing_at, replacement_ready_at, identity_fingerprint, identity_generation,
                            created_at, updated_at
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        proxy_values,
                    )
                    added += 1
                else:
                    changed = identity_changed or any(
                        existing_proxy[key] != value
                        for key, value in zip(
                            (
                                "subscription_id",
                                "host",
                                "port",
                                "country",
                                "status",
                                "qualification",
                                "provider_eligible",
                                "live_status",
                            ),
                            (
                                int(subscription_id),
                                host,
                                port,
                                country,
                                status,
                                qualification,
                                provider_eligible,
                                live_status,
                            ),
                            strict=True,
                        )
                    )
                    db.execute(
                        """
                        UPDATE provider_assignments SET subscription_id=?, host=?, port=?, username_encrypted=?,
                            password_encrypted=?, country=?, status=?, qualification=?, provider_eligible=?,
                            live_status=?, exit_ip=CASE WHEN ? THEN NULL ELSE exit_ip END,
                            protocol=CASE WHEN ? THEN 'unknown' ELSE protocol END,
                            egress_verified_at=CASE WHEN ? THEN NULL ELSE egress_verified_at END,
                            last_checked_at=CASE WHEN ? THEN NULL ELSE last_checked_at END,
                            last_error_code=CASE WHEN ? THEN '' ELSE last_error_code END,
                            duplicate_egress=CASE WHEN ? THEN 0 ELSE duplicate_egress END,
                            distribution_enabled=CASE WHEN ? THEN 0 ELSE distribution_enabled END,
                            qualification_next_check_at=CASE WHEN ? THEN NULL ELSE qualification_next_check_at END,
                            qualification_claimed_until=CASE WHEN ? THEN NULL ELSE qualification_claimed_until END,
                            qualification_claim_token=CASE WHEN ? THEN NULL ELSE qualification_claim_token END,
                            identity_fingerprint=?, identity_generation=?, last_seen_at=?, missing_at=NULL,
                            updated_at=? WHERE provider=? AND external_id=?
                        """,
                        (
                            int(subscription_id),
                            host,
                            port,
                            proxy_values[5],
                            proxy_values[6],
                            country,
                            status,
                            qualification,
                            provider_eligible,
                            live_status,
                            *([int(identity_changed)] * 10),
                            identity_fingerprint,
                            identity_generation,
                            now_iso,
                            now_iso,
                            "proxiware",
                            proxy_id,
                        ),
                    )
                    updated += int(changed)
            _assert_sync_owner(db, run_id, claim_token, now=now)
            db.commit()
            db.execute("UPDATE provider_sync_runs SET processed_count=? WHERE id=?", (index, run_id))
            db.commit()
        _raise_if_sync_cancelled(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
        db.execute("BEGIN IMMEDIATE")
        _renew_sync_lease(db, run_id, claim_token, lease_seconds=lease_seconds, now=now)
        for row in db.execute(
            "SELECT id, external_id FROM provider_subscriptions WHERE provider='proxiware' AND missing_at IS NULL"
        ).fetchall():
            if str(row["external_id"]) not in seen_subscriptions:
                db.execute(
                    "UPDATE provider_subscriptions SET status='missing', missing_at=?, updated_at=? WHERE id=?",
                    (_iso(now), _iso(now), row["id"]),
                )
                missing += 1
        for row in db.execute(
            "SELECT id, external_id FROM provider_assignments WHERE provider='proxiware' AND missing_at IS NULL"
        ).fetchall():
            if str(row["external_id"]) not in seen_assignments:
                db.execute(
                    "UPDATE provider_assignments SET status='missing', missing_at=?, updated_at=? WHERE id=?",
                    (_iso(now), _iso(now), row["id"]),
                )
                missing += 1
        finished = _iso(now)
        _assert_sync_owner(db, run_id, claim_token, now=now)
        cursor = db.execute(
            "UPDATE provider_sync_runs SET finished_at=?, duration_ms=?, added_count=?, updated_count=?, missing_count=?, error_count=?, status='success', claim_token=NULL, claimed_until=NULL, processed_count=? WHERE id=? AND provider='proxiware' AND status='running' AND claim_token=?",
            (
                finished,
                max(0, round((monotonic() - started_monotonic) * 1000)),
                added,
                updated,
                missing,
                errors,
                len(subscriptions),
                run_id,
                claim_token,
            ),
        )
        if cursor.rowcount != 1:
            raise SyncLeaseLost("Proxiware sync lease is no longer owned")
        db.commit()
        return SyncResult(run_id, added, updated, missing, errors)
    except (SyncCancelled, SyncLeaseLost):
        if db.in_transaction:
            db.rollback()
        raise
    except Exception as exc:
        if db.in_transaction:
            db.rollback()
        code = exc.code if isinstance(exc, ProxiwareAPIError) else "provider_error"
        db.execute(
            "UPDATE provider_sync_runs SET finished_at=?, duration_ms=?, status='failed', error_code=?, error_message=?, claim_token=NULL, claimed_until=NULL WHERE id=? AND provider='proxiware' AND status='running' AND claim_token=?",
            (
                _iso(now),
                max(0, round((monotonic() - started_monotonic) * 1000)),
                code,
                "Proxiware sync failed",
                run_id,
                claim_token,
            ),
        )
        db.commit()
        raise
