"""Durable, fail-closed Proxiware swap state machine.

This module deliberately contains no HTTP/browser code.  Provider adapters are
injected by the worker, while this module owns the SQLite invariants that keep
swap jobs restart-safe and auditable.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.services.proxiware_health import is_proxiware_automation_paused
from app.services.settings import get_setting

PROVIDER = "proxiware"
DEFAULT_ELIGIBLE_THRESHOLD = 1000
DEFAULT_COOLDOWN_SECONDS = 60
DEFAULT_CLAIM_SECONDS = 300
DEFAULT_RETRY_LIMIT = 3
ACTIVE_SWAP_STATES = frozenset({"pending", "running"})
SAFE_ERROR_CODES = frozenset(
    {
        "captcha_required",
        "captcha_timeout",
        "csrf_failed",
        "fingerprint_failed",
        "login_failed",
        "manual_action_required",
        "session_expired",
        "quota_exhausted",
        "stock_unavailable",
        "provider_forbidden",
        "provider_conflict",
        "provider_timeout",
        "provider_error",
    }
)
GUARD_ERROR_CODES = frozenset(
    {
        "not_live",
        "not_risk",
        "provider_ineligible",
        "connections_limit",
        "quota_exhausted",
        "cooldown",
        "duplicate_egress",
        "manual_action_required",
    }
)
MANUAL_ACTION_CODES = frozenset(
    {
        "captcha_required",
        "captcha_timeout",
        "csrf_failed",
        "fingerprint_failed",
        "login_failed",
        "manual_action_required",
        "session_expired",
        "quota_exhausted",
        "stock_unavailable",
        "provider_forbidden",
    }
)
_SAFE_CODE = re.compile(r"[^a-z0-9_:-]+")


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    return current.astimezone(UTC) if current.tzinfo else current.replace(tzinfo=UTC)


def _iso(value: datetime | None = None) -> str:
    return _now(value).isoformat()


def _set_setting_no_commit(db, key: str, value: str, *, now: datetime | None = None) -> None:
    db.execute(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
        (str(key), str(value), _iso(now)),
    )


def _safe_code(value: object, default: str = "provider_error") -> str:
    candidate = _SAFE_CODE.sub("_", str(value or "").strip().lower()).strip("_")[:64]
    return candidate if candidate in SAFE_ERROR_CODES else default


def _safe_guard_code(value: object) -> str:
    candidate = _SAFE_CODE.sub("_", str(value or "").strip().lower()).strip("_")[:64]
    return candidate if candidate in GUARD_ERROR_CODES else "manual_action_required"


def _as_bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "eligible", "allow"}


def _column_names(db, table: str) -> set[str]:
    return {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _table_exists(db, table: str) -> bool:
    return (
        db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (str(table),),
        ).fetchone()
        is not None
    )


def _ensure_columns(db, table: str, definitions: dict[str, str]) -> None:
    existing = _column_names(db, table)
    for name, definition in definitions.items():
        if name not in existing:
            db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}')


def ensure_proxiware_swap_schema(db) -> None:
    """Create the provider state tables and compatibility columns idempotently."""

    owns_bootstrap_transaction = not db.in_transaction

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
            swap_quota INTEGER NOT NULL DEFAULT -1,
            swap_used INTEGER NOT NULL DEFAULT 0,
            last_swap_reason TEXT NOT NULL DEFAULT '',
            last_swap_checked_at TEXT,
            last_swap_success_at TEXT,
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
            replacement_ready_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(provider, external_id)
        );
        CREATE TABLE IF NOT EXISTS swap_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            subscription_id INTEGER NOT NULL REFERENCES provider_subscriptions(id) ON DELETE CASCADE,
            old_assignment_id INTEGER,
            new_assignment_id INTEGER,
            state TEXT NOT NULL DEFAULT 'pending',
            reason TEXT NOT NULL DEFAULT 'queued',
            error_code TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            claim_token TEXT,
            claimed_until TEXT,
            blocked_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swap_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            swap_job_id INTEGER NOT NULL UNIQUE REFERENCES swap_jobs(id) ON DELETE CASCADE,
            old_assignment_external_id TEXT NOT NULL,
            new_assignment_external_id TEXT NOT NULL,
            success_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS provider_credentials (
            name TEXT PRIMARY KEY,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            secret_encrypted TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS provider_sessions (
            provider TEXT PRIMARY KEY,
            cookie_encrypted TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            state TEXT NOT NULL DEFAULT 'missing',
            last_error_code TEXT NOT NULL DEFAULT '',
            renewed_at TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS provider_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            actor_id INTEGER,
            action TEXT NOT NULL,
            target_id TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT '',
            error_code TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS provider_action_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL DEFAULT 'proxiware',
            actor_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS swap_jobs_one_active_idx
            ON swap_jobs(subscription_id) WHERE state IN ('pending','running');
        CREATE INDEX IF NOT EXISTS swap_jobs_due_idx
            ON swap_jobs(state, claimed_until, created_at);
        CREATE INDEX IF NOT EXISTS swap_jobs_subscription_idx
            ON swap_jobs(subscription_id, state, updated_at);
        CREATE INDEX IF NOT EXISTS provider_assignments_subscription_idx
            ON provider_assignments(subscription_id, status, live_status, qualification);
        CREATE INDEX IF NOT EXISTS provider_audit_events_idx
            ON provider_audit_events(provider, created_at);
        CREATE INDEX IF NOT EXISTS provider_action_attempts_idx
            ON provider_action_attempts(actor_id, action, attempted_at);
        """
    )
    # Task 2 may have created the provider tables with a narrower column set.
    if _column_names(db, "provider_subscriptions"):
        _ensure_columns(
            db,
            "provider_subscriptions",
            {
                "swap_quota": "INTEGER NOT NULL DEFAULT -1",
                "swap_used": "INTEGER NOT NULL DEFAULT 0",
                "last_swap_reason": "TEXT NOT NULL DEFAULT ''",
                "last_swap_checked_at": "TEXT",
                "last_swap_success_at": "TEXT",
                "eligible_count": "INTEGER NOT NULL DEFAULT 0",
                "connections": "INTEGER NOT NULL DEFAULT 0",
                "status": "TEXT NOT NULL DEFAULT 'active'",
            },
        )
    if _column_names(db, "provider_assignments"):
        _ensure_columns(
            db,
            "provider_assignments",
            {
                "status": "TEXT NOT NULL DEFAULT 'active'",
                "qualification": "TEXT NOT NULL DEFAULT 'pending'",
                "provider_eligible": "INTEGER NOT NULL DEFAULT 0",
                "live_status": "TEXT NOT NULL DEFAULT 'pending'",
                "replacement_ready_at": "TEXT",
                "host": "TEXT NOT NULL DEFAULT ''",
                "port": "INTEGER NOT NULL DEFAULT 0",
                "country": "TEXT NOT NULL DEFAULT ''",
                "protocol": "TEXT NOT NULL DEFAULT 'unknown'",
                "last_checked_at": "TEXT",
                "egress_verified_at": "TEXT",
                "last_error_code": "TEXT NOT NULL DEFAULT ''",
                "duplicate_egress": "INTEGER NOT NULL DEFAULT 0",
                "distribution_enabled": "INTEGER NOT NULL DEFAULT 0",
                "updated_at": "TEXT NOT NULL DEFAULT ''",
                "qualification_next_check_at": "TEXT",
                "qualification_claimed_until": "TEXT",
                "qualification_claim_token": "TEXT",
                "qualification_attempts": "INTEGER NOT NULL DEFAULT 0",
            },
        )
    _ensure_columns(db, "provider_credentials", {"provider": "TEXT NOT NULL DEFAULT 'proxiware'"})
    _ensure_columns(db, "provider_action_attempts", {"provider": "TEXT NOT NULL DEFAULT 'proxiware'"})
    db.execute(
        "CREATE INDEX IF NOT EXISTS provider_action_attempts_provider_idx "
        "ON provider_action_attempts(provider, actor_id, action, attempted_at)"
    )
    # A standalone provider worker may bootstrap against a provider-only DB
    # without the core user ``proxies`` table.  The reconciliation service
    # remains authoritative in that case; install triggers only when the
    # table and required columns are present.
    proxy_columns = _column_names(db, "proxies") if _table_exists(db, "proxies") else set()
    if {"archived_at", "exit_ip", "egress_attestation_source"}.issubset(proxy_columns):
        db.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS provider_egress_user_conflict_insert
            AFTER INSERT ON proxies
            WHEN NEW.archived_at IS NULL AND NEW.exit_ip IS NOT NULL
                 AND NEW.egress_attestation_source IN ('https_quorum','earnapp_tls')
            BEGIN
                UPDATE provider_assignments
                SET duplicate_egress=1, distribution_enabled=0, updated_at=datetime('now')
                WHERE provider='proxiware' AND missing_at IS NULL AND exit_ip=NEW.exit_ip;
            END;
            CREATE TRIGGER IF NOT EXISTS provider_egress_user_conflict_update
            AFTER UPDATE OF exit_ip, egress_attestation_source, archived_at ON proxies
            BEGIN
                UPDATE provider_assignments
                SET duplicate_egress=CASE
                        WHEN EXISTS (
                            SELECT 1 FROM proxies p
                            WHERE p.archived_at IS NULL AND p.exit_ip=provider_assignments.exit_ip
                              AND p.egress_attestation_source IN ('https_quorum','earnapp_tls')
                        ) THEN 1
                        WHEN id <> COALESCE(
                            (SELECT MIN(pa2.id) FROM provider_assignments pa2
                             WHERE pa2.provider='proxiware' AND pa2.missing_at IS NULL
                               AND pa2.exit_ip=provider_assignments.exit_ip), id
                        ) THEN 1
                        ELSE 0
                    END,
                    distribution_enabled=CASE
                        WHEN qualification='allow' AND live_status='live' AND provider_eligible=1
                             AND NOT EXISTS (
                                 SELECT 1 FROM proxies p
                                 WHERE p.archived_at IS NULL AND p.exit_ip=provider_assignments.exit_ip
                                   AND p.egress_attestation_source IN ('https_quorum','earnapp_tls')
                             )
                             AND id=COALESCE(
                                 (SELECT MIN(pa3.id) FROM provider_assignments pa3
                                  WHERE pa3.provider='proxiware' AND pa3.missing_at IS NULL
                                    AND pa3.exit_ip=provider_assignments.exit_ip), id
                             ) THEN 1
                        ELSE 0
                    END,
                    updated_at=datetime('now')
                WHERE provider='proxiware' AND missing_at IS NULL
                  AND exit_ip IS NOT NULL AND (exit_ip=NEW.exit_ip OR exit_ip=OLD.exit_ip);
            END;
            """
        )
    # Settings are part of the existing core schema.  INSERT OR IGNORE keeps
    # auto-swap fail-closed on every fresh installation.
    now = _iso()
    # Migrate settings once from the names used by the first workspace draft.
    # Canonical keys are the only keys written after this point.
    legacy_auto = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap_enabled'").fetchone()
    legacy_threshold = db.execute("SELECT value FROM settings WHERE key='proxiware_eligibility_threshold'").fetchone()
    if legacy_auto is not None:
        db.execute(
            "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_auto_swap',?,?)",
            (str(legacy_auto[0]), now),
        )
        db.execute("DELETE FROM settings WHERE key='proxiware_auto_swap_enabled'")
    if legacy_threshold is not None:
        db.execute(
            "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_eligible_threshold',?,?)",
            (str(legacy_threshold[0]), now),
        )
        db.execute("DELETE FROM settings WHERE key='proxiware_eligibility_threshold'")
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_auto_swap','0',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_eligible_threshold','1000',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_worker_concurrency','1',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_retry_limit','3',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_cooldown_seconds','60',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_distribution_enabled','0',?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES('proxiware_automation_paused','0',?)",
        (now,),
    )
    if owns_bootstrap_transaction and db.in_transaction:
        db.commit()


@contextmanager
def _write_transaction(db):
    owns = not db.in_transaction
    if owns:
        db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if owns and db.in_transaction:
            db.rollback()
        raise
    else:
        if owns and db.in_transaction:
            db.commit()


@dataclass(frozen=True)
class SwapDecision:
    allowed: bool
    reason: str
    subscription_id: int
    assignment_id: int | None = None

    @classmethod
    def for_subscription(
        cls,
        db,
        subscription_id: int,
        *,
        now: datetime | None = None,
        threshold: int = DEFAULT_ELIGIBLE_THRESHOLD,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
    ) -> "SwapDecision":
        current = _now(now)
        subscription = db.execute(
            "SELECT * FROM provider_subscriptions WHERE id=? AND provider=?",
            (int(subscription_id), PROVIDER),
        ).fetchone()
        if subscription is None:
            return cls(False, "manual_action_required", int(subscription_id))
        assignment = db.execute(
            "SELECT * FROM provider_assignments WHERE subscription_id=? AND provider=? "
            "AND status IN ('active','current') ORDER BY id DESC LIMIT 1",
            (int(subscription_id), PROVIDER),
        ).fetchone()
        if assignment is None:
            return cls(False, "manual_action_required", int(subscription_id))
        assignment_id = int(assignment["id"])
        live = str(assignment["live_status"] or "").strip().lower()
        if live not in {"live", "online"}:
            return cls(False, "not_live", int(subscription_id), assignment_id)
        if _as_bool(dict(assignment).get("duplicate_egress", 0)):
            return cls(False, "duplicate_egress", int(subscription_id), assignment_id)
        qualification = str(assignment["qualification"] or "").strip().lower()
        # Swaps replace only non-allow assignments.  An Allow assignment is
        # already the desired state and must remain untouched.
        if qualification not in {"risk"}:
            return cls(False, "not_risk", int(subscription_id), assignment_id)
        if not _as_bool(assignment["provider_eligible"]):
            return cls(False, "provider_ineligible", int(subscription_id), assignment_id)
        try:
            if subscription["eligible_count"] is None:
                raise ValueError
            eligible_count = int(subscription["eligible_count"])
        except (TypeError, ValueError):
            return cls(False, "manual_action_required", int(subscription_id), assignment_id)
        if eligible_count >= max(1, int(threshold)):
            return cls(False, "provider_ineligible", int(subscription_id), assignment_id)
        try:
            if subscription["connections"] is None:
                raise ValueError
            connections = int(subscription["connections"])
        except (TypeError, ValueError):
            return cls(False, "manual_action_required", int(subscription_id), assignment_id)
        if connections >= 1000:
            return cls(False, "connections_limit", int(subscription_id), assignment_id)
        try:
            quota = int(subscription["swap_quota"] or 0)
            used = int(subscription["swap_used"] or 0)
        except (TypeError, ValueError):
            quota, used = 0, 0
        if quota >= 0 and quota <= used:
            return cls(False, "quota_exhausted", int(subscription_id), assignment_id)
        ready_at = assignment["replacement_ready_at"]
        if ready_at:
            try:
                ready = datetime.fromisoformat(str(ready_at))
                ready = ready.astimezone(UTC) if ready.tzinfo else ready.replace(tzinfo=UTC)
                if ready > current:
                    return cls(False, "cooldown", int(subscription_id), assignment_id)
            except ValueError:
                return cls(False, "manual_action_required", int(subscription_id), assignment_id)
        # A subscription-level timestamp protects against replacements whose
        # old assignment was already removed from the provider response.
        last_success = subscription["last_swap_success_at"]
        if last_success:
            try:
                elapsed = current - datetime.fromisoformat(str(last_success)).astimezone(UTC)
                if elapsed < timedelta(seconds=max(60, int(cooldown_seconds))):
                    return cls(False, "cooldown", int(subscription_id), assignment_id)
            except ValueError:
                return cls(False, "manual_action_required", int(subscription_id), assignment_id)
        return cls(True, "ready", int(subscription_id), assignment_id)


def _remember_decision(db, decision: SwapDecision, *, now: datetime) -> None:
    db.execute(
        "UPDATE provider_subscriptions SET last_swap_reason=?, last_swap_checked_at=?, updated_at=? WHERE id=?",
        (decision.reason, now.isoformat(), now.isoformat(), decision.subscription_id),
    )


def queue_eligible_swaps(
    db,
    *,
    now: datetime | None = None,
    limit: int = 20,
    threshold: int | None = None,
) -> int:
    """Queue only guarded replacements; never performs a provider mutation."""

    ensure_proxiware_swap_schema(db)
    current = _now(now)
    auto_swap = get_setting(db, "proxiware_auto_swap", "0")
    if (
        auto_swap != "1"
        or is_proxiware_automation_paused(db)
        or get_setting(db, "proxiware_swap_worker_paused", "0") == "1"
    ):
        return 0
    try:
        configured_threshold = int(get_setting(db, "proxiware_eligible_threshold", str(DEFAULT_ELIGIBLE_THRESHOLD)))
    except ValueError:
        configured_threshold = DEFAULT_ELIGIBLE_THRESHOLD
    try:
        configured_cooldown = max(
            DEFAULT_COOLDOWN_SECONDS,
            int(get_setting(db, "proxiware_cooldown_seconds", str(DEFAULT_COOLDOWN_SECONDS))),
        )
    except ValueError:
        configured_cooldown = DEFAULT_COOLDOWN_SECONDS
    effective_threshold = max(1, int(threshold or configured_threshold))
    rows = db.execute(
        "SELECT id FROM provider_subscriptions WHERE provider=? AND status IN ('active','ready') "
        "ORDER BY updated_at,id LIMIT ?",
        (PROVIDER, max(0, int(limit))),
    ).fetchall()
    queued = 0
    with _write_transaction(db):
        for row in rows:
            subscription_id = int(row["id"])
            decision = SwapDecision.for_subscription(
                db,
                subscription_id,
                now=current,
                threshold=effective_threshold,
                cooldown_seconds=configured_cooldown,
            )
            _remember_decision(db, decision, now=current)
            if not decision.allowed:
                continue
            try:
                cursor = db.execute(
                    """
                    INSERT INTO swap_jobs(
                        provider,subscription_id,old_assignment_id,state,reason,attempts,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        PROVIDER,
                        subscription_id,
                        decision.assignment_id,
                        "pending",
                        "queued",
                        0,
                        current.isoformat(),
                        current.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                # The partial unique index is the race-safe one-active-job
                # guard.  Do not leak the database error to callers.
                continue
            if cursor.rowcount == 1:
                queued += 1
    return queued


def claim_next_swap(
    db,
    *,
    now: datetime | None = None,
    claim_seconds: int = DEFAULT_CLAIM_SECONDS,
    job_id: int | None = None,
):
    ensure_proxiware_swap_schema(db)
    current = _now(now)
    token = secrets.token_urlsafe(18)
    claimed_until = current + timedelta(seconds=max(30, int(claim_seconds)))
    with _write_transaction(db):
        # Recover a lease abandoned by a crashed worker before claiming the
        # next job. This makes restart behavior durable without a cleanup loop.
        db.execute(
            "UPDATE swap_jobs SET state='pending', claim_token=NULL, claimed_until=NULL, updated_at=? "
            "WHERE provider=? AND state='running' AND claimed_until IS NOT NULL AND claimed_until<=?",
            (current.isoformat(), PROVIDER, current.isoformat()),
        )
        if job_id is None:
            row = db.execute(
                "SELECT id FROM swap_jobs WHERE provider=? AND state='pending' AND "
                "(claimed_until IS NULL OR claimed_until<=?) ORDER BY created_at,id LIMIT 1",
                (PROVIDER, current.isoformat()),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT id FROM swap_jobs WHERE id=? AND provider=? AND state='pending' AND "
                "(claimed_until IS NULL OR claimed_until<=?) LIMIT 1",
                (int(job_id), PROVIDER, current.isoformat()),
            ).fetchone()
        if row is None:
            return None
        cursor = db.execute(
            "UPDATE swap_jobs SET state='running', claim_token=?, claimed_until=?, attempts=attempts+1, updated_at=? "
            "WHERE id=? AND provider=? AND state='pending' AND (claimed_until IS NULL OR claimed_until<=?)",
            (token, claimed_until.isoformat(), current.isoformat(), int(row["id"]), PROVIDER, current.isoformat()),
        )
        if cursor.rowcount != 1:
            return None
        return db.execute(
            "SELECT * FROM swap_jobs WHERE id=? AND provider=?",
            (int(row["id"]), PROVIDER),
        ).fetchone()


def revalidate_swap_job(
    db,
    job_id: int,
    *,
    now: datetime | None = None,
    allow_manual: bool = False,
) -> SwapDecision:
    """Recheck mutable swap guards after a durable claim and before adapter I/O."""

    ensure_proxiware_swap_schema(db)
    current = _now(now)
    with _write_transaction(db):
        job = db.execute(
            "SELECT state,subscription_id,old_assignment_id FROM swap_jobs WHERE id=? AND provider=?",
            (int(job_id), PROVIDER),
        ).fetchone()
        if job is None:
            raise LookupError("Swap job not found")
        if str(job["state"] or "") != "running":
            raise ValueError("Swap job is not running")
        if (
            (is_proxiware_automation_paused(db) and not allow_manual)
            or get_setting(db, "proxiware_swap_worker_paused", "0") == "1"
            or not allow_manual
            and get_setting(db, "proxiware_auto_swap", "0") != "1"
        ):
            decision = SwapDecision(False, "manual_action_required", int(job["subscription_id"]))
        else:
            decision = None
        try:
            threshold = int(get_setting(db, "proxiware_eligible_threshold", str(DEFAULT_ELIGIBLE_THRESHOLD)))
        except (TypeError, ValueError):
            threshold = DEFAULT_ELIGIBLE_THRESHOLD
        try:
            cooldown_seconds = max(
                DEFAULT_COOLDOWN_SECONDS,
                int(get_setting(db, "proxiware_cooldown_seconds", str(DEFAULT_COOLDOWN_SECONDS))),
            )
        except (TypeError, ValueError):
            cooldown_seconds = DEFAULT_COOLDOWN_SECONDS
        if decision is None:
            decision = SwapDecision.for_subscription(
                db,
                int(job["subscription_id"]),
                now=current,
                threshold=max(1, threshold),
                cooldown_seconds=cooldown_seconds,
            )
        if decision.allowed and decision.assignment_id == job["old_assignment_id"]:
            return decision
        reason = decision.reason if decision.allowed is False else "manual_action_required"
        db.execute(
            "UPDATE swap_jobs SET state='blocked', reason='guard_failed', error_code=?, blocked_at=?, "
            "claim_token=NULL, claimed_until=NULL, updated_at=? WHERE id=? AND provider=? AND state='running'",
            (
                _safe_guard_code(reason),
                current.isoformat(),
                current.isoformat(),
                int(job_id),
                PROVIDER,
            ),
        )
        return SwapDecision(False, reason, int(job["subscription_id"]), decision.assignment_id)


def _resolve_assignment(db, external_id: str):
    return db.execute(
        "SELECT * FROM provider_assignments WHERE provider=? AND external_id=?",
        (PROVIDER, str(external_id)),
    ).fetchone()


def mark_swap_success(
    db,
    job_id: int,
    *,
    old_assignment_external_id: str,
    new_assignment_external_id: str,
    success_at: datetime | None = None,
    new_assignment: dict[str, object] | None = None,
    claim_token: str | None = None,
) -> None:
    """Persist mapping before exposing a successful swap state."""

    ensure_proxiware_swap_schema(db)
    current = _now(success_at)
    old_external = str(old_assignment_external_id or "").strip()
    new_external = str(new_assignment_external_id or "").strip()
    if not old_external or not new_external or old_external == new_external:
        raise ValueError("Swap assignment mapping is invalid")
    with _write_transaction(db):
        job = db.execute(
            "SELECT * FROM swap_jobs WHERE id=? AND provider=?",
            (int(job_id), PROVIDER),
        ).fetchone()
        if job is None:
            raise LookupError("Swap job not found")
        if str(job["state"]) not in ACTIVE_SWAP_STATES:
            raise ValueError("Swap job is not active")
        if claim_token is not None and str(job["claim_token"] or "") != str(claim_token):
            raise ValueError("Swap job claim is stale")
        old = _resolve_assignment(db, old_external)
        if old is None:
            raise LookupError("Old assignment not found")
        if int(old["subscription_id"]) != int(job["subscription_id"]):
            raise ValueError("Swap old assignment subscription mismatch")
        if job["old_assignment_id"] is not None and int(old["id"]) != int(job["old_assignment_id"]):
            raise ValueError("Swap old assignment does not match job")
        new = _resolve_assignment(db, new_external)
        if new is not None and int(new["subscription_id"]) != int(job["subscription_id"]):
            raise ValueError("Swap new assignment subscription mismatch")
        try:
            cooldown_seconds = max(
                DEFAULT_COOLDOWN_SECONDS,
                int(get_setting(db, "proxiware_cooldown_seconds", str(DEFAULT_COOLDOWN_SECONDS))),
            )
        except ValueError:
            cooldown_seconds = DEFAULT_COOLDOWN_SECONDS
        ready_at = (current + timedelta(seconds=cooldown_seconds)).isoformat()
        if new is None:
            payload = dict(new_assignment or {})
            db.execute(
                """
                INSERT INTO provider_assignments(
                    subscription_id,provider,external_id,host,port,username_encrypted,password_encrypted,
                    country,status,qualification,provider_eligible,live_status,assigned_at,replacement_ready_at,
                    last_seen_at,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    int(old["subscription_id"]),
                    PROVIDER,
                    new_external,
                    str(payload.get("host") or old["host"] or ""),
                    int(payload.get("port") or old["port"] or 0),
                    str(payload.get("username_encrypted") or old["username_encrypted"] or ""),
                    str(payload.get("password_encrypted") or old["password_encrypted"] or ""),
                    str(payload.get("country") or old["country"] or ""),
                    "pending",
                    "pending",
                    0,
                    "pending",
                    current.isoformat(),
                    ready_at,
                    current.isoformat(),
                    current.isoformat(),
                    current.isoformat(),
                ),
            )
            new = _resolve_assignment(db, new_external)
        else:
            db.execute(
                "UPDATE provider_assignments SET replacement_ready_at=?, status='pending', "
                "qualification='pending', provider_eligible=0, live_status='pending', "
                "distribution_enabled=0, egress_verified_at=NULL, last_checked_at=NULL, updated_at=? WHERE id=?",
                (ready_at, current.isoformat(), int(new["id"])),
            )
        if new is None:
            raise RuntimeError("Replacement assignment could not be persisted")
        # Mapping is written first.  Any failure rolls back the whole state
        # transition, so a success can never be reported without lineage.
        db.execute(
            "INSERT INTO swap_mappings(swap_job_id,old_assignment_external_id,new_assignment_external_id,success_at,created_at) "
            "VALUES(?,?,?,?,?)",
            (int(job_id), old_external, new_external, current.isoformat(), current.isoformat()),
        )
        db.execute(
            "UPDATE provider_assignments SET status='replaced', replacement_ready_at=NULL, "
            "distribution_enabled=0, updated_at=? WHERE id=?",
            (current.isoformat(), int(old["id"])),
        )
        db.execute(
            "UPDATE swap_jobs SET state='success', reason='swapped', error_code='', old_assignment_id=?, "
            "new_assignment_id=?, claim_token=NULL, claimed_until=NULL, updated_at=? WHERE id=? AND provider=?",
            (int(old["id"]), int(new["id"]), current.isoformat(), int(job_id), PROVIDER),
        )
        db.execute(
            "UPDATE provider_subscriptions SET swap_used=swap_used+1, last_swap_reason='swapped', "
            "last_swap_checked_at=?, last_swap_success_at=?, updated_at=? WHERE id=? AND provider=?",
            (current.isoformat(), current.isoformat(), current.isoformat(), int(job["subscription_id"]), PROVIDER),
        )


def mark_swap_blocked(
    db,
    job_id: int,
    *,
    error_code: str,
    blocked_at: datetime | None = None,
    claim_token: str | None = None,
) -> None:
    ensure_proxiware_swap_schema(db)
    current = _now(blocked_at)
    safe_error = _safe_code(error_code)
    reason = "manual_action_required" if safe_error in MANUAL_ACTION_CODES else "provider_blocked"
    with _write_transaction(db):
        if claim_token is not None:
            active = db.execute(
                "SELECT claim_token,state FROM swap_jobs WHERE id=? AND provider=?",
                (int(job_id), PROVIDER),
            ).fetchone()
            if (
                active is None
                or str(active["state"]) not in ACTIVE_SWAP_STATES
                or str(active["claim_token"] or "") != str(claim_token)
            ):
                raise ValueError("Swap job claim is stale")
        cursor = db.execute(
            "UPDATE swap_jobs SET state='blocked', reason=?, error_code=?, blocked_at=?, claim_token=NULL, "
            "claimed_until=NULL, updated_at=? WHERE id=? AND provider=? AND state IN ('pending','running')",
            (reason, safe_error, current.isoformat(), current.isoformat(), int(job_id), PROVIDER),
        )
        if cursor.rowcount != 1:
            raise LookupError("Swap job not found or already terminal")
        if safe_error in MANUAL_ACTION_CODES:
            _set_setting_no_commit(db, "proxiware_auto_swap", "0", now=current)


def mark_swap_failed(
    db,
    job_id: int,
    *,
    error_code: str,
    failed_at: datetime | None = None,
    retryable: bool = True,
    retry_limit: int | None = None,
    claim_token: str | None = None,
) -> str:
    ensure_proxiware_swap_schema(db)
    current = _now(failed_at)
    safe_error = _safe_code(error_code)
    try:
        configured_limit = int(get_setting(db, "proxiware_retry_limit", str(DEFAULT_RETRY_LIMIT)))
    except ValueError:
        configured_limit = DEFAULT_RETRY_LIMIT
    maximum = max(1, int(retry_limit or configured_limit))
    with _write_transaction(db):
        job = db.execute(
            "SELECT attempts,state FROM swap_jobs WHERE id=? AND provider=?",
            (int(job_id), PROVIDER),
        ).fetchone()
        if job is None:
            raise LookupError("Swap job not found")
        if str(job["state"]) not in ACTIVE_SWAP_STATES:
            raise ValueError("Swap job is not active")
        if claim_token is not None:
            current_claim = db.execute(
                "SELECT claim_token FROM swap_jobs WHERE id=? AND provider=?",
                (int(job_id), PROVIDER),
            ).fetchone()
            if current_claim is None or str(current_claim["claim_token"] or "") != str(claim_token):
                raise ValueError("Swap job claim is stale")
        terminal = not retryable or int(job["attempts"] or 0) >= maximum
        if terminal:
            reason = "manual_action_required" if safe_error in MANUAL_ACTION_CODES else "provider_blocked"
            state = "blocked"
            blocked_at = current.isoformat()
        else:
            reason = "retry_scheduled"
            state = "pending"
            blocked_at = None
        db.execute(
            "UPDATE swap_jobs SET state=?, reason=?, error_code=?, blocked_at=?, claim_token=NULL, claimed_until=NULL, "
            "updated_at=? WHERE id=? AND provider=?",
            (state, reason, safe_error, blocked_at, current.isoformat(), int(job_id), PROVIDER),
        )
        if terminal and safe_error in MANUAL_ACTION_CODES:
            _set_setting_no_commit(db, "proxiware_auto_swap", "0", now=current)
        return state


def cancel_swap(db, job_id: int, *, now: datetime | None = None) -> None:
    ensure_proxiware_swap_schema(db)
    current = _now(now)
    with _write_transaction(db):
        cursor = db.execute(
            "UPDATE swap_jobs SET state='canceled', reason='canceled', claim_token=NULL, claimed_until=NULL, updated_at=? "
            "WHERE id=? AND provider=? AND state IN ('pending','running')",
            (current.isoformat(), int(job_id), PROVIDER),
        )
        if cursor.rowcount != 1:
            raise LookupError("Swap job not found or already terminal")


def retry_swap(db, job_id: int, *, now: datetime | None = None) -> None:
    """Requeue one terminal job after an explicit admin decision."""

    ensure_proxiware_swap_schema(db)
    current = _now(now)
    with _write_transaction(db):
        row = db.execute(
            "SELECT state FROM swap_jobs WHERE id=? AND provider=?",
            (int(job_id), PROVIDER),
        ).fetchone()
        if row is None:
            raise LookupError("Swap job not found")
        if str(row["state"] or "") not in {"failed", "blocked", "canceled"}:
            raise ValueError("Swap job is not retryable")
        db.execute(
            "UPDATE swap_jobs SET state='pending', reason='manual_retry', error_code='', "
            "blocked_at=NULL, claim_token=NULL, claimed_until=NULL, updated_at=? WHERE id=? AND provider=?",
            (current.isoformat(), int(job_id), PROVIDER),
        )


def request_manual_swap(db, job_id: int, *, now: datetime | None = None) -> None:
    """Revalidate and mark one job for explicit execution.

    Manual execution bypasses only the global auto-swap toggle. All proxy,
    provider, quota, and cooldown guards remain mandatory.
    """

    ensure_proxiware_swap_schema(db)
    current = _now(now)
    if get_setting(db, "proxiware_swap_worker_paused", "0") == "1":
        raise ValueError("Swap worker is paused")
    with _write_transaction(db):
        row = db.execute(
            "SELECT state,subscription_id,old_assignment_id FROM swap_jobs WHERE id=? AND provider=?",
            (int(job_id), PROVIDER),
        ).fetchone()
        if row is None:
            raise LookupError("Swap job not found")
        if str(row["state"] or "") not in {"pending", "failed", "blocked", "canceled"}:
            raise ValueError("Swap job is not available for manual execution")
        try:
            threshold = int(get_setting(db, "proxiware_eligible_threshold", str(DEFAULT_ELIGIBLE_THRESHOLD)))
        except ValueError:
            threshold = DEFAULT_ELIGIBLE_THRESHOLD
        try:
            cooldown_seconds = max(
                DEFAULT_COOLDOWN_SECONDS,
                int(get_setting(db, "proxiware_cooldown_seconds", str(DEFAULT_COOLDOWN_SECONDS))),
            )
        except ValueError:
            cooldown_seconds = DEFAULT_COOLDOWN_SECONDS
        decision = SwapDecision.for_subscription(
            db,
            int(row["subscription_id"]),
            now=current,
            threshold=max(1, threshold),
            cooldown_seconds=cooldown_seconds,
        )
        if not decision.allowed or decision.assignment_id != row["old_assignment_id"]:
            raise ValueError(f"Swap guards no longer pass: {decision.reason}")
        db.execute(
            "UPDATE swap_jobs SET state='pending', reason='manual_requested', error_code='', "
            "blocked_at=NULL, claim_token=NULL, claimed_until=NULL, updated_at=? WHERE id=? AND provider=?",
            (current.isoformat(), int(job_id), PROVIDER),
        )


__all__ = [
    "ACTIVE_SWAP_STATES",
    "SwapDecision",
    "cancel_swap",
    "claim_next_swap",
    "ensure_proxiware_swap_schema",
    "mark_swap_blocked",
    "mark_swap_failed",
    "mark_swap_success",
    "queue_eligible_swaps",
    "revalidate_swap_job",
    "retry_swap",
    "request_manual_swap",
]

# Compatibility re-exports keep callers on one provider service surface while
# the secret implementation remains isolated from the swap state machine.
from app.services.proxiware_credentials import (  # noqa: E402
    get_provider_secret_metadata,
    save_provider_secret,
)

__all__ += ["get_provider_secret_metadata", "save_provider_secret"]
