from __future__ import annotations

import sqlite3
from pathlib import Path

import click
from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'pending',
    earn_paused INTEGER NOT NULL DEFAULT 0,
    session_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol_hint TEXT NOT NULL DEFAULT 'auto',
    detected_protocol TEXT NOT NULL DEFAULT 'unknown',
    username_encrypted TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    credential_fingerprint TEXT NOT NULL UNIQUE,
    credential_generation INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    eligibility TEXT NOT NULL DEFAULT 'pending',
    earnapp_verdict TEXT NOT NULL DEFAULT '',
    earnapp_reason TEXT NOT NULL DEFAULT '',
    earnapp_checked_at TEXT,
    earnapp_next_check_at TEXT,
    egress_verified_at TEXT,
    egress_attestation_source TEXT NOT NULL DEFAULT '',
    earnapp_claimed_until TEXT,
    earnapp_claim_token TEXT,
    exit_ip TEXT,
    country_code TEXT NOT NULL DEFAULT '',
    duplicate_of INTEGER REFERENCES proxies(id),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    online_since TEXT,
    offline_since TEXT,
    last_checked_at TEXT,
    last_success_at TEXT,
    next_check_at TEXT,
    check_claimed_until TEXT,
    check_claim_token TEXT,
    health_mode TEXT NOT NULL DEFAULT 'strong',
    next_probe_index INTEGER NOT NULL DEFAULT 0,
    last_probe_endpoint TEXT NOT NULL DEFAULT '',
    last_latency_ms INTEGER,
    failure_kind TEXT NOT NULL DEFAULT '',
    accrual_cursor_at TEXT,
    probation_started_at TEXT,
    accumulated_online_seconds INTEGER NOT NULL DEFAULT 0,
    accumulated_offline_seconds INTEGER NOT NULL DEFAULT 0,
    continuous_dead_since TEXT,
    archived_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS proxies_due_idx
    ON proxies(archived_at, next_check_at, check_claimed_until);
CREATE INDEX IF NOT EXISTS proxies_exit_idx
    ON proxies(exit_ip, duplicate_of, created_at);
CREATE INDEX IF NOT EXISTS proxies_distribution_idx
    ON proxies(status, eligibility, duplicate_of, archived_at);
CREATE INDEX IF NOT EXISTS proxies_user_inventory_idx
    ON proxies(user_id, archived_at, status, detected_protocol, eligibility, created_at, id);
CREATE INDEX IF NOT EXISTS proxies_user_endpoint_idx
    ON proxies(user_id, archived_at, host, port, id);

CREATE TABLE IF NOT EXISTS proxy_geo_cache (
    exit_ip TEXT PRIMARY KEY,
    country_code TEXT NOT NULL DEFAULT '',
    country_name TEXT NOT NULL DEFAULT '',
    geo_source TEXT NOT NULL DEFAULT '',
    geo_confidence TEXT NOT NULL DEFAULT 'unknown',
    checked_at TEXT NOT NULL,
    retry_after TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS proxy_geo_cache_retry_idx
    ON proxy_geo_cache(retry_after);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_hash TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS registration_attempts_identity_idx
    ON registration_attempts(identity_hash, attempted_at);
CREATE INDEX IF NOT EXISTS registration_attempts_time_idx
    ON registration_attempts(attempted_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_hash TEXT NOT NULL,
    account_hash TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS login_attempts_identity_idx
    ON login_attempts(identity_hash, attempted_at);
CREATE INDEX IF NOT EXISTS login_attempts_account_idx
    ON login_attempts(account_hash, attempted_at);
CREATE INDEX IF NOT EXISTS login_attempts_time_idx
    ON login_attempts(attempted_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL DEFAULT 'managed',
    created_by_user_id INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS api_keys_active_idx
    ON api_keys(revoked_at, created_at);

CREATE TABLE IF NOT EXISTS api_key_reveals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reveal_id TEXT NOT NULL UNIQUE,
    token_encrypted TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS api_key_reveals_due_idx
    ON api_key_reveals(reveal_id, expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS earnings_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    proxy_id INTEGER NOT NULL REFERENCES proxies(id),
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    micro_usd INTEGER NOT NULL,
    bucket TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(proxy_id, started_at, ended_at, bucket)
);

CREATE INDEX IF NOT EXISTS earnings_user_bucket_idx
    ON earnings_ledger(user_id, bucket);

CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    address TEXT NOT NULL COLLATE NOCASE UNIQUE,
    locked_until TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    wallet_id INTEGER NOT NULL REFERENCES wallets(id),
    wallet_address TEXT NOT NULL DEFAULT '',
    amount_micro_usd INTEGER NOT NULL,
    fee_bps INTEGER NOT NULL DEFAULT 0,
    fee_micro_usd INTEGER NOT NULL DEFAULT 0,
    net_micro_usd INTEGER NOT NULL DEFAULT 0,
    processing_due_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'requested',
    tx_hash TEXT NOT NULL DEFAULT '',
    verification_error TEXT NOT NULL DEFAULT '',
    verification_attempts INTEGER NOT NULL DEFAULT 0,
    next_verification_at TEXT,
    verified_at TEXT,
    confirmations INTEGER NOT NULL DEFAULT 0,
    tx_block_number INTEGER,
    verification_claimed_until TEXT,
    verification_claim_token TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS payouts_user_status_idx ON payouts(user_id, status);
CREATE INDEX IF NOT EXISTS payouts_verification_due_idx
    ON payouts(status, next_verification_at, verification_claimed_until);
CREATE UNIQUE INDEX IF NOT EXISTS payouts_tx_hash_uidx
    ON payouts(lower(tx_hash)) WHERE tx_hash <> '' AND length(tx_hash)=66;
"""


PROXY_MIGRATION_COLUMNS = {
    "protocol_hint": "TEXT NOT NULL DEFAULT 'auto'",
    "detected_protocol": "TEXT NOT NULL DEFAULT 'unknown'",
    "username_encrypted": "TEXT NOT NULL DEFAULT ''",
    "password_encrypted": "TEXT NOT NULL DEFAULT ''",
    "credential_fingerprint": "TEXT NOT NULL DEFAULT ''",
    "credential_generation": "INTEGER NOT NULL DEFAULT 1",
    "eligibility": "TEXT NOT NULL DEFAULT 'pending'",
    "earnapp_verdict": "TEXT NOT NULL DEFAULT ''",
    "earnapp_reason": "TEXT NOT NULL DEFAULT ''",
    "earnapp_checked_at": "TEXT",
    "earnapp_next_check_at": "TEXT",
    "egress_verified_at": "TEXT",
    "egress_attestation_source": "TEXT NOT NULL DEFAULT ''",
    "earnapp_claimed_until": "TEXT",
    "earnapp_claim_token": "TEXT",
    "exit_ip": "TEXT",
    "country_code": "TEXT NOT NULL DEFAULT ''",
    "duplicate_of": "INTEGER REFERENCES proxies(id)",
    "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
    "online_since": "TEXT",
    "offline_since": "TEXT",
    "last_checked_at": "TEXT",
    "last_success_at": "TEXT",
    "next_check_at": "TEXT",
    "check_claimed_until": "TEXT",
    "check_claim_token": "TEXT",
    "health_mode": "TEXT NOT NULL DEFAULT 'strong'",
    "next_probe_index": "INTEGER NOT NULL DEFAULT 0",
    "last_probe_endpoint": "TEXT NOT NULL DEFAULT ''",
    "last_latency_ms": "INTEGER",
    "failure_kind": "TEXT NOT NULL DEFAULT ''",
    "accrual_cursor_at": "TEXT",
    "probation_started_at": "TEXT",
    "accumulated_online_seconds": "INTEGER NOT NULL DEFAULT 0",
    "accumulated_offline_seconds": "INTEGER NOT NULL DEFAULT 0",
    "continuous_dead_since": "TEXT",
    "archived_at": "TEXT",
    "last_error": "TEXT NOT NULL DEFAULT ''",
    "updated_at": "TEXT NOT NULL DEFAULT ''",
}

USER_MIGRATION_COLUMNS = {
    "earn_paused": "INTEGER NOT NULL DEFAULT 0",
    "session_version": "INTEGER NOT NULL DEFAULT 1",
}

PAYOUT_MIGRATION_COLUMNS = {
    "wallet_address": "TEXT NOT NULL DEFAULT ''",
    "fee_bps": "INTEGER NOT NULL DEFAULT 0",
    "fee_micro_usd": "INTEGER NOT NULL DEFAULT 0",
    "net_micro_usd": "INTEGER NOT NULL DEFAULT 0",
    "processing_due_at": "TEXT NOT NULL DEFAULT ''",
    "verification_error": "TEXT NOT NULL DEFAULT ''",
    "verification_attempts": "INTEGER NOT NULL DEFAULT 0",
    "next_verification_at": "TEXT",
    "verified_at": "TEXT",
    "confirmations": "INTEGER NOT NULL DEFAULT 0",
    "tx_block_number": "INTEGER",
    "verification_claimed_until": "TEXT",
    "verification_claim_token": "TEXT",
}


API_KEY_MIGRATION_COLUMNS = {
    "public_id": "TEXT NOT NULL DEFAULT ''",
    "name": "TEXT NOT NULL DEFAULT ''",
    "token_prefix": "TEXT NOT NULL DEFAULT ''",
    "token_hash": "TEXT NOT NULL DEFAULT ''",
    "source": "TEXT NOT NULL DEFAULT 'managed'",
    "created_by_user_id": "INTEGER",
    "created_at": "TEXT NOT NULL DEFAULT ''",
    "last_used_at": "TEXT",
    "revoked_at": "TEXT",
}


def _columns(db, table: str) -> set[str]:
    return {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _table_exists(db, table: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _add_missing_columns(db, table: str, definitions: dict[str, str]) -> None:
    existing = _columns(db, table)
    for name, definition in definitions.items():
        if name not in existing:
            db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}')


def migrate_db(db) -> None:
    """Upgrade earlier SQLite layouts before creating indexes that depend on new columns."""
    db.execute("BEGIN IMMEDIATE")
    try:
        if _table_exists(db, "users"):
            _add_missing_columns(db, "users", USER_MIGRATION_COLUMNS)
        if _table_exists(db, "payouts"):
            existing_payout_columns = _columns(db, "payouts")
            _add_missing_columns(db, "payouts", PAYOUT_MIGRATION_COLUMNS)
            if "net_micro_usd" not in existing_payout_columns:
                from datetime import UTC, datetime, timedelta

                legacy_payouts = db.execute("SELECT id, amount_micro_usd, created_at FROM payouts").fetchall()
                for payout in legacy_payouts:
                    try:
                        created_at = datetime.fromisoformat(str(payout["created_at"] or ""))
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=UTC)
                    except ValueError:
                        created_at = datetime(1970, 1, 1, tzinfo=UTC)
                    db.execute(
                        """
                        UPDATE payouts SET fee_bps=0, fee_micro_usd=0,
                            net_micro_usd=amount_micro_usd, processing_due_at=?
                        WHERE id=?
                        """,
                        ((created_at + timedelta(hours=48)).isoformat(), payout["id"]),
                    )
            if _table_exists(db, "wallets"):
                db.execute(
                    """
                    UPDATE payouts
                    SET wallet_address=COALESCE(
                        NULLIF(wallet_address,''),
                        (SELECT address FROM wallets WHERE wallets.id=payouts.wallet_id),
                        ''
                    )
                    WHERE wallet_address=''
                    """
                )
            db.execute(
                """
                UPDATE payouts
                SET verification_error=CASE
                        WHEN status='sent' AND verification_error='' THEN
                            'Legacy payout marked sent before on-chain verification'
                        ELSE verification_error
                    END
                WHERE status='sent' AND verification_error=''
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS payouts_verification_due_idx "
                "ON payouts(status,next_verification_at,verification_claimed_until)"
            )
            db.execute("DROP INDEX IF EXISTS payouts_tx_hash_uidx")
            # Legacy versions accepted duplicate full transaction hashes. Keep
            # the oldest record authoritative and clear later copies so the
            # new uniqueness invariant can be created without aborting startup.
            seen_hashes: set[str] = set()
            duplicate_rows = db.execute(
                "SELECT id, tx_hash, verification_error FROM payouts "
                "WHERE tx_hash <> '' AND length(tx_hash)=66 ORDER BY id"
            ).fetchall()
            for payout in duplicate_rows:
                normalized_hash = str(payout["tx_hash"]).strip().lower()
                if normalized_hash not in seen_hashes:
                    seen_hashes.add(normalized_hash)
                    continue
                existing_error = str(payout["verification_error"] or "").strip()
                marker = "Duplicate legacy transaction hash cleared during migration"
                error = f"{existing_error}; {marker}" if existing_error else marker
                db.execute(
                    "UPDATE payouts SET tx_hash='', verification_error=? WHERE id=?",
                    (error[:500], payout["id"]),
                )
            db.execute(
                "CREATE UNIQUE INDEX payouts_tx_hash_uidx "
                "ON payouts(lower(tx_hash)) WHERE tx_hash <> '' AND length(tx_hash)=66"
            )
        if _table_exists(db, "api_keys"):
            _add_missing_columns(db, "api_keys", API_KEY_MIGRATION_COLUMNS)
        if not _table_exists(db, "proxies"):
            db.commit()
            return
        legacy_columns = _columns(db, "proxies")
        _add_missing_columns(db, "proxies", PROXY_MIGRATION_COLUMNS)
        now = "1970-01-01T00:00:00+00:00"
        # Force any identity without a trusted attestation through one strong
        # qualification pass. This remains idempotent for databases that saw
        # an intermediate schema with the column present but blank values.
        db.execute(
            """
            UPDATE proxies SET exit_ip=NULL, egress_verified_at=NULL,
                egress_attestation_source='', country_code='', duplicate_of=NULL,
                eligibility=CASE WHEN archived_at IS NULL THEN 'pending' ELSE eligibility END,
                health_mode=CASE WHEN archived_at IS NULL THEN 'strong' ELSE health_mode END,
                next_check_at=CASE WHEN archived_at IS NULL THEN ? ELSE next_check_at END,
                earnapp_next_check_at=CASE WHEN archived_at IS NULL THEN ? ELSE earnapp_next_check_at END,
                check_claimed_until=NULL, check_claim_token=NULL,
                earnapp_claimed_until=NULL, earnapp_claim_token=NULL
            WHERE egress_attestation_source NOT IN ('https_quorum','earnapp_tls')
              AND (
                  exit_ip IS NOT NULL OR egress_verified_at IS NOT NULL OR duplicate_of IS NOT NULL
                  OR country_code<>'' OR health_mode='fast'
                  OR (archived_at IS NULL AND status='online' AND eligibility IN ('allow','risk'))
              )
            """,
            (now, now),
        )
        db.execute(
            "UPDATE proxies SET updated_at=COALESCE(NULLIF(updated_at,''), created_at, ?)",
            (now,),
        )
        db.execute(
            "UPDATE proxies SET next_check_at=COALESCE(next_check_at, created_at, ?)",
            (now,),
        )
        db.execute(
            "UPDATE proxies SET accrual_cursor_at=COALESCE(accrual_cursor_at, created_at, ?)",
            (now,),
        )
        db.execute(
            "UPDATE proxies SET probation_started_at=COALESCE(probation_started_at, created_at, ?)",
            (now,),
        )
        db.execute(
            """
            UPDATE proxies SET
                health_mode=CASE
                    WHEN status='online' AND detected_protocol IN ('http','socks5')
                         AND egress_attestation_source IN ('https_quorum','earnapp_tls') THEN 'fast'
                    ELSE COALESCE(NULLIF(health_mode,''), 'strong')
                END
            WHERE status='online'
            """
        )

        if {"username", "password"}.issubset(legacy_columns):
            from app.crypto import encrypt_secret
            from app.proxy_parser import ParsedProxy
            from app.services.proxies import credential_fingerprint

            rows = db.execute(
                "SELECT * FROM proxies WHERE username_encrypted='' OR password_encrypted='' OR credential_fingerprint=''"
            ).fetchall()
            for row in rows:
                parsed = ParsedProxy(
                    str(row["protocol_hint"] or "auto"),
                    str(row["host"]),
                    int(row["port"]),
                    str(row["username"] or ""),
                    str(row["password"] or ""),
                )
                db.execute(
                    "UPDATE proxies SET username_encrypted=?, password_encrypted=?, credential_fingerprint=? WHERE id=?",
                    (
                        encrypt_secret(parsed.username),
                        encrypt_secret(parsed.password),
                        credential_fingerprint(parsed),
                        row["id"],
                    ),
                )
            # Remove the old plaintext columns' contents after every row has
            # been encrypted successfully. The columns remain only for
            # schema compatibility with older tooling.
            db.execute("UPDATE proxies SET username='', password=''")

        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS proxies_credential_fingerprint_uidx "
            "ON proxies(credential_fingerprint) WHERE credential_fingerprint <> ''"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS proxies_due_idx ON proxies(archived_at,next_check_at,check_claimed_until)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS proxies_exit_idx ON proxies(exit_ip,duplicate_of,created_at)")
        db.execute(
            "CREATE INDEX IF NOT EXISTS proxies_distribution_idx "
            "ON proxies(status,eligibility,duplicate_of,archived_at)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS proxies_user_inventory_idx "
            "ON proxies(user_id,archived_at,status,detected_protocol,eligibility,created_at,id)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS proxies_user_endpoint_idx ON proxies(user_id,archived_at,host,port,id)")
        if _table_exists(db, "api_keys"):
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS api_keys_public_id_uidx ON api_keys(public_id) WHERE public_id <> ''"
            )
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS api_keys_token_hash_uidx "
                "ON api_keys(token_hash) WHERE token_hash <> ''"
            )
            db.execute("CREATE INDEX IF NOT EXISTS api_keys_active_idx ON api_keys(revoked_at, created_at)")
        db.commit()
    except Exception:
        db.rollback()
        raise


DEFAULT_SETTINGS = {
    "health_interval_minutes": "60",
    "health_concurrency": "5",
    "health_per_host_concurrency": "2",
    "health_retry_first_minutes": "5",
    "health_retry_second_minutes": "15",
    "health_stale_minutes": "120",
    "api_include_allow": "1",
    "api_include_risk": "1",
    "earnapp_refresh_hours": "168",
}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database = Path(current_app.config["DATABASE"])
        database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database, timeout=30, detect_types=sqlite3.PARSE_DECLTYPES)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    migrate_db(db)
    db.executescript(SCHEMA)
    db.executemany(
        "INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES (?, ?, datetime('now'))",
        DEFAULT_SETTINGS.items(),
    )
    db.commit()


@click.command("init-db")
def init_db_command() -> None:
    init_db()
    click.echo("Initialized Earn Proxy database.")


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    with app.app_context():
        init_db()
