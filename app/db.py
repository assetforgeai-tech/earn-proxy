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
    earnapp_claimed_until TEXT,
    earnapp_claim_token TEXT,
    exit_ip TEXT,
    country_code TEXT NOT NULL DEFAULT '',
    duplicate_of INTEGER REFERENCES proxies(id),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    online_since TEXT,
    offline_since TEXT,
    last_checked_at TEXT,
    next_check_at TEXT,
    check_claimed_until TEXT,
    check_claim_token TEXT,
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

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

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
    amount_micro_usd INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested',
    tx_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS payouts_user_status_idx ON payouts(user_id, status);
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
    "earnapp_claimed_until": "TEXT",
    "earnapp_claim_token": "TEXT",
    "exit_ip": "TEXT",
    "country_code": "TEXT NOT NULL DEFAULT ''",
    "duplicate_of": "INTEGER REFERENCES proxies(id)",
    "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
    "online_since": "TEXT",
    "offline_since": "TEXT",
    "last_checked_at": "TEXT",
    "next_check_at": "TEXT",
    "check_claimed_until": "TEXT",
    "check_claim_token": "TEXT",
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
    if _table_exists(db, "users"):
        _add_missing_columns(db, "users", USER_MIGRATION_COLUMNS)
    if not _table_exists(db, "proxies"):
        return
    legacy_columns = _columns(db, "proxies")
    _add_missing_columns(db, "proxies", PROXY_MIGRATION_COLUMNS)
    now = "1970-01-01T00:00:00+00:00"
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

    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS proxies_credential_fingerprint_uidx ON proxies(credential_fingerprint)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS proxies_due_idx ON proxies(archived_at,next_check_at,check_claimed_until)")
    db.execute("CREATE INDEX IF NOT EXISTS proxies_exit_idx ON proxies(exit_ip,duplicate_of,created_at)")
    db.execute(
        "CREATE INDEX IF NOT EXISTS proxies_distribution_idx ON proxies(status,eligibility,duplicate_of,archived_at)"
    )
    db.commit()


DEFAULT_SETTINGS = {
    "health_interval_minutes": "60",
    "health_concurrency": "5",
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
