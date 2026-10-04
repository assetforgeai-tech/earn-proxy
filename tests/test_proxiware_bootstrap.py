from __future__ import annotations

import sqlite3

from app import create_app
from app.db import get_db


def _app(database):
    return create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "bootstrap-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
            "CSRF_ENABLED": False,
        }
    )


def test_fresh_app_bootstraps_all_provider_tables_and_canonical_settings(tmp_path):
    app = _app(tmp_path / "fresh.db")
    with app.app_context():
        db = get_db()
        tables = {
            row["name"]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'provider_%'"
            ).fetchall()
        }
        keys = {row["key"] for row in db.execute("SELECT key FROM settings WHERE key LIKE 'proxiware_%'").fetchall()}

    assert {
        "provider_subscriptions",
        "provider_assignments",
        "provider_sync_runs",
        "provider_credentials",
        "provider_sessions",
        "provider_audit_events",
    }.issubset(tables)
    assert {
        "proxiware_auto_swap",
        "proxiware_allow_mutation",
        "proxiware_eligible_threshold",
        "proxiware_worker_concurrency",
        "proxiware_retry_limit",
        "proxiware_cooldown_seconds",
    }.issubset(keys)
    assert app.config["PROXIWARE_ACTION_RATE_LIMIT"] == 10
    assert app.config["PROXIWARE_ACTION_RATE_WINDOW_SECONDS"] == 60
    assert app.config["PROXIWARE_LOGIN_URL"] == "https://app.proxiware.com/auth/login?redirect=%2F"
    assert app.config["PROXIWARE_HCAPTCHA_SITE_KEY"] == ""


def test_legacy_auto_swap_setting_is_migrated_once_and_not_written_back(tmp_path):
    database = tmp_path / "legacy-settings.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
        INSERT INTO settings VALUES
          ('proxiware_auto_swap_enabled', '1', '2026-01-01T00:00:00+00:00'),
          ('proxiware_eligibility_threshold', '777', '2026-01-01T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    app = _app(database)
    with app.app_context():
        db = get_db()
        values = dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_%'").fetchall())

    assert values["proxiware_auto_swap"] == "1"
    assert values["proxiware_allow_mutation"] == "1"
    assert values["proxiware_eligible_threshold"] == "777"
    assert "proxiware_auto_swap_enabled" not in values
    assert "proxiware_eligibility_threshold" not in values


def test_runtime_allow_mutation_switch_synchronizes_auto_swap(tmp_path):
    app = _app(tmp_path / "mutation-policy.db")
    from app.services.proxiware_health import set_proxiware_runtime_mutation

    with app.app_context():
        db = get_db()
        set_proxiware_runtime_mutation(db, True)
        db.commit()
        enabled = dict(
            db.execute(
                "SELECT key,value FROM settings WHERE key IN ('proxiware_auto_swap','proxiware_allow_mutation')"
            ).fetchall()
        )
        set_proxiware_runtime_mutation(db, False)
        db.commit()
        disabled = dict(
            db.execute(
                "SELECT key,value FROM settings WHERE key IN ('proxiware_auto_swap','proxiware_allow_mutation')"
            ).fetchall()
        )

    assert enabled == {"proxiware_auto_swap": "1", "proxiware_allow_mutation": "1"}
    assert disabled == {"proxiware_auto_swap": "0", "proxiware_allow_mutation": "0"}


def test_swap_schema_does_not_require_core_proxies_table(tmp_path):
    database = tmp_path / "provider-only.db"
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    connection.commit()
    connection.close()

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    from app.services.proxiware_swap import ensure_proxiware_swap_schema

    ensure_proxiware_swap_schema(connection)
    assert connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='swap_jobs'").fetchone()
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND name='provider_egress_user_conflict_insert'"
        ).fetchone()
        is None
    )
    connection.close()


def test_provider_session_schema_contains_all_renewal_backoff_columns(tmp_path):
    app = _app(tmp_path / "renewal-columns.db")
    with app.app_context():
        columns = {row["name"] for row in get_db().execute("PRAGMA table_info('provider_sessions')").fetchall()}

    assert {"renew_attempted_at", "renew_next_attempt_at", "renewal_failures"}.issubset(columns)
