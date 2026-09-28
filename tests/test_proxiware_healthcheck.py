from __future__ import annotations

import sqlite3
import sys
from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxiware_health import record_worker_heartbeat
from scripts.proxiware_healthcheck import check_worker_health, main


def test_worker_healthcheck_accepts_recent_heartbeat(app):
    with app.app_context():
        db = get_db()
        record_worker_heartbeat(db, "sync_worker", "ok")
        result = check_worker_health(db, "sync_worker", max_age_seconds=60)

    assert result.ok is True
    assert result.reason == "ok"


def test_worker_healthcheck_rejects_stale_heartbeat(app):
    with app.app_context():
        db = get_db()
        old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_sync_worker_status", "ok", old),
        )
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_sync_worker_heartbeat_at", old, old),
        )
        db.commit()
        result = check_worker_health(db, "sync_worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "stale"


def test_worker_healthcheck_rejects_unknown_worker_name(app):
    with app.app_context():
        result = check_worker_health(get_db(), "not-a-worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "invalid_worker"


def test_worker_healthcheck_accepts_browser_worker(app):
    with app.app_context():
        db = get_db()
        record_worker_heartbeat(db, "browser_worker", "manual_action_required")
        result = check_worker_health(db, "browser_worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "manual_action_required"


def test_worker_healthcheck_reports_disabled_even_when_disabled_heartbeat_is_old(app):
    with app.app_context():
        db = get_db()
        old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_browser_worker_status", "disabled", old),
        )
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_browser_worker_heartbeat_at", old, old),
        )
        db.commit()
        result = check_worker_health(db, "browser_worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "disabled"


def test_worker_healthcheck_uses_disabled_config_over_old_browser_heartbeat(app):
    with app.app_context():
        db = get_db()
        old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_browser_worker_status", "sleeping", old),
        )
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
            ("proxiware_browser_worker_heartbeat_at", old, old),
        )
        db.commit()
        result = check_worker_health(db, "browser_worker", max_age_seconds=60, configured_enabled=False)

    assert result.ok is False
    assert result.status == "disabled"
    assert result.reason == "disabled"


def test_worker_healthcheck_rejects_degraded_worker(app):
    with app.app_context():
        db = get_db()
        record_worker_heartbeat(db, "qualification_worker", "degraded")
        result = check_worker_health(db, "qualification_worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "degraded"


def test_worker_healthcheck_rejects_stopped_worker(app):
    with app.app_context():
        db = get_db()
        record_worker_heartbeat(db, "qualification_worker", "stopped")
        result = check_worker_health(db, "qualification_worker", max_age_seconds=60)

    assert result.ok is False
    assert result.reason == "stopped"


def test_healthcheck_cli_reads_database_without_application_secrets(tmp_path, monkeypatch, capsys):
    database = tmp_path / "health.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    now = datetime.now(UTC).isoformat()
    connection.executemany(
        "INSERT INTO settings(key,value) VALUES(?,?)",
        [("proxiware_sync_worker_status", "ok"), ("proxiware_sync_worker_heartbeat_at", now)],
    )
    connection.commit()
    connection.close()

    monkeypatch.delenv("EARN_PROXY_SECRET_KEY", raising=False)
    monkeypatch.delenv("EARN_PROXY_FERNET_KEY", raising=False)
    monkeypatch.delenv("EARN_PROXY_PROXIWARE_WORKER_FERNET_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["proxiware_healthcheck", "sync_worker", "--database", str(database)])

    assert main() == 0
    assert capsys.readouterr().out.strip() == "ok"


def test_healthcheck_cli_does_not_assume_browser_disabled_without_config(tmp_path, monkeypatch, capsys):
    database = tmp_path / "health.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    now = datetime.now(UTC).isoformat()
    connection.executemany(
        "INSERT INTO settings(key,value) VALUES(?,?)",
        [("proxiware_browser_worker_status", "sleeping"), ("proxiware_browser_worker_heartbeat_at", now)],
    )
    connection.commit()
    connection.close()

    monkeypatch.delenv("EARN_PROXY_PROXIWARE_BROWSER_ENABLED", raising=False)
    monkeypatch.setattr(sys, "argv", ["proxiware_healthcheck", "browser_worker", "--database", str(database)])

    assert main() == 0
    assert capsys.readouterr().out.strip() == "ok"
