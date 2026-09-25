from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxiware_health import record_worker_heartbeat
from scripts.proxiware_healthcheck import check_worker_health


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
