from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxies import (
    add_proxy,
    archive_proxy,
    promote_duplicate_if_due,
    replace_proxy,
)
from app.services.users import create_user


def test_replace_updates_same_record_and_resets_probation(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:old-pass")
        replace_proxy(db, proxy_id, user_id, "new.example:9010:u:new-pass", now=now)
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    assert row["host"] == "new.example"
    assert row["status"] == "pending"
    assert row["probation_started_at"] == now.isoformat()


def test_archive_keeps_history_but_removes_operational_record(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        archive_proxy(db, proxy_id, user_id)
        row = db.execute("SELECT archived_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    assert row["archived_at"] is not None


def test_live_duplicate_is_promoted_after_canonical_offline_for_24_hours(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical.example:9001:u:p")
        duplicate = add_proxy(db, user_id, "duplicate.example:9002:u:p")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.7', status='offline', offline_since=? WHERE id=?",
            ((now - timedelta(hours=25)).isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.7', status='online', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()
        promoted = promote_duplicate_if_due(db, canonical, now=now)
        rows = db.execute(
            "SELECT id, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (canonical, duplicate),
        ).fetchall()
    assert promoted == duplicate
    assert rows[0]["duplicate_of"] == duplicate
    assert rows[1]["duplicate_of"] is None
