from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.check_service import CheckRunner, SchedulerState
from app.db import get_db
from app.services.checks import archive_due_dead_proxies
from app.services.proxies import add_proxy
from app.services.users import create_user


def test_schema_contains_scheduler_and_egress_audit_columns(app):
    with app.app_context():
        columns = {row["name"] for row in get_db().execute("PRAGMA table_info(proxies)").fetchall()}
    assert {
        "egress_verified_at",
        "egress_attestation_source",
        "earnapp_claimed_until",
        "continuous_dead_since",
    }.issubset(columns)


def test_dead_proxy_is_archived_after_24_hours_but_history_remains(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        dead_since = now - timedelta(hours=25)
        db.execute(
            "UPDATE proxies SET status='offline', offline_since=?, continuous_dead_since=? WHERE id=?",
            (dead_since.isoformat(), dead_since.isoformat(), proxy_id),
        )
        db.commit()
        archived = archive_due_dead_proxies(db, now=now)
        row = db.execute("SELECT status, archived_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    assert archived == 1
    assert row["status"] == "archived"
    assert row["archived_at"] is not None


def test_checker_worker_exception_is_recorded_and_does_not_abort_batch(app, monkeypatch):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        first = add_proxy(db, user_id, "one.example:9000:u:p")
        second = add_proxy(db, user_id, "two.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=? WHERE id IN (?,?)",
            ((now - timedelta(minutes=1)).isoformat(), first, second),
        )
        db.commit()

    calls = {0: 0}

    def fake_check(proxy):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("simulated worker failure")
        return {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.20"}

    monkeypatch.setattr("app.check_service.check_proxy", fake_check)
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=2))
    assert runner.run_batch() == 2
    with app.app_context():
        rows = get_db().execute("SELECT last_error, status FROM proxies ORDER BY id").fetchall()
    assert any("simulated worker failure" in row["last_error"] for row in rows)
    assert any(row["status"] == "online" for row in rows)


def test_egress_verification_timestamp_drives_canonical_choice(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        first = add_proxy(db, user_id, "first.example:9000:u:p")
        second = add_proxy(db, user_id, "second.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET egress_verified_at=? WHERE id=?",
            ("2026-08-29T10:00:00+00:00", first),
        )
        db.execute(
            "UPDATE proxies SET egress_verified_at=? WHERE id=?",
            ("2026-08-29T08:00:00+00:00", second),
        )
        db.commit()
        from app.services.proxies import reconcile_exit_ip

        reconcile_exit_ip(db, first, "198.51.100.30")
        reconcile_exit_ip(db, second, "198.51.100.30")
        rows = db.execute(
            "SELECT id, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (first, second),
        ).fetchall()
    assert rows[1]["duplicate_of"] is None
    assert rows[0]["duplicate_of"] == second
