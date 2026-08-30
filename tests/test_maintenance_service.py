from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.maintenance_service import MaintenanceRunner
from app.services.proxies import add_proxy
from app.services.users import create_user


def test_maintenance_cycle_accrues_and_archives_without_health_runner(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "maintenance@example.com", "password", status="active")
        earning = add_proxy(db, user_id, "earning.example:9000:u:p")
        dead = add_proxy(db, user_id, "dead.example:9001:u:p")
        db.execute(
            """
            UPDATE proxies SET status='online', eligibility='allow', country_code='US',
                online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?
            """,
            (
                (now - timedelta(hours=8)).isoformat(),
                now.isoformat(),
                (now - timedelta(hours=8)).isoformat(),
                (now - timedelta(hours=8)).isoformat(),
                earning,
            ),
        )
        db.execute(
            "UPDATE proxies SET status='offline', offline_since=?, continuous_dead_since=? WHERE id=?",
            ((now - timedelta(hours=25)).isoformat(), (now - timedelta(hours=25)).isoformat(), dead),
        )
        db.commit()

    result = MaintenanceRunner(app=app).run_cycle(now=now)

    with app.app_context():
        db = get_db()
        archived = db.execute("SELECT archived_at FROM proxies WHERE id=?", (dead,)).fetchone()["archived_at"]
        ledger = db.execute("SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=?", (earning,)).fetchone()[
            "count"
        ]
    assert result["archived"] == 1
    assert archived
    assert ledger > 0


def test_maintenance_cycle_checkpoints_wal(app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.maintenance_service.checkpoint_wal", lambda db: calls.append(db.execute("SELECT 1").fetchone()[0])
    )
    MaintenanceRunner(app=app).run_cycle()
    assert calls == [1]
