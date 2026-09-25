from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxiware_qualification_service import ProxiwareQualificationRunner
from app.services.proxiware_swap import ensure_proxiware_swap_schema


def _assignment(db, external_id="qual-worker-1"):
    ensure_proxiware_swap_schema(db)
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,created_at,updated_at) "
        "VALUES('proxiware','qual-sub','active',?,?,?,?)",
        (now, now, now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
        "provider_eligible,live_status,assigned_at,last_seen_at,created_at,updated_at) "
        "VALUES(?,?,?,?,?,'active','pending',1,'pending',?,?,?,?)",
        (sub_id, "proxiware", external_id, "worker.example", 8080, now, now, now, now),
    )
    db.commit()
    return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def test_runner_claims_and_qualifies_assignment_with_bounded_worker(app):
    with app.app_context():
        assignment_id = _assignment(get_db())

    runner = ProxiwareQualificationRunner(
        app=app,
        probe=lambda _proxy: {
            "status": "live",
            "protocol": "socks5",
            "exit_ip": "198.51.100.90",
            "egress_trusted": True,
        },
        eligibility=lambda _proxy: {"verdict": "CID_SET"},
        concurrency=1,
        interval_seconds=3600,
    )

    outcome = runner.run_once()

    assert outcome["status"] == "ok"
    assert outcome["checked"] == 1
    with app.app_context():
        row = get_db().execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()
    assert row["qualification"] == "allow"
    assert row["qualification_claim_token"] is None
    assert row["qualification_next_check_at"]


def test_runner_recovers_expired_claim_after_restart(app):
    with app.app_context():
        db = get_db()
        assignment_id = _assignment(db, "qual-worker-recover")
        expired = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
        db.execute(
            "UPDATE provider_assignments SET qualification_claim_token='stale', qualification_claimed_until=? WHERE id=?",
            (expired, assignment_id),
        )
        db.commit()

    runner = ProxiwareQualificationRunner(
        app=app,
        probe=lambda _proxy: {"status": "inconclusive", "failure_kind": "probe_endpoint"},
        eligibility=lambda _proxy: {"verdict": "CID_SET"},
        concurrency=1,
    )
    assert runner.run_once()["checked"] == 1
    with app.app_context():
        row = get_db().execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()
    assert row["live_status"] == "inconclusive"
    assert row["qualification_claim_token"] is None


def test_runner_idle_does_not_claim_or_loop(app):
    runner = ProxiwareQualificationRunner(app=app, probe=lambda _: {}, eligibility=lambda _: {})
    outcome = runner.run_once()
    assert outcome == {"status": "idle", "checked": 0}
    assert runner.run_forever(max_cycles=1) == 1
    with app.app_context():
        values = dict(
            get_db()
            .execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'")
            .fetchall()
        )
    assert values["proxiware_qualification_worker_status"] == "idle"
    assert values["proxiware_qualification_worker_heartbeat_at"]


def test_global_proxiware_pause_stops_qualification_before_claim(app):
    from app.services.settings import set_setting

    with app.app_context():
        set_setting(get_db(), "proxiware_automation_paused", "1")

    calls: list[str] = []
    runner = ProxiwareQualificationRunner(
        app=app,
        probe=lambda _proxy: calls.append("probe") or {"status": "dead"},
        eligibility=lambda _proxy: {"verdict": "UNKNOWN"},
    )

    assert runner.run_once() == {"status": "paused", "checked": 0}
    assert calls == []
    with app.app_context():
        value = (
            get_db()
            .execute("SELECT value FROM settings WHERE key='proxiware_qualification_worker_status'")
            .fetchone()["value"]
        )
    assert value == "paused"


def test_runner_refreshes_heartbeat_while_waiting_between_cycles(app):
    runner = ProxiwareQualificationRunner(app=app, interval_seconds=120)
    runner._stop.wait = lambda _seconds: True

    with app.app_context():
        runner._wait_with_heartbeat(120)
        values = dict(
            get_db()
            .execute(
                "SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'"
            )
            .fetchall()
        )

    assert values["proxiware_qualification_worker_status"] == "sleeping"
    assert values["proxiware_qualification_worker_heartbeat_at"]
