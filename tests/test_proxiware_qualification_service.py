from __future__ import annotations

import threading
import time
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
    outcome = runner.run_once()
    assert outcome["status"] == "degraded"
    assert outcome["checked"] == 0
    assert outcome["failed"] == 1
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
            .execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'")
            .fetchall()
        )

    assert values["proxiware_qualification_worker_status"] == "sleeping"
    assert values["proxiware_qualification_worker_heartbeat_at"]


def test_runner_reports_degraded_when_every_claimed_row_fails(app):
    with app.app_context():
        assignment_id = _assignment(get_db(), "qual-worker-all-fail")

    def fail(_proxy):
        raise TimeoutError("probe timeout")

    runner = ProxiwareQualificationRunner(app=app, probe=fail, eligibility=lambda _proxy: {}, concurrency=1)

    outcome = runner.run_once()

    assert outcome["status"] == "degraded"
    assert outcome["checked"] == 0
    assert outcome["failed"] == 1
    with app.app_context():
        values = dict(
            get_db()
            .execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'")
            .fetchall()
        )
        row = (
            get_db()
            .execute("SELECT qualification_claim_token FROM provider_assignments WHERE id=?", (assignment_id,))
            .fetchone()
        )
    assert values["proxiware_qualification_worker_status"] == "degraded"
    assert "proxiware_qualification_worker_last_success_at" not in values
    assert row["qualification_claim_token"] is None


def test_runner_reports_degraded_when_every_probe_is_inconclusive(app):
    with app.app_context():
        _assignment(get_db(), "qual-worker-inconclusive")

    runner = ProxiwareQualificationRunner(
        app=app,
        probe=lambda _proxy: {"status": "inconclusive", "failure_kind": "probe_endpoint"},
        eligibility=lambda _proxy: {},
        concurrency=1,
    )

    outcome = runner.run_once()

    assert outcome["status"] == "degraded"
    assert outcome["checked"] == 0
    assert outcome["failed"] == 1
    with app.app_context():
        values = dict(
            get_db()
            .execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'")
            .fetchall()
        )
    assert values["proxiware_qualification_worker_status"] == "degraded"
    assert "proxiware_qualification_worker_last_success_at" not in values


def test_runner_refreshes_heartbeat_while_probe_is_active(app):
    with app.app_context():
        _assignment(get_db(), "qual-worker-long-probe")

    started = threading.Event()
    release = threading.Event()

    def slow_probe(_proxy):
        started.set()
        release.wait(2)
        return {"status": "inconclusive", "failure_kind": "probe_endpoint"}

    runner = ProxiwareQualificationRunner(
        app=app,
        probe=slow_probe,
        eligibility=lambda _proxy: {},
        concurrency=1,
        heartbeat_interval_seconds=0.05,
    )
    result: dict[str, object] = {}
    thread = threading.Thread(target=lambda: result.update(runner.run_once()))
    thread.start()
    assert started.wait(1)
    time.sleep(0.12)
    with app.app_context():
        status = (
            get_db()
            .execute("SELECT value FROM settings WHERE key='proxiware_qualification_worker_status'")
            .fetchone()["value"]
        )
    release.set()
    thread.join(2)

    assert status == "running"
    assert result["status"] == "degraded"


def test_runner_does_not_claim_replacement_before_cooldown(app):
    with app.app_context():
        db = get_db()
        assignment_id = _assignment(db, "qual-worker-cooldown")
        db.execute(
            "UPDATE provider_assignments SET replacement_ready_at=? WHERE id=?",
            ((datetime.now(UTC) + timedelta(minutes=5)).isoformat(), assignment_id),
        )
        db.commit()

    runner = ProxiwareQualificationRunner(app=app, probe=lambda _proxy: {}, eligibility=lambda _proxy: {})

    assert runner.run_once()["status"] == "idle"


def test_runner_stop_releases_claims_that_never_started(app):
    with app.app_context():
        db = get_db()
        first = _assignment(db, "qual-worker-stop-1")
        now = datetime.now(UTC).isoformat()
        subscription_id = db.execute(
            "SELECT subscription_id FROM provider_assignments WHERE id=?", (first,)
        ).fetchone()[0]
        db.execute(
            "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
            "provider_eligible,live_status,assigned_at,last_seen_at,created_at,updated_at) "
            "VALUES(?,'proxiware','qual-worker-stop-2','worker-2.example',8080,'active','pending',1,'pending',?,?,?,?)",
            (subscription_id, now, now, now, now),
        )
        second = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        db.commit()

    started = threading.Event()
    release = threading.Event()

    def slow_probe(_proxy):
        started.set()
        release.wait(2)
        return {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.90", "egress_trusted": True}

    runner = ProxiwareQualificationRunner(
        app=app,
        probe=slow_probe,
        eligibility=lambda _proxy: {"verdict": "CID_SET"},
        concurrency=1,
        claim_seconds=300,
    )
    result: dict[str, object] = {}
    thread = threading.Thread(target=lambda: result.update(runner.run_once()))
    thread.start()
    assert started.wait(1)
    runner.stop()
    release.set()
    thread.join(3)

    assert result["status"] == "stopped"
    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT qualification_claim_token FROM provider_assignments WHERE id IN (?,?) ORDER BY id",
                (first, second),
            )
            .fetchall()
        )
    assert rows[0]["qualification_claim_token"] is None
    assert rows[1]["qualification_claim_token"] is None


def test_runner_persists_next_wake_before_idle_sleep(app):
    runner = ProxiwareQualificationRunner(app=app, interval_seconds=120)
    runner._stop.wait = lambda _seconds: True

    runner._wait_with_heartbeat(120)

    with app.app_context():
        values = dict(
            get_db()
            .execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_qualification_worker_%'")
            .fetchall()
        )
    assert values["proxiware_qualification_worker_next_wake_at"]
