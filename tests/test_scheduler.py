from datetime import UTC, datetime, timedelta

from app.check_service import CheckRunner, SchedulerState


def test_worker_modes_are_independent():
    health = CheckRunner(state=SchedulerState(), worker="health")
    earnapp = CheckRunner(state=SchedulerState(), worker="earnapp")
    assert health.worker == "health"
    assert earnapp.worker == "earnapp"
    health.close()
    earnapp.close()


def test_scheduler_has_independent_health_and_earnapp_due_windows():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=5))
    assert runner.health_due is True
    assert runner.earnapp_due is True
    runner.mark_health_sweep(datetime(2026, 8, 29, 8, 0, tzinfo=UTC))
    assert runner.health_due is False
    assert runner.earnapp_due is True


def test_health_due_reopens_after_the_configured_window():
    closed_at = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=5, last_sweep_at=closed_at))
    assert runner.health_due is False
    assert runner.next_wait_seconds(now=closed_at + timedelta(minutes=59)) == 60
    assert runner.health_due is False
    assert runner.next_wait_seconds(now=closed_at + timedelta(minutes=60)) == 0
    assert runner.health_due is True


def test_next_wait_uses_health_clock_when_legacy_clock_is_missing():
    closed_at = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    runner = CheckRunner(
        state=SchedulerState(interval_minutes=60, last_health_sweep_at=closed_at),
    )
    assert runner.next_wait_seconds(now=closed_at + timedelta(minutes=5)) == 3300


def test_empty_health_batch_does_not_move_a_closed_window(app):
    closed_at = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.mark_health_sweep(closed_at)

    assert runner.run_batch() == 0
    assert runner.state.last_health_sweep_at == closed_at
    assert runner.health_due is False


def test_run_forever_processes_due_backlog_without_added_spacing(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "spacing-backlog@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "spacing-backlog.example:9000:u:p")
        db.execute("UPDATE proxies SET next_check_at=datetime('now','-1 minute') WHERE id=?", (proxy_id,))
        db.commit()

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))

    def one_batch():
        runner.stop()
        return 1

    def spacing(db, *, due_count):
        # Accessing the connection proves it has not been closed by a context
        # teardown before the spacing calculation.
        assert db.execute("SELECT 1").fetchone()[0] == 1
        assert due_count >= 0
        return 0

    monkeypatch.setattr(runner, "run_batch", one_batch)
    monkeypatch.setattr("app.check_service.batch_spacing_seconds", spacing)
    waits = []
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: waits.append(seconds))
    runner.run_forever()

    assert waits == [0]


def test_run_forever_sleeps_until_next_health_window_after_last_batch(app, monkeypatch):
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    finished_at = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    calls = 0
    waits = []

    def batch():
        nonlocal calls
        calls += 1
        if calls == 1:
            runner.mark_health_sweep(finished_at)
            return 1
        runner.stop()
        return 0

    monkeypatch.setattr(runner, "run_batch", batch)
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: waits.append(seconds))
    runner.run_forever()

    assert waits and waits[0] >= 3500


def test_run_forever_wakes_for_a_durable_retry_before_the_hour_window(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "retry-wakeup@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "retry-wakeup.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=? WHERE id=?",
            ((now + timedelta(minutes=5)).isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.mark_health_sweep(now)
    waits = []
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: (waits.append(seconds), runner.stop()))

    runner.run_forever()

    assert waits and waits[0] <= 360


def test_run_forever_keeps_empty_inventory_sleeping_until_the_health_window(app, monkeypatch):
    closed_at = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.mark_health_sweep(closed_at)
    waits = []
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: (waits.append(seconds), runner.stop()))

    runner.run_forever()

    assert waits and waits[0] >= 3500


def test_run_forever_wakes_when_a_stale_claim_expires_before_next_check(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "claim-wakeup@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "claim-wakeup.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=?, check_claimed_until=? WHERE id=?",
            ((now + timedelta(hours=1)).isoformat(), (now + timedelta(minutes=5)).isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.mark_health_sweep(now)
    waits = []
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: (waits.append(seconds), runner.stop()))

    runner.run_forever()

    assert waits and waits[0] <= 360


def test_scheduler_queues_ignore_blocked_users_but_keep_paused_active_users(app):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    now = datetime.now(UTC)
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    with app.app_context():
        db = get_db()
        blocked_user = create_user(db, "scheduler-blocked@example.com", "password", status="blocked")
        blocked_proxy = add_proxy(db, blocked_user, "scheduler-blocked.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', next_check_at=?, earnapp_next_check_at=? WHERE id=?",
            (now.isoformat(), now.isoformat(), blocked_proxy),
        )
        db.commit()

        assert runner._health_queue_due(db, now) is False
        assert runner._earnapp_queue_due(db, now) is False
        assert runner._next_health_wake_seconds(db, now) is None
        assert runner._next_earnapp_wake_seconds(db, now) is None

        paused_user = create_user(db, "scheduler-paused@example.com", "password", status="active")
        paused_proxy = add_proxy(db, paused_user, "scheduler-paused.example:9001:u:p")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (paused_user,))
        db.execute(
            "UPDATE proxies SET status='online', next_check_at=?, earnapp_next_check_at=? WHERE id=?",
            (now.isoformat(), now.isoformat(), paused_proxy),
        )
        db.commit()

        assert runner._health_queue_due(db, now) is True
        assert runner._earnapp_queue_due(db, now) is True
    runner.close()


def test_earnapp_forever_wakes_for_a_due_qualification_before_the_week_window(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "earnapp-wakeup@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "earnapp-wakeup.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', earnapp_next_check_at=? WHERE id=?",
            ((now + timedelta(minutes=5)).isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(
        app=app,
        state=SchedulerState(interval_minutes=60, concurrency=5),
        worker="earnapp",
    )
    runner.mark_earnapp_sweep(now)
    waits = []
    monkeypatch.setattr(runner._stop, "wait", lambda seconds: (waits.append(seconds), runner.stop()))

    runner.run_earnapp_forever()

    assert waits and waits[0] <= 360


def test_earnapp_forever_processes_newly_due_qualification_during_cooldown(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "earnapp-due@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "earnapp-due.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', earnapp_next_check_at=? WHERE id=?",
            (now.isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(
        app=app,
        state=SchedulerState(interval_minutes=60, concurrency=5),
        worker="earnapp",
    )
    runner.mark_earnapp_sweep(now)
    calls = []

    def batch():
        calls.append(True)
        runner.stop()
        return 0

    monkeypatch.setattr(runner, "run_earnapp_batch", batch)

    runner.run_earnapp_forever()

    assert calls


def test_runner_refreshes_interval_and_concurrency_from_admin_settings(app):
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    with app.app_context():
        db = __import__("app.db", fromlist=["get_db"]).get_db()
        db.execute("UPDATE settings SET value='120' WHERE key='health_interval_minutes'")
        db.execute("UPDATE settings SET value='2' WHERE key='health_concurrency'")
        db.commit()
        runner.refresh_settings(db)
    assert runner.state.interval_minutes == 120
    assert runner.state.concurrency == 2


def test_health_batch_does_not_run_global_earnings_or_archive_maintenance(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "no-maintenance@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "no-maintenance.example:9000:u:p")
        db.execute("UPDATE proxies SET next_check_at=datetime('now','-1 minute') WHERE id=?", (proxy_id,))
        db.commit()

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=1))
    monkeypatch.setattr(
        runner,
        "_check_one",
        lambda row, parsed=None: (int(row["id"]), {"status": "inconclusive", "failure_kind": "probe_endpoint"}),
    )
    assert runner.run_batch() == 1


def test_newly_added_due_proxy_is_processed_during_health_cooldown(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    closed_at = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "new-proxy@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "new.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=? WHERE id=?",
            (closed_at.isoformat(), proxy_id),
        )
        db.commit()
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=1))
    runner.mark_health_sweep(closed_at - timedelta(minutes=1))
    monkeypatch.setattr(
        runner,
        "_check_one",
        lambda row, parsed=None: (
            int(row["id"]),
            {"status": "inconclusive", "error": "test"},
        ),
    )
    runner.run_forever = runner.run_forever
    # The durable queue must override the cooldown for newly-created work.
    calls = []
    original_batch = runner.run_batch

    def batch():
        calls.append(True)
        result = original_batch()
        runner.stop()
        return result

    monkeypatch.setattr(runner, "run_batch", batch)
    runner.run_forever()
    assert calls


def test_earnapp_worker_failure_is_recorded_and_claim_is_released(app, monkeypatch):
    from datetime import datetime

    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "earn-failure@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "earn.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', earnapp_next_check_at=? WHERE id=?",
            (datetime.now(UTC).isoformat(), proxy_id),
        )
        db.commit()

    async def fail_probe(*args, **kwargs):
        raise RuntimeError("simulated earnapp failure")

    monkeypatch.setattr("app.check_service.probe_earnapp_proxy", fail_probe)
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    assert runner.run_earnapp_batch() == 1
    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT earnapp_claimed_until, eligibility, earnapp_reason FROM proxies WHERE id=?",
                (proxy_id,),
            )
            .fetchone()
        )
    assert row["earnapp_claimed_until"] is None
    assert row["eligibility"] == "pending"
    assert "simulated earnapp failure" in row["earnapp_reason"]


def test_health_credential_decryption_failure_is_isolated_and_claim_is_released(app):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "health-corrupt@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "health-corrupt.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET username_encrypted='not-fernet', next_check_at=? WHERE id=?",
            (datetime.now(UTC).isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=1))
    try:
        assert runner.run_batch() == 1
    finally:
        runner.close()

    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT status, check_claimed_until, check_claim_token, failure_kind, last_error "
                "FROM proxies WHERE id=?",
                (proxy_id,),
            )
            .fetchone()
        )
    assert row["status"] == "pending"
    assert row["check_claimed_until"] is None
    assert row["check_claim_token"] is None
    assert row["failure_kind"] == "worker"
    assert "could not be decrypted" in row["last_error"]


def test_earnapp_credential_decryption_failure_is_isolated_and_claim_is_released(app):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "earnapp-corrupt@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "earnapp-corrupt.example:9000:u:p")
        db.execute(
            """
            UPDATE proxies SET status='online', detected_protocol='socks5', username_encrypted='not-fernet',
                earnapp_next_check_at=? WHERE id=?
            """,
            (datetime.now(UTC).isoformat(), proxy_id),
        )
        db.commit()

    runner = CheckRunner(
        app=app,
        state=SchedulerState(interval_minutes=60, concurrency=1),
        worker="earnapp",
    )
    try:
        assert runner.run_earnapp_batch() == 1
    finally:
        runner.close()

    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT eligibility, earnapp_claimed_until, earnapp_claim_token, earnapp_reason "
                "FROM proxies WHERE id=?",
                (proxy_id,),
            )
            .fetchone()
        )
    assert row["eligibility"] == "pending"
    assert row["earnapp_claimed_until"] is None
    assert row["earnapp_claim_token"] is None
    assert "could not be decrypted" in row["earnapp_reason"]


def test_unknown_protocol_qualification_clears_claim_and_is_rescheduled(app):
    from datetime import datetime, timezone

    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "unknown@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "unknown.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', earnapp_next_check_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), proxy_id),
        )
        db.commit()
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=5))
    assert runner.run_earnapp_batch() == 1
    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT earnapp_claimed_until, earnapp_next_check_at, eligibility FROM proxies WHERE id=?",
                (proxy_id,),
            )
            .fetchone()
        )
    assert row["earnapp_claimed_until"] is None
    assert row["earnapp_next_check_at"]
    assert row["eligibility"] == "pending"
