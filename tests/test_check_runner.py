from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta

from app.check_service import CheckRunner, SchedulerState
from app.checker import PROBE_URLS


def test_runner_uses_configured_concurrency_and_never_exceeds_it():
    state = SchedulerState(interval_minutes=60, concurrency=5)
    runner = CheckRunner(state=state)
    assert runner.concurrency == 5
    assert runner.interval_seconds == 3600


def test_runner_hard_caps_direct_state_concurrency_at_five():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=50))
    assert runner.concurrency == 20


def test_runner_selects_fast_mode_for_stable_detected_proxy(monkeypatch):
    calls = []
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    row = {
        "id": 1,
        "host": "provider.example",
        "port": 9000,
        "protocol_hint": "auto",
        "detected_protocol": "socks5",
        "username_encrypted": "",
        "password_encrypted": "",
        "credential_generation": 1,
        "check_claim_token": "claim",
        "health_mode": "fast",
        "next_probe_index": 1,
        "exit_ip": "198.51.100.10",
    }

    monkeypatch.setattr(
        "app.check_service.check_proxy_fast",
        lambda proxy, **kwargs: calls.append((proxy, kwargs)) or {"status": "live", "exit_ip": "198.51.100.10"},
    )
    monkeypatch.setattr(
        "app.check_service.check_proxy_strong", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())
    )
    parsed = type(
        "Parsed", (), {"host": "provider.example", "port": 9000, "username": "u", "password": "p", "protocol": "auto"}
    )()

    _proxy_id, result = runner._check_one(row, parsed)

    assert result["status"] == "live"
    assert calls[0][0]["protocol"] == "socks5"
    assert calls[0][1]["probe_index"] == 1
    assert calls[0][1]["expected_exit_ip"] == "198.51.100.10"


def test_runner_escalates_transient_fast_failure_to_strong_confirmation(monkeypatch):
    calls = []
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    row = {
        "id": 3,
        "host": "provider.example",
        "port": 9000,
        "protocol_hint": "auto",
        "detected_protocol": "socks5",
        "credential_generation": 1,
        "check_claim_token": "claim",
        "health_mode": "fast",
        "next_probe_index": 0,
        "exit_ip": "198.51.100.12",
    }
    monkeypatch.setattr(
        "app.check_service.check_proxy_fast",
        lambda *args, **kwargs: {"status": "needs_confirmation", "failure_kind": "transient"},
    )
    monkeypatch.setattr(
        "app.check_service.check_proxy_strong",
        lambda proxy: calls.append(proxy) or {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.12"},
    )
    parsed = type(
        "Parsed", (), {"host": "provider.example", "port": 9000, "username": "u", "password": "p", "protocol": "auto"}
    )()

    _proxy_id, result = runner._check_one(row, parsed)

    assert result["status"] == "live"
    assert len(calls) == 1


def test_runner_does_not_escalate_third_party_endpoint_failure(monkeypatch):
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    row = {
        "id": 4,
        "host": "provider.example",
        "port": 9000,
        "protocol_hint": "auto",
        "detected_protocol": "socks5",
        "credential_generation": 1,
        "check_claim_token": "claim",
        "health_mode": "fast",
        "next_probe_index": 0,
        "exit_ip": "198.51.100.12",
    }
    monkeypatch.setattr(
        "app.check_service.check_proxy_fast",
        lambda *args, **kwargs: {"status": "inconclusive", "failure_kind": "probe_endpoint"},
    )
    monkeypatch.setattr(
        "app.check_service.check_proxy_strong", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError())
    )
    parsed = type(
        "Parsed", (), {"host": "provider.example", "port": 9000, "username": "u", "password": "p", "protocol": "auto"}
    )()

    _proxy_id, result = runner._check_one(row, parsed)

    assert result["status"] == "inconclusive"


def test_runner_opens_a_short_circuit_after_repeated_probe_endpoint_failures(monkeypatch):
    unavailable = []
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    row = {
        "id": 5,
        "host": "provider.example",
        "port": 9000,
        "protocol_hint": "auto",
        "detected_protocol": "socks5",
        "credential_generation": 1,
        "check_claim_token": "claim",
        "health_mode": "fast",
        "next_probe_index": 0,
        "exit_ip": "198.51.100.12",
    }

    def endpoint_failure(*args, **kwargs):
        unavailable.append(set(kwargs["unavailable_endpoints"]))
        return {
            "status": "inconclusive",
            "failure_kind": "probe_endpoint",
            "probe_endpoint": PROBE_URLS[0],
            "failed_probe_endpoint": PROBE_URLS[0],
        }

    monkeypatch.setattr("app.check_service.check_proxy_fast", endpoint_failure)
    parsed = type(
        "Parsed", (), {"host": "provider.example", "port": 9000, "username": "u", "password": "p", "protocol": "auto"}
    )()

    try:
        for _ in range(4):
            runner._check_one(row, parsed)
    finally:
        runner.close()

    assert unavailable[:3] == [set(), set(), set()]
    assert PROBE_URLS[0] in unavailable[3]


def test_probe_endpoint_circuit_closes_after_its_cooldown():
    runner = CheckRunner(state=SchedulerState())
    failed = {
        "status": "inconclusive",
        "failure_kind": "probe_endpoint",
        "failed_probe_endpoint": PROBE_URLS[0],
    }
    try:
        for _ in range(3):
            runner.record_fast_probe_result(failed, now=100.0)
        assert PROBE_URLS[0] in runner.unavailable_probe_endpoints(now=100.0)
        assert PROBE_URLS[0] not in runner.unavailable_probe_endpoints(now=401.0)
    finally:
        runner.close()


def test_runner_selects_strong_mode_for_new_or_suspect_proxy(monkeypatch):
    calls = []
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    row = {
        "id": 2,
        "host": "provider.example",
        "port": 9000,
        "protocol_hint": "auto",
        "detected_protocol": "unknown",
        "credential_generation": 1,
        "check_claim_token": "claim",
        "health_mode": "strong",
        "next_probe_index": 0,
        "exit_ip": "",
    }
    monkeypatch.setattr(
        "app.check_service.check_proxy_strong",
        lambda proxy, **kwargs: (
            calls.append((proxy, kwargs)) or {"status": "live", "protocol": "http", "exit_ip": "198.51.100.11"}
        ),
    )
    parsed = type(
        "Parsed", (), {"host": "provider.example", "port": 9000, "username": "u", "password": "p", "protocol": "auto"}
    )()

    _proxy_id, result = runner._check_one(row, parsed)

    assert result["status"] == "live"
    assert calls[0][0]["protocol"] == "auto"
    assert calls[0][1]["unavailable_endpoints"] == set()


def test_runner_reuses_one_health_executor_across_batches(app):
    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=20))
    first = runner.health_executor
    runner.run_batch()
    second = runner.health_executor
    runner.close()
    assert first is second


def test_provider_host_limiter_caps_simultaneous_checks():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=20))
    runner.per_host_concurrency = 2
    active = 0
    peak = 0
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def work():
        nonlocal active, peak
        barrier.wait(timeout=2)
        with runner.provider_slot("shared.example"):
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1

    threads = [threading.Thread(target=work) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)
    runner.close()

    assert peak == 2


def test_runner_wait_delay_is_until_next_due_work_not_busy_loop():
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    state = SchedulerState(interval_minutes=60, concurrency=5, last_sweep_at=now)
    runner = CheckRunner(state=state)
    assert runner.next_wait_seconds(now=now + timedelta(minutes=5)) == 3300


def test_runner_stop_event_interrupts_wait_without_spinning():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.stop()
    assert runner.stopped is True


def test_health_batch_stop_processes_completed_results_and_releases_pending_claims(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stop-batch@example.com", "password", status="active")
        first = add_proxy(db, user_id, "first-stop.example:9000:u:p")
        second = add_proxy(db, user_id, "second-stop.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=datetime('now','-1 minute') WHERE id IN (?, ?)",
            (first, second),
        )
        db.commit()

    class ControlledExecutor:
        def __init__(self):
            self.submissions = []

        def submit(self, _fn, row, _parsed):
            future = Future()
            self.submissions.append((future, row))
            if len(self.submissions) == 1:
                future.set_result(
                    (
                        int(row["id"]),
                        {
                            "status": "live",
                            "protocol": "socks5",
                            "exit_ip": "198.51.100.80",
                        },
                    )
                )
            return future

        def shutdown(self, *, wait, cancel_futures):
            return None

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=2))
    controlled = ControlledExecutor()
    runner._health_executor = controlled

    def completed_then_stop(futures):
        runner.stop()
        yield futures[0]

    monkeypatch.setattr("app.check_service.as_completed", completed_then_stop)

    assert runner.run_batch() == 1
    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT id, status, check_claimed_until, check_claim_token, next_check_at FROM proxies ORDER BY id"
            )
            .fetchall()
        )

    assert rows[0]["status"] == "online"
    assert rows[0]["check_claimed_until"] is None
    assert rows[1]["status"] == "pending"
    assert rows[1]["check_claimed_until"] is None
    assert rows[1]["check_claim_token"] is None
    assert datetime.fromisoformat(rows[1]["next_check_at"]) <= datetime.now(UTC)


def test_health_batch_stop_does_not_release_a_running_claim(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stop-running@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "running-stop.example:9000:u:p")
        db.execute("UPDATE proxies SET next_check_at=datetime('now','-1 minute') WHERE id=?", (proxy_id,))
        db.commit()

    class RunningFuture(Future):
        def cancel(self):
            return False

    class RunningExecutor:
        def submit(self, _fn, row, _parsed):
            future = RunningFuture()
            return future

        def shutdown(self, *, wait, cancel_futures):
            return None

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=1))
    runner._health_executor = RunningExecutor()
    monkeypatch.setattr("app.check_service.as_completed", lambda _futures: iter(()))
    assert runner.run_batch() == 0

    with app.app_context():
        row = (
            get_db()
            .execute("SELECT check_claimed_until, check_claim_token FROM proxies WHERE id=?", (proxy_id,))
            .fetchone()
        )
    assert row["check_claimed_until"] is not None
    assert row["check_claim_token"]


def test_earnapp_batch_stop_releases_unprocessed_claims(app, monkeypatch):
    from app.db import get_db
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stop-earnapp@example.com", "password", status="active")
        first = add_proxy(db, user_id, "first-earnapp-stop.example:9000:u:p")
        second = add_proxy(db, user_id, "second-earnapp-stop.example:9001:u:p")
        db.execute(
            """
            UPDATE proxies SET status='online', detected_protocol='socks5',
                earnapp_next_check_at=datetime('now','-1 minute')
            WHERE id IN (?, ?)
            """,
            (first, second),
        )
        db.commit()

    async def one_result_then_stop(*args, **kwargs):
        runner.stop()
        return {"verdict": "CID_SET", "reason": "cid"}

    runner = CheckRunner(app=app, state=SchedulerState(interval_minutes=60, concurrency=2), worker="earnapp")
    monkeypatch.setattr("app.check_service.probe_earnapp_proxy", one_result_then_stop)

    assert runner.run_earnapp_batch() == 1
    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT id, eligibility, earnapp_claimed_until, earnapp_claim_token, earnapp_next_check_at "
                "FROM proxies ORDER BY id"
            )
            .fetchall()
        )

    assert rows[0]["eligibility"] == "allow"
    assert rows[0]["earnapp_claimed_until"] is None
    assert rows[1]["eligibility"] == "pending"
    assert rows[1]["earnapp_claimed_until"] is None
    assert rows[1]["earnapp_claim_token"] is None
    assert datetime.fromisoformat(rows[1]["earnapp_next_check_at"]) <= datetime.now(UTC)
