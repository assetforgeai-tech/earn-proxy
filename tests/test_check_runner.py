from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.check_service import CheckRunner, SchedulerState


def test_runner_uses_configured_concurrency_and_never_exceeds_it():
    state = SchedulerState(interval_minutes=60, concurrency=5)
    runner = CheckRunner(state=state)
    assert runner.concurrency == 5
    assert runner.interval_seconds == 3600


def test_runner_hard_caps_direct_state_concurrency_at_five():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=50))
    assert runner.concurrency == 5


def test_runner_wait_delay_is_until_next_due_work_not_busy_loop():
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    state = SchedulerState(interval_minutes=60, concurrency=5, last_sweep_at=now)
    runner = CheckRunner(state=state)
    assert runner.next_wait_seconds(now=now + timedelta(minutes=5)) == 3300


def test_runner_stop_event_interrupts_wait_without_spinning():
    runner = CheckRunner(state=SchedulerState(interval_minutes=60, concurrency=5))
    runner.stop()
    assert runner.stopped is True
