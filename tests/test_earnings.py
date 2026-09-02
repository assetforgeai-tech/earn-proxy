import contextlib
import threading
from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.checks import apply_health_result
from app.services.earnings import accrue_eligible_time, balances_for_user
from app.services.proxies import add_proxy, replace_proxy
from app.services.users import create_user


def test_earnings_accrue_immediately_but_unlock_after_168_hours(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=169)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        first = balances_for_user(db, user_id)
        accrue_eligible_time(db, now=start + timedelta(hours=169))
        unlocked = balances_for_user(db, user_id)

    assert first.pending_micro_usd > 0
    assert first.available_micro_usd == 0
    assert unlocked.available_micro_usd > first.available_micro_usd
    assert unlocked.pending_micro_usd == 0


def test_pause_earn_stops_new_accrual(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (user_id,))
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balances = balances_for_user(db, user_id)

    assert balances.pending_micro_usd == 0
    assert balances.available_micro_usd == 0


def test_long_gap_splits_probation_before_unlocking_available_balance(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "long-gap@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=240)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=240))
        buckets = {
            row["bucket"]: int(row["micro_usd"])
            for row in db.execute(
                "SELECT bucket, COALESCE(SUM(micro_usd), 0) AS micro_usd FROM earnings_ledger WHERE proxy_id=? GROUP BY bucket",
                (proxy_id,),
            ).fetchall()
        }
    assert buckets.get("pending", 0) == 0
    assert buckets["available"] > 0


def test_replacing_proxy_expires_old_pending_cycle_without_touching_available(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replace-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        replace_proxy(
            db,
            proxy_id,
            user_id,
            "new.example:9001:u:new",
            now=start + timedelta(hours=24),
        )
        row = db.execute(
            "SELECT bucket, COALESCE(SUM(micro_usd), 0) AS total FROM earnings_ledger WHERE proxy_id=? GROUP BY bucket",
            (proxy_id,),
        ).fetchall()
        buckets = {item["bucket"]: int(item["total"]) for item in row}
    assert buckets.get("pending", 0) == 0
    assert buckets.get("expired", 0) > 0


def test_concurrent_accrual_does_not_create_overlapping_ledger_intervals(app, monkeypatch):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "accrual-race@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "race.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=2)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

    barrier = threading.Barrier(2)
    from app.services import earnings as earnings_service

    original_add = earnings_service._add_ledger_entry

    def synchronized_add(*args, **kwargs):
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=0.5)
        return original_add(*args, **kwargs)

    monkeypatch.setattr(earnings_service, "_add_ledger_entry", synchronized_add)

    def accrue_at(end):
        with app.app_context():
            accrue_eligible_time(get_db(), now=end)

    threads = [
        threading.Thread(target=accrue_at, args=(start + timedelta(hours=1),)),
        threading.Thread(target=accrue_at, args=(start + timedelta(hours=2),)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT started_at, ended_at FROM earnings_ledger WHERE proxy_id=? ORDER BY started_at, ended_at",
                (proxy_id,),
            )
            .fetchall()
        )
    for previous, current in zip(rows, rows[1:], strict=False):
        assert datetime.fromisoformat(current["started_at"]) >= datetime.fromisoformat(previous["ended_at"])


def test_stale_health_does_not_accrue_or_backfill_an_unobserved_gap(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "stale.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip=?, "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                "198.51.100.60",
                start.isoformat(),
                start.isoformat(),
                start.isoformat(),
                (start - timedelta(days=8)).isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=3))
        before_recovery = balances_for_user(db, user_id)
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.60"},
            now=start + timedelta(hours=4),
        )
        accrue_eligible_time(db, now=start + timedelta(hours=5))
        after_recovery = balances_for_user(db, user_id)

    two_hours = (1_000_000 * 2 * 3600) // (720 * 3600)
    one_hour = (1_000_000 * 3600) // (720 * 3600)
    assert before_recovery.available_micro_usd == two_hours
    assert after_recovery.available_micro_usd == two_hours
    assert after_recovery.pending_micro_usd == one_hour


def test_online_row_without_successful_health_observation_does_not_accrue(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "unverified-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "unverified.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', "
            "online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balance = balances_for_user(db, user_id)
        cursor = db.execute("SELECT accrual_cursor_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()[
            "accrual_cursor_at"
        ]

    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0
    assert cursor == start.isoformat()


def test_online_pending_row_without_verified_egress_does_not_accrue(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "unverified-egress-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "unverified-egress-earnings.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='pending', country_code='US', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balance = balances_for_user(db, user_id)

    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0
