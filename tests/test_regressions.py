from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.checks import apply_health_result
from app.services.earnings import accrue_eligible_time, balances_for_user
from app.services.proxies import add_proxy, reconcile_exit_ip
from app.services.users import create_user


def test_egress_canonicalization_is_deterministic_by_creation_time(app):
    first_created = "2026-08-29T08:00:00+00:00"
    second_created = "2026-08-29T09:00:00+00:00"
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        first = add_proxy(db, user_id, "first.example:9001:u:first")
        second = add_proxy(db, user_id, "second.example:9002:u:second")
        db.execute(
            "UPDATE proxies SET created_at=?, updated_at=? WHERE id=?",
            (first_created, first_created, first),
        )
        db.execute(
            "UPDATE proxies SET created_at=?, updated_at=? WHERE id=?",
            (second_created, second_created, second),
        )
        db.commit()
        reconcile_exit_ip(db, second, "198.51.100.44")
        reconcile_exit_ip(db, first, "198.51.100.44")
        rows = db.execute(
            "SELECT id, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (first, second),
        ).fetchall()
    assert rows[0]["duplicate_of"] is None
    assert rows[1]["duplicate_of"] == first


def test_earnings_do_not_count_offline_gap_as_online(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.9"},
            now=start,
        )
        accrue_eligible_time(db, now=start + timedelta(hours=100))
        # The checker confirms a sustained outage, then a later recovery.
        for hour in (100, 101, 102):
            apply_health_result(db, proxy_id, {"status": "dead"}, now=start + timedelta(hours=hour))
        accrue_eligible_time(db, now=start + timedelta(hours=200))
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.9"},
            now=start + timedelta(hours=200),
        )
        accrue_eligible_time(db, now=start + timedelta(hours=268))
        balances = balances_for_user(db, user_id)
    # A confirmed outage resets the 168-hour continuous-online probation.
    assert balances.available_micro_usd == 0
    assert balances.pending_micro_usd > 0
