from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.checks import apply_health_result
from app.services.proxies import add_proxy
from app.services.uptime import format_duration, uptime_hours
from app.services.users import create_user


def test_format_duration_uses_fixed_month_day_hour_units():
    assert format_duration(0) == "0 hours"
    assert format_duration(57 * 3600 + 30 * 60) == "2 days 9 hours 30 minutes"
    assert format_duration(32 * 24 * 3600 + 4 * 3600) == "1 month 2 days 4 hours"


def test_confirmed_transitions_accumulate_online_and_offline_hours(app):
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.3"},
            now=start,
        )
        for hour in (1, 2, 3):
            apply_health_result(db, proxy_id, {"status": "dead"}, now=start + timedelta(hours=hour))
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.3"},
            now=start + timedelta(hours=5),
        )
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        hours = uptime_hours(row, now=start + timedelta(hours=6), health_stale_minutes=120)
    assert hours.online == 3.0
    assert hours.offline == 2.0


def test_online_duration_is_zero_for_non_earning_rows():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "online",
        "accumulated_online_seconds": 3600,
        "accumulated_offline_seconds": 0,
        "online_since": start.isoformat(),
        "offline_since": None,
        "last_success_at": start.isoformat(),
    }

    hours = uptime_hours(row, now=start + timedelta(hours=2), earning_enabled=False)

    assert hours.online == 0
    assert hours.online_label == "0 hours"


def test_active_online_duration_stops_at_health_stale_boundary():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "online",
        "accumulated_online_seconds": 0,
        "accumulated_offline_seconds": 0,
        "online_since": start.isoformat(),
        "offline_since": None,
        "last_success_at": start.isoformat(),
    }

    hours = uptime_hours(
        row,
        now=start + timedelta(hours=5),
        health_stale_minutes=120,
    )

    assert hours.online == 2.0
    assert hours.online_label == "2 hours"


def test_active_online_duration_requires_a_success_observation_when_bounded():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "online",
        "accumulated_online_seconds": 0,
        "accumulated_offline_seconds": 0,
        "online_since": start.isoformat(),
        "offline_since": None,
        "last_success_at": None,
    }

    hours = uptime_hours(
        row,
        now=start + timedelta(hours=5),
        health_stale_minutes=120,
    )

    assert hours.online == 0


def test_offline_duration_keeps_counting_from_confirmed_offline_time():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "offline",
        "accumulated_online_seconds": 0,
        "accumulated_offline_seconds": 0,
        "online_since": None,
        "offline_since": start.isoformat(),
        "last_success_at": start.isoformat(),
    }

    hours = uptime_hours(
        row,
        now=start + timedelta(hours=5),
        health_stale_minutes=120,
    )

    assert hours.offline == 5.0
    assert hours.offline_label == "5 hours"


def test_blocked_duration_counts_as_operationally_offline():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "blocked",
        "accumulated_online_seconds": 0,
        "accumulated_offline_seconds": 3600,
        "online_since": None,
        "offline_since": start.isoformat(),
        "last_success_at": start.isoformat(),
    }

    hours = uptime_hours(row, now=start + timedelta(hours=3), earning_enabled=False)

    assert hours.online == 0
    assert hours.offline == 4.0


def test_suspect_duration_keeps_the_confirmed_online_interval_visible():
    start = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
    row = {
        "status": "suspect",
        "accumulated_online_seconds": 0,
        "accumulated_offline_seconds": 0,
        "online_since": start.isoformat(),
        "offline_since": None,
        "last_success_at": start.isoformat(),
    }

    hours = uptime_hours(row, now=start + timedelta(hours=3), health_stale_minutes=120)

    assert hours.online == 2.0
