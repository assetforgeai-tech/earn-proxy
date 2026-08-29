from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.checks import apply_health_result
from app.services.proxies import add_proxy
from app.services.uptime import uptime_hours
from app.services.users import create_user


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
        hours = uptime_hours(row, now=start + timedelta(hours=6))
    assert hours.online == 4.0
    assert hours.offline == 2.0
