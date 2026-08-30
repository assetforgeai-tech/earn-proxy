from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxies import add_proxy
from app.services.settings import set_setting
from app.services.users import create_user


def _online_proxy(db, user_id, raw, eligibility, exit_ip):
    proxy_id = add_proxy(db, user_id, raw)
    db.execute(
        "UPDATE proxies SET status='online', eligibility=?, exit_ip=?, detected_protocol='socks5', "
        "last_success_at=? WHERE id=?",
        (eligibility, exit_ip, datetime.now(UTC).isoformat(), proxy_id),
    )
    db.commit()
    return proxy_id


def test_internal_api_defaults_to_allow_and_risk_and_requires_key(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        _online_proxy(db, user_id, "allow.example:9001:u:allow-pass", "allow", "198.51.100.1")
        _online_proxy(db, user_id, "risk.example:9002:u:risk-pass", "risk", "198.51.100.2")

    assert client.get("/internal/api/v1/proxies").status_code == 401
    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.status_code == 200
    assert response.get_data(as_text=True).splitlines() == [
        "allow.example:9001:u:allow-pass",
        "risk.example:9002:u:risk-pass",
    ]


def test_admin_risk_toggle_applies_immediately_but_pause_earn_does_not_remove_proxy(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        _online_proxy(db, user_id, "allow.example:9001:u:allow-pass", "allow", "198.51.100.1")
        _online_proxy(db, user_id, "risk.example:9002:u:risk-pass", "risk", "198.51.100.2")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (user_id,))
        set_setting(db, "api_include_risk", "0")

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["allow.example:9001:u:allow-pass"]


def test_api_excludes_blocked_user_offline_and_duplicate_proxy(app, client):
    with app.app_context():
        db = get_db()
        active = create_user(db, "active@example.com", "password", status="active")
        blocked = create_user(db, "blocked@example.com", "password", status="blocked")
        canonical = _online_proxy(db, active, "canonical.example:9001:u:p", "allow", "198.51.100.8")
        duplicate = _online_proxy(db, active, "duplicate.example:9002:u:p", "allow", "198.51.100.8")
        db.execute("UPDATE proxies SET duplicate_of=? WHERE id=?", (canonical, duplicate))
        offline = add_proxy(db, active, "offline.example:9003:u:p")
        db.execute(
            "UPDATE proxies SET status='offline', eligibility='allow' WHERE id=?",
            (offline,),
        )
        _online_proxy(db, blocked, "blocked.example:9004:u:p", "allow", "198.51.100.9")
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["canonical.example:9001:u:p"]


def test_api_excludes_stale_online_and_suspect_proxies(app, client):
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "freshness@example.com", "password", status="active")
        fresh = _online_proxy(db, user_id, "fresh.example:9001:u:p", "allow", "198.51.100.31")
        stale = _online_proxy(db, user_id, "stale.example:9002:u:p", "allow", "198.51.100.32")
        suspect = _online_proxy(db, user_id, "suspect.example:9003:u:p", "allow", "198.51.100.33")
        db.execute(
            "UPDATE proxies SET last_success_at=? WHERE id=?", ((now - timedelta(minutes=30)).isoformat(), fresh)
        )
        db.execute(
            "UPDATE proxies SET last_success_at=? WHERE id=?", ((now - timedelta(minutes=121)).isoformat(), stale)
        )
        db.execute(
            "UPDATE proxies SET status='suspect', last_success_at=? WHERE id=?",
            ((now - timedelta(minutes=10)).isoformat(), suspect),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["fresh.example:9001:u:p"]


def test_api_excludes_online_rows_without_a_successful_health_observation(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "never-success@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "never-success.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', exit_ip=? WHERE id=?",
            ("198.51.100.40", proxy_id),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.get_data(as_text=True) == ""


def test_api_uses_safe_freshness_default_when_setting_is_malformed(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bad-setting@example.com", "password", status="active")
        _online_proxy(db, user_id, "fresh.example:9001:u:p", "allow", "198.51.100.41")
        set_setting(db, "health_stale_minutes", "not-a-number")

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.status_code == 200
    assert response.get_data(as_text=True).splitlines() == ["fresh.example:9001:u:p"]


def test_api_skips_corrupt_credentials_without_failing_the_distribution_batch(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "corrupt-api@example.com", "password", status="active")
        healthy = _online_proxy(db, user_id, "healthy.example:9001:u:good", "allow", "198.51.100.42")
        corrupt = _online_proxy(db, user_id, "corrupt.example:9002:u:bad", "allow", "198.51.100.43")
        db.execute("UPDATE proxies SET password_encrypted='not-fernet' WHERE id=?", (corrupt,))
        db.commit()

    text_response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    json_response = client.get(
        "/internal/api/v1/proxies?format=json",
        headers={"X-API-Key": "internal-test-key"},
    )

    assert text_response.status_code == 200
    assert text_response.get_data(as_text=True).splitlines() == ["healthy.example:9001:u:good"]
    assert json_response.status_code == 200
    assert [item["endpoint"] for item in json_response.get_json()] == ["healthy.example:9001"]
    assert healthy != corrupt
