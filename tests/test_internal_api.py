from __future__ import annotations

from app.db import get_db
from app.services.proxies import add_proxy
from app.services.settings import set_setting
from app.services.users import create_user


def _online_proxy(db, user_id, raw, eligibility, exit_ip):
    proxy_id = add_proxy(db, user_id, raw)
    db.execute(
        "UPDATE proxies SET status='online', eligibility=?, exit_ip=?, detected_protocol='socks5' WHERE id=?",
        (eligibility, exit_ip, proxy_id),
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
