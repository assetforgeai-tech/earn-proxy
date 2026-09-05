from datetime import UTC, datetime

from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy
from app.services.users import create_user


def _activate_user(app, client):
    register(client, "ui-user@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='ui-user@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, "ui-user@example.com", "member-password")
    return user_id


def test_user_dashboard_shows_safe_proxy_controls_uptime_and_payout_history(app, client):
    user_id = _activate_user(app, client)
    with app.app_context():
        db = get_db()
        proxy_id = add_proxy(db, user_id, "safe.example:9000:private-user:private-pass")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', eligibility='allow', online_since=datetime('now') WHERE id=?",
            (proxy_id,),
        )
        db.commit()
    page = client.get("/dashboard/proxies").get_data(as_text=True)
    assert "Replace" in page
    assert "Remove" in page
    assert "Online hours" in page
    assert "Wallet &amp; payouts" in page
    assert "private-user" not in page
    assert "private-pass" not in page


def test_admin_dashboard_exposes_create_delete_and_payout_controls(app, client):
    register(client, "admin-ui-user@example.com", "member-password")
    client.post("/logout")
    login_admin(client)
    users_page = client.get("/admin/users").get_data(as_text=True)
    payouts_page = client.get("/admin/payouts").get_data(as_text=True)
    assert 'action="/admin/users"' in users_page
    assert "Delete" in users_page
    assert "Payout queue" in payouts_page
    assert "Approve the request, transfer USDT manually" in payouts_page
    assert "transaction hash" in payouts_page.lower()


def test_internal_api_json_mode_labels_allow_and_risk(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "json@example.com", "password", status="active")
        first = add_proxy(db, user_id, "json-allow.example:9000:u:a")
        second = add_proxy(db, user_id, "json-risk.example:9001:u:r")
        success_at = datetime.now(UTC).isoformat()
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', "
            "exit_ip='198.51.100.60', egress_verified_at=?, "
            "egress_attestation_source='https_quorum', last_success_at=? WHERE id=?",
            (success_at, success_at, first),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='risk', detected_protocol='http', "
            "exit_ip='198.51.100.61', egress_verified_at=?, "
            "egress_attestation_source='https_quorum', last_success_at=? WHERE id=?",
            (success_at, success_at, second),
        )
        db.commit()
    response = client.get(
        "/internal/api/v1/proxies?format=json",
        headers={"X-API-Key": "internal-test-key"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert [item["status"] for item in payload] == ["Allow", "Risk"]
    assert payload[0]["raw"] == "json-allow.example:9000:u:a"
