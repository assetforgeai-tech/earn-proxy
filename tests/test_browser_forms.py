from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy


def _activate_user(app, client, email="browser@example.com"):
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    return user_id


def test_browser_login_redirects_to_dashboard_and_keeps_json_contract(app, client):
    _activate_user(app, client)

    browser_response = client.post(
        "/login",
        data={"email": "browser@example.com", "password": "member-password", "ui": "1"},
    )
    assert browser_response.status_code == 303
    assert browser_response.headers["Location"].endswith("/dashboard")

    client.post("/logout")
    api_response = login(client, "browser@example.com", "member-password")
    assert api_response.status_code == 200
    assert api_response.get_json()["status"] == "active"


def test_browser_registration_and_validation_show_feedback(client):
    invalid = client.post(
        "/register",
        data={"email": "invalid", "password": "short", "ui": "1"},
        follow_redirects=True,
    )
    assert invalid.status_code == 200
    assert "valid email" in invalid.get_data(as_text=True).lower()

    created = client.post(
        "/register",
        data={"email": "pending@example.com", "password": "member-password", "ui": "1"},
        follow_redirects=True,
    )
    assert created.status_code == 200
    page = created.get_data(as_text=True)
    assert "awaiting administrator approval" in page.lower()
    assert "Sign in" in page


def test_admin_browser_forms_redirect_and_flash(app, client):
    login_admin(client)
    response = client.post(
        "/admin/settings",
        data={
            "health_interval_minutes": "60",
            "health_concurrency": "3",
            "api_include_allow": "1",
            "api_include_risk": "1",
            "ui": "1",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Checker policy saved" in page
    assert 'value="60"' in page
    assert 'value="3"' in page


def test_user_browser_forms_redirect_and_dashboard_has_payout_form(app, client):
    user_id = _activate_user(app, client)
    login(client, "browser@example.com", "member-password")

    added = client.post(
        "/proxies",
        data={"raw_proxy": "browser-proxy.example:9000:user:pass", "ui": "1"},
        follow_redirects=True,
    )
    assert added.status_code == 200
    page = added.get_data(as_text=True)
    assert "Proxy added" in page
    assert "browser-proxy.example:9000" in page
    assert 'action="/payouts"' in page
    assert 'name="amount_usd"' in page

    with app.app_context():
        proxy_id = add_proxy(get_db(), user_id, "second-proxy.example:9001:user:pass")
    removed = client.post(f"/proxies/{proxy_id}/delete", data={"ui": "1"})
    assert removed.status_code == 303
    assert removed.headers["Location"].endswith("/dashboard")
