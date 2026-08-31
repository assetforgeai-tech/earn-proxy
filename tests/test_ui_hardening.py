from __future__ import annotations

from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy


def _activate_user(app, client, email="hardening@example.com"):
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, email, "member-password")
    return user_id


def test_branded_error_pages_cover_auth_forbidden_and_missing_routes(app, client):
    assert "Page not found" in client.get("/does-not-exist").get_data(as_text=True)
    assert "Sign in" in client.get("/dashboard").get_data(as_text=True)

    _activate_user(app, client, "forbidden@example.com")
    forbidden = client.get("/admin")
    assert forbidden.status_code == 403
    assert "Access denied" in forbidden.get_data(as_text=True)


def test_browser_validation_marks_the_invalid_field_and_exposes_summary(client):
    response = client.post(
        "/login",
        data={"email": "not-an-email", "password": "", "ui": "1"},
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    assert 'role="alert"' in page
    assert 'aria-invalid="true"' in page
    assert "aria-describedby" in page
    assert "Please correct" in page or "valid email" in page.lower()


def test_dashboard_exposes_progressive_forms_confirmation_and_freshness(app, client):
    user_id = _activate_user(app, client)
    with app.app_context():
        db = get_db()
        proxy_id = add_proxy(db, user_id, "fresh.example:9000:user:pass")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', last_checked_at=datetime('now'), last_success_at=datetime('now','-3 hours'), next_check_at=datetime('now','+1 hour') WHERE id=?",
            (proxy_id,),
        )
        db.commit()
    page = client.get("/dashboard").get_data(as_text=True)
    assert 'data-submit-once="true"' in page
    assert "data-loading-label" in page
    assert "data-confirm-dialog" in page
    assert "data-confirm-trigger" in page
    assert "Enable JavaScript to perform destructive actions safely" in page
    assert "confirm(" not in page
    assert "Last checked" in page and "Next check" in page
    assert 'class="freshness stale"' in page
    assert "Stale result" in page
    assert 'class="mono breakable"' in page
    assert 'data-label="Endpoint"' in page
    assert 'id="dashboard-nav"' in page
    assert 'href="#request-payout"' in page
    assert "<caption>" in page
    assert 'scope="col"' in page


def test_admin_dashboard_uses_accessible_confirmation_and_section_navigation(client):
    register(client, "admin-table@example.com", "member-password")
    login_admin(client)
    page = client.get("/admin/users").get_data(as_text=True)
    assert "data-confirm-dialog" in page
    assert "data-confirm-trigger" in page
    assert "confirm(" not in page
    assert 'id="admin-nav"' in page
    assert "<caption>" in page
    assert 'scope="col"' in page


def test_json_error_contract_remains_json(client):
    response = client.get("/does-not-exist", headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.get_json()["error"]
