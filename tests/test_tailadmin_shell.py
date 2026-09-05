from conftest import login, login_admin, register


def test_admin_pages_render_tailadmin_shell_and_active_navigation(client):
    login_admin(client)

    page = client.get("/admin").get_data(as_text=True)

    assert 'class="app-shell"' in page
    assert 'id="app-sidebar"' in page
    assert 'class="app-topbar"' in page
    assert 'id="mobile-menu-toggle"' in page
    assert 'id="main-content"' in page
    assert 'data-nav="overview"' in page
    assert 'aria-current="page"' in page
    assert 'href="/admin/integrations/api-keys"' in page


def test_admin_subworkspace_marks_its_navigation_item(client):
    login_admin(client)

    page = client.get("/admin/checker").get_data(as_text=True)

    assert 'data-nav="checker"' in page
    assert 'data-nav="overview"' in page
    assert page.count('aria-current="page"') == 1


def test_contributor_dashboard_uses_same_shell_without_exposing_credentials(app, client):
    register(client, "tailadmin-user@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        from app.db import get_db

        user_id = (
            get_db().execute("SELECT id FROM users WHERE email=?", ("tailadmin-user@example.com",)).fetchone()["id"]
        )
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, "tailadmin-user@example.com", "member-password")

    page = client.get("/dashboard").get_data(as_text=True)

    assert 'class="app-shell"' in page
    assert 'id="app-sidebar"' in page
    assert 'data-nav="dashboard"' in page
    assert "private-user" not in page
    assert "private-pass" not in page


def test_auth_pages_keep_lightweight_auth_shell(client):
    page = client.get("/login").get_data(as_text=True)

    assert 'class="auth-shell"' in page
    assert 'id="app-sidebar"' not in page
