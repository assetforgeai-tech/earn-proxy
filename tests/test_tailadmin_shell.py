from pathlib import Path

from conftest import login, login_admin, register

ADMIN_NAV_LABELS = (
    "Overview",
    "Health checker",
    "Users",
    "Payouts",
    "Distribution API",
    "API keys",
    "Transfer Proxy",
)


def _activate_contributor(app, client, email="tailadmin-user@example.com"):
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        from app.db import get_db

        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, email, "member-password")
    return user_id


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
    assert "data-page-search" not in page
    assert 'class="topbar-context"' in page


def test_admin_subworkspace_marks_its_navigation_item(client):
    login_admin(client)

    page = client.get("/admin/checker").get_data(as_text=True)

    assert 'data-nav="checker"' in page
    assert 'data-nav="overview"' in page
    assert page.count('aria-current="page"') == 1


def test_admin_sidebar_is_the_only_workspace_navigation_and_uses_canonical_labels(client):
    login_admin(client)

    for path in (
        "/admin",
        "/admin/checker",
        "/admin/users",
        "/admin/payouts",
        "/admin/integrations",
        "/admin/integrations/api-keys",
        "/admin/transfer-proxy",
    ):
        page = client.get(path).get_data(as_text=True)
        assert 'class="section-nav"' not in page
        assert page.count('aria-current="page"') == 1
        for label in ADMIN_NAV_LABELS:
            assert f"<span>{label}</span>" in page


def test_admin_overview_is_the_only_page_with_complete_quick_links(client):
    login_admin(client)
    overview = client.get("/admin").get_data(as_text=True)

    assert overview.count('class="quick-link"') == 6
    for label in ADMIN_NAV_LABELS[1:]:
        assert f"<strong>{label}</strong>" in overview

    for path in (
        "/admin/checker",
        "/admin/users",
        "/admin/payouts",
        "/admin/integrations",
        "/admin/integrations/api-keys",
        "/admin/transfer-proxy",
    ):
        assert 'class="quick-link"' not in client.get(path).get_data(as_text=True)


def test_contributor_dashboard_uses_same_shell_without_exposing_credentials(app, client):
    _activate_contributor(app, client)

    page = client.get("/dashboard").get_data(as_text=True)

    assert 'class="app-shell"' in page
    assert 'id="app-sidebar"' in page
    assert 'data-nav="dashboard"' in page
    assert "private-user" not in page
    assert "private-pass" not in page


def test_contributor_workspaces_have_distinct_routes_content_and_active_navigation(app, client):
    _activate_contributor(app, client, "route-user@example.com")

    expectations = {
        "/dashboard": ('data-nav="dashboard"', "Earnings overview", "Add proxy"),
        "/dashboard/proxies": ('data-nav="proxy_pool"', "Add proxy", "Request payout"),
        "/dashboard/earnings": ('data-nav="earnings"', "Earnings overview", "Add proxy"),
        "/dashboard/wallet": ('data-nav="wallet"', "Request payout", "Add proxy"),
    }
    for path, (active_nav, visible_text, absent_text) in expectations.items():
        response = client.get(path)
        page = response.get_data(as_text=True)
        assert response.status_code == 200
        assert f'{active_nav} aria-current="page"' in page
        assert page.count('aria-current="page"') == 1
        assert visible_text in page
        assert absent_text not in page
        assert 'id="dashboard-nav"' not in page
        assert 'class="quick-link"' not in page


def test_mobile_drawer_markup_and_script_prevent_hidden_focus():
    root = Path(__file__).parents[1]
    base = (root / "app" / "templates" / "base.html").read_text()
    js = (root / "app" / "static" / "app.js").read_text()

    assert 'id="sidebar-overlay"' in base and " hidden" in base
    assert "sidebar.inert" in js
    assert "menuToggle?.focus" in js
    assert "syncSidebarMode" in js
    assert "focusableElements" in js


def test_auth_pages_keep_lightweight_auth_shell(client):
    page = client.get("/login").get_data(as_text=True)

    assert 'class="auth-shell"' in page
    assert 'id="app-sidebar"' not in page


def test_theme_control_has_a_persisted_visual_theme_contract():
    css = (Path(__file__).parents[1] / "app" / "static" / "app.css").read_text()
    js = (Path(__file__).parents[1] / "app" / "static" / "app.js").read_text()

    assert ".theme-dark" in css
    assert "localStorage" in js
    assert "data-theme-toggle" in (Path(__file__).parents[1] / "app" / "templates" / "base.html").read_text()
