from pathlib import Path

from conftest import login, login_admin, register

ADMIN_NAV_LABELS = (
    "Overview",
    "Health checker",
    "Egress duplicates",
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
        "/admin/egress-duplicates",
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

    assert overview.count('class="quick-link"') == 7
    for label in ADMIN_NAV_LABELS[1:]:
        assert f"<strong>{label}</strong>" in overview

    for path in (
        "/admin/checker",
        "/admin/egress-duplicates",
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


def test_data_heavy_workspaces_use_compact_table_contract(client):
    root = Path(__file__).parents[1]
    user_template = (root / "app" / "templates" / "user_dashboard.html").read_text()
    admin_template = (root / "app" / "templates" / "admin_dashboard.html").read_text()
    api_keys_template = (root / "app" / "templates" / "admin_api_keys.html").read_text()
    duplicates_template = (root / "app" / "templates" / "admin_egress_duplicates.html").read_text()
    css = (root / "app" / "static" / "app.css").read_text()
    js = (root / "app" / "static" / "app.js").read_text()

    assert "proxy-inventory-table" in user_template
    assert "compact-data-table" in admin_template
    assert "compact-data-table" in api_keys_template
    assert "compact-data-table" in duplicates_template
    assert ".proxy-row-actions" in css
    assert ".compact-data-table" in css
    assert "openReplaceDialog" in js
    assert "replaceDialog.showModal()" in js


def test_proxy_actions_fit_one_compact_touch_safe_row():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()

    assert ".proxy-inventory-table {\n  min-width: 1000px;" in css
    assert ".proxy-inventory-table th:nth-child(9) { width: 17%; }" in css
    assert (
        ".proxy-row-actions {\n  display: flex;\n  min-width: 0;\n  align-items: center;\n  gap: 6px;\n  flex-wrap: nowrap;"
        in css
    )
    assert ".proxy-row-actions .button {\n  min-height: 44px;" in css
    assert "body.authenticated .responsive-table .proxy-row-actions form" in css


def test_proxy_endpoint_column_keeps_host_port_readable_on_desktop():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()

    assert ".proxy-inventory-table th:nth-child(1) { width: 20%; }" in css
    assert "@media (min-width: 701px)" in css
    desktop_rule = css[css.index("@media (min-width: 701px)") :]
    assert 'body.authenticated .proxy-inventory-table tbody th[scope="row"]' in desktop_rule
    assert "white-space: nowrap;" in desktop_rule


def test_proxy_action_cascade_keeps_controls_inline_after_legacy_actions_rules():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()

    action_rule = css.index("body.authenticated .proxy-inventory-table .proxy-row-actions {")
    form_rule = css.index("body.authenticated .proxy-inventory-table .proxy-row-actions form {")
    assert "flex-wrap: nowrap;" in css[action_rule : action_rule + 240]
    assert "align-items: center;" in css[action_rule : action_rule + 240]
    assert "display: inline-flex;" in css[form_rule : form_rule + 180]


def test_authenticated_dark_mode_remaps_legacy_data_tokens_and_states():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()

    dark_rule = css[css.index("body.authenticated.theme-dark {") :]
    for declaration in (
        "--ink: #f2f4f7;",
        "--ink-soft: #d0d5dd;",
        "--muted: #b7c3d4;",
        "--shell-muted: #b7c3d4;",
        "--surface-strong: #1d2939;",
        "--line-strong: #475467;",
    ):
        assert declaration in dark_rule
    assert "body.authenticated.theme-dark .freshness.fresh strong" in dark_rule
    assert "body.authenticated.theme-dark .freshness.stale strong" in dark_rule
    assert "body.authenticated.theme-dark .format-guide summary small" in dark_rule


def test_mobile_inventory_summary_prioritizes_status_and_egress_without_tiny_targets():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()

    mobile_rule = css[css.index("@media (max-width: 700px) {", css.index("/* Compact authenticated workspaces")) :]
    assert (
        "body.authenticated .inventory-summary {\n    grid-template-columns: repeat(2, minmax(0, 1fr));" in mobile_rule
    )
    assert "body.authenticated .inventory-summary .inventory-count-group:nth-child(1)," in mobile_rule
    assert "body.authenticated .inventory-summary .inventory-count-group:nth-child(4)" in mobile_rule
    assert "grid-template-columns: repeat(auto-fit, minmax(76px, 1fr));" in mobile_rule
    count_rule = mobile_rule[mobile_rule.index("body.authenticated .inventory-summary .inventory-count {") :]
    assert "min-height: 44px;" in count_rule[:240]
    assert "flex-direction: row;" in count_rule[:240]
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in mobile_rule
    assert "grid-column: 1 / -1;" in mobile_rule
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in mobile_rule


def test_mobile_authenticated_controls_keep_touch_targets_at_least_44px():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()
    mobile_rule = css[css.index("@media (max-width: 700px) {", css.index("/* Compact authenticated workspaces")) :]

    assert (
        "body.authenticated .inventory-toolbar input,\n  body.authenticated .inventory-toolbar select {\n    min-height: 44px;"
        in mobile_rule
    )
    assert "body.authenticated .page-link {\n    min-height: 44px;" in mobile_rule


def test_mobile_inventory_compacts_protocol_and_eligibility_side_by_side():
    root = Path(__file__).parents[1]
    css = (root / "app" / "static" / "app.css").read_text()
    mobile_rule = css[css.index("@media (max-width: 700px) {", css.index("/* Compact authenticated workspaces")) :]

    assert (
        "body.authenticated .inventory-summary .inventory-count-group:nth-child(2),\n  body.authenticated .inventory-summary .inventory-count-group:nth-child(3) {\n    grid-column: auto;"
        in mobile_rule
    )
    assert (
        "body.authenticated .inventory-summary .inventory-count-group:nth-child(2) .inventory-count-list,\n  body.authenticated .inventory-summary .inventory-count-group:nth-child(3) .inventory-count-list {\n    grid-template-columns: repeat(2, minmax(0, 1fr));"
        in mobile_rule
    )
