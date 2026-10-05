import re
from pathlib import Path

from conftest import login, login_admin, register

ROOT = Path(__file__).parents[1]


def _activate_contributor(app, client, email="ui-refresh@example.com"):
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        from app.db import get_db

        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, email, "member-password")


def test_admin_shell_groups_navigation_and_avoids_false_global_health_claim(client):
    login_admin(client)

    page = client.get("/admin").get_data(as_text=True)

    for group in ("Proxy operations", "Accounts &amp; payments", "Integrations", "Providers"):
        assert group in page
    assert "All systems operational" not in page
    assert "Open the overview for current status" in page


def test_admin_overview_limits_priority_actions_to_four(client):
    login_admin(client)

    page = client.get("/admin").get_data(as_text=True)

    assert page.count('class="quick-link"') == 4
    for label in ("Review proxies", "Tune health checks", "Review users", "Review payouts"):
        assert f"<strong>{label}</strong>" in page


def test_contributor_proxy_page_hides_internal_identity_language(app, client):
    _activate_contributor(app, client)

    page = client.get("/dashboard/proxies").get_data(as_text=True)

    for internal_term in ("Egress identity", "Canonical", "Duplicate egress", "Awaiting probe"):
        assert internal_term not in page
    for public_label in ("Earning eligibility", "Eligible", "Replace recommended", "Checking"):
        assert public_label in page


def test_proxiware_uses_grouped_navigation_and_tablet_card_contract(client):
    login_admin(client)

    page = client.get("/admin/providers/proxiware/qualification").get_data(as_text=True)
    css = (ROOT / "app" / "static" / "app.css").read_text()

    assert 'class="proxiware-nav-groups"' in page
    assert 'id="proxiware-mobile-nav"' in page
    for group in ("Inventory", "Operations", "Connection", "Settings"):
        assert f">{group}<" in page
    assert ".breadcrumbs ol" in css and "list-style: none;" in css
    assert "@media (max-width: 900px)" in css
    tablet_rules = css[css.rindex("@media (max-width: 900px)") :]
    assert ".proxiware-table" in tablet_rules
    assert "min-width: 0;" in tablet_rules
    assert re.search(r"\.proxiware-nav-groups details\[open\] > div\s*\{[^}]*display:\s*grid", css)
    assert not re.search(r"\.proxiware-nav-groups details > div\s*\{[^}]*display:\s*grid", css)
    assert ".proxiware-nav-groups details.is-current > summary" in css


def test_contributor_inventory_switches_to_labeled_cards_before_table_overflows():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    tablet_rules = css[css.rindex("@media (max-width: 900px)") :]

    assert ".table-wrap:has(.proxy-inventory-table)" in tablet_rules
    assert "body.authenticated .proxy-inventory-table tbody" in tablet_rules
    assert "body.authenticated .proxy-inventory-table {\n    display: block;" in tablet_rules
    assert 'th[data-label="Endpoint"]' in tablet_rules
    assert "display: block;" in tablet_rules
    assert "grid-template-columns: 1fr;" in tablet_rules
    assert "content: attr(data-label);" in tablet_rules


def test_admin_inventory_switches_dense_table_to_labeled_cards_at_tablet_width():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    tablet_rules = css[css.rindex("@media (max-width: 900px)") :]

    assert ".table-wrap:has(.admin-proxy-table)" in tablet_rules
    assert "body.authenticated .admin-proxy-table tbody" in tablet_rules
    assert 'th[data-label="Endpoint"]' in tablet_rules
    assert "content: attr(data-label);" in tablet_rules


def test_admin_proxy_desktop_column_widths_fit_the_table():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    widths = re.findall(
        r"\.admin-proxy-table th:nth-child\(\d+\)\s*\{\s*width:\s*(\d+(?:\.\d+)?)%;\s*\}",
        css,
    )

    assert len(widths) == 11
    assert sum(map(float, widths)) == 100


def test_admin_proxy_summary_is_compact_on_mobile():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    mobile_start = css.index("@media (max-width: 700px)", css.index(".admin-proxy-overview"))
    mobile_rules = css[mobile_start:]

    assert re.search(
        r"\.admin-proxy-overview\s*\{\s*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\);",
        mobile_rules,
    )
    assert re.search(r"\.admin-proxy-total\s*\{\s*grid-column:\s*1\s*/\s*-1;", mobile_rules)


def test_admin_proxy_table_keeps_its_desktop_minimum_over_compact_table_rule():
    css = (ROOT / "app" / "static" / "app.css").read_text()

    assert re.search(
        r"@media\s*\(min-width:\s*901px\)\s*\{\s*body\.authenticated \.admin-proxy-table\s*\{\s*min-width:\s*1360px;",
        css,
    )


def test_admin_proxy_horizontal_scroll_has_a_hint_and_keyboard_accessible_region():
    template = (ROOT / "app" / "templates" / "admin_proxies.html").read_text()
    css = (ROOT / "app" / "static" / "app.css").read_text()

    assert 'class="table-wrap admin-proxy-scroll" role="region" tabindex="0"' in template
    assert 'aria-label="Scrollable global proxy inventory"' in template
    assert "scroll horizontally to view all columns." in template
    assert ".admin-proxy-scroll-hint" in css


def test_admin_proxy_scroll_hint_tracks_real_horizontal_overflow():
    template = (ROOT / "app" / "templates" / "admin_proxies.html").read_text()
    css = (ROOT / "app" / "static" / "app.css").read_text()
    js = (ROOT / "app" / "static" / "app.js").read_text()

    assert 'class="admin-proxy-scroll-hint" hidden' in template
    assert ".admin-proxy-scroll-hint[hidden]" in css
    assert "region.scrollWidth > region.clientWidth + 1" in js
    assert template.index('class="admin-proxy-scroll-hint"') < template.index('class="table-wrap admin-proxy-scroll"')


def test_contributor_proxy_horizontal_scroll_is_labeled_and_keyboard_accessible():
    template = (ROOT / "app" / "templates" / "user_dashboard.html").read_text()
    css = (ROOT / "app" / "static" / "app.css").read_text()

    assert 'class="table-wrap proxy-inventory-scroll" role="region" tabindex="0"' in template
    assert 'aria-label="Scrollable proxy inventory"' in template
    assert 'class="proxy-inventory-scroll-hint" hidden' in template
    assert "scroll horizontally to view all columns." in template
    assert ".proxy-inventory-scroll-hint[hidden]" in css
    assert ".proxy-inventory-scroll:focus-visible" in css


def test_scroll_hints_follow_overflow_for_admin_and_contributor_proxy_tables():
    js = (ROOT / "app" / "static" / "app.js").read_text()

    assert 'document.querySelectorAll("[data-scroll-hint]")' in js
    assert "region.scrollWidth > region.clientWidth + 1" in js
    assert 'window.addEventListener("resize", syncScrollHint' in js


def test_contributor_proxy_endpoint_wraps_in_desktop_table():
    css = (ROOT / "app" / "static" / "app.css").read_text()
    desktop_rule = re.search(
        r"@media \(min-width: 701px\) \{\s*body\.authenticated \.proxy-inventory-table tbody th\[scope=\"row\"\] \{([^}]*)\}",
        css,
    )

    assert desktop_rule is not None
    assert "white-space: normal;" in desktop_rule.group(1)
    assert "overflow-wrap: anywhere;" in desktop_rule.group(1)


def test_ui_script_supports_checker_presets_mobile_provider_nav_and_inline_copy_feedback():
    js = (ROOT / "app" / "static" / "app.js").read_text()

    assert "checkerPresets" in js
    assert "proxiwareMobileNav" in js
    assert 'button.textContent = "Copied"' in js


def test_auth_pages_share_the_product_visual_shell(client):
    for path in ("/login", "/register"):
        page = client.get(path).get_data(as_text=True)
        assert 'class="auth-layout"' in page
        assert 'class="auth-brand-panel"' in page
        assert 'class="brand-mark"' in page
