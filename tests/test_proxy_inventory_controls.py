from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from html import unescape
from urllib.parse import parse_qs, urlparse

from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy


def _activate_user(app, client, email: str) -> int:
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, email, "member-password")
    return int(user_id)


def _seed_inventory(app, user_id: int, count: int = 31) -> None:
    with app.app_context():
        db = get_db()
        for index in range(count):
            proxy_id = add_proxy(db, user_id, f"node-{index:02d}.example:9000:user-{index}:secret-{index}")
            status = "online" if index % 3 == 0 else "offline" if index % 3 == 1 else "pending"
            protocol = "socks5" if index % 2 == 0 else "http"
            eligibility = "allow" if index % 4 == 0 else "risk" if index % 4 == 1 else "pending"
            db.execute(
                "UPDATE proxies SET status=?, detected_protocol=?, eligibility=? WHERE id=?",
                (status, protocol, eligibility, proxy_id),
            )
        db.commit()


def test_proxy_inventory_reports_counts_and_server_side_pagination(app, client):
    user_id = _activate_user(app, client, "inventory-page@example.com")
    _seed_inventory(app, user_id)

    response = client.get("/dashboard/proxies?per_page=10&page=2&sort=endpoint&direction=asc")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "31 total" in page
    assert "Showing 11–20 of 31" in page
    assert "node-10.example:9000" in page
    assert "node-00.example:9000" not in page
    assert 'name="per_page"' in page
    assert 'value="10" selected' in page
    assert 'aria-sort="ascending"' in page
    assert "page=3" in page


def test_proxy_inventory_search_and_quick_filters_are_composable(app, client):
    user_id = _activate_user(app, client, "inventory-filter@example.com")
    _seed_inventory(app, user_id)

    response = client.get("/dashboard/proxies?q=node-12&status=online&protocol=socks5&eligibility=allow&per_page=10")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Showing 1–1 of 1" in page
    assert "node-12.example:9000" in page
    assert "node-00.example:9000" not in page
    assert 'name="q"' in page
    assert 'name="status"' in page
    assert 'name="protocol"' in page
    assert 'name="eligibility"' in page
    assert "Clear filters" in page


def test_proxy_inventory_active_quick_filters_toggle_off_individually(app, client):
    user_id = _activate_user(app, client, "inventory-filter-toggle@example.com")
    _seed_inventory(app, user_id)

    page = client.get(
        "/dashboard/proxies?q=node&status=online&protocol=socks5&eligibility=allow&identity=awaiting&per_page=10"
    ).get_data(as_text=True)
    active_links = {
        label: parse_qs(urlparse(unescape(href)).query)
        for href, label in re.findall(
            r'<a class="inventory-count[^\"]*is-active[^\"]*" href="([^\"]+)"><span>([^<]+)</span>',
            page,
        )
    }

    expected_filters = {
        "Online": "status",
        "SOCKS5": "protocol",
        "Allow": "eligibility",
        "Awaiting probe": "identity",
    }
    for label, removed_filter in expected_filters.items():
        assert removed_filter not in active_links[label]
        assert active_links[label]["q"] == ["node"]
        assert active_links[label]["page"] == ["1"]
        assert all(
            name in active_links[label] for name in {"status", "protocol", "eligibility", "identity"} - {removed_filter}
        )


def test_proxy_inventory_normalizes_invalid_controls_without_server_error(app, client):
    user_id = _activate_user(app, client, "inventory-invalid@example.com")
    _seed_inventory(app, user_id, count=3)

    response = client.get(
        "/dashboard/proxies?page=-99&per_page=999&sort=not-a-column&direction=sideways&status=unknown"
    )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Showing 1–3 of 3" in page
    assert 'value="25" selected' in page
    assert "node-00.example:9000" in page


def test_proxy_inventory_sort_links_preserve_filters_and_toggle_direction(app, client):
    user_id = _activate_user(app, client, "inventory-sort@example.com")
    _seed_inventory(app, user_id, count=12)

    response = client.get(
        "/dashboard/proxies?q=node&status=online&protocol=socks5&eligibility=allow&per_page=10&sort=status&direction=asc"
    )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "sort=status" in page
    assert "direction=desc" in page
    assert "q=node" in page
    assert "protocol=socks5" in page
    assert "eligibility=allow" in page


def test_proxy_inventory_never_exposes_credentials_in_search_or_pagination(app, client):
    user_id = _activate_user(app, client, "inventory-secret@example.com")
    _seed_inventory(app, user_id, count=31)

    response = client.get("/dashboard/proxies?page=2&per_page=10")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "secret-" not in page
    assert "user-" not in page


def test_proxy_inventory_filters_and_labels_global_egress_identity(app, client):
    user_id = _activate_user(app, client, "inventory-egress@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "egress-a.example:9000:u-a:p-a")
        duplicate = add_proxy(db, user_id, "egress-b.example:9001:u-b:p-b")
        add_proxy(db, user_id, "egress-c.example:9002:u-c:p-c")
        db.execute(
            "UPDATE proxies SET status='online', exit_ip='198.51.100.10', "
            "egress_attestation_source='https_quorum' WHERE id=?",
            (canonical,),
        )
        db.execute(
            "UPDATE proxies SET status='online', exit_ip='198.51.100.10', "
            "egress_attestation_source='earnapp_tls', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()

    all_rows = client.get("/dashboard/proxies").get_data(as_text=True)
    duplicate_rows = client.get("/dashboard/proxies?identity=duplicate").get_data(as_text=True)

    assert "Egress identity" in all_rows
    assert "Canonical" in all_rows
    assert "Duplicate egress" in all_rows
    assert "Awaiting probe" in all_rows
    assert "Duplicate egress does not earn or enter API distribution." in all_rows
    assert "198.51.100.10" not in all_rows
    assert "egress-b.example:9001" in duplicate_rows
    assert "egress-a.example:9000" not in duplicate_rows
    assert "egress-c.example:9002" not in duplicate_rows
    assert "Showing 1–1 of 1" in duplicate_rows
    assert 'value="duplicate" selected' in duplicate_rows


def test_proxy_inventory_keeps_untrusted_duplicate_pointer_in_awaiting_state(app, client):
    user_id = _activate_user(app, client, "inventory-egress-untrusted@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "untrusted-a.example:9000:u-a:p-a")
        malformed = add_proxy(db, user_id, "untrusted-b.example:9001:u-b:p-b")
        db.execute("UPDATE proxies SET duplicate_of=? WHERE id=?", (canonical, malformed))
        db.commit()

    duplicate_rows = client.get("/dashboard/proxies?identity=duplicate").get_data(as_text=True)
    awaiting_rows = client.get("/dashboard/proxies?identity=awaiting").get_data(as_text=True)

    assert "untrusted-b.example:9001" not in duplicate_rows
    assert "untrusted-b.example:9001" in awaiting_rows


def test_duplicate_egress_is_not_presented_as_earning_allow(app, client):
    user_id = _activate_user(app, client, "inventory-effective-earning@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "effective-canonical.example:9000:u-a:p-a")
        duplicate = add_proxy(db, user_id, "effective-duplicate.example:9001:u-b:p-b")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.77', "
            "egress_attestation_source='https_quorum' WHERE id=?",
            (canonical,),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.77', "
            "egress_attestation_source='earnapp_tls', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()

    page = client.get("/dashboard/proxies?identity=duplicate").get_data(as_text=True)
    row_start = page.index("effective-duplicate.example:9001")
    row = page[row_start : page.index("</tr>", row_start)]
    assert 'class="badge excluded">Not earning</span>' in row
    assert "Duplicate egress blocks earnings and distribution" in row
    assert ">Allow<" not in row


def test_stale_duplicate_pointer_is_fail_closed_in_earning_view(app, client):
    user_id = _activate_user(app, client, "inventory-stale-duplicate@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "stale-canonical.example:9000:u-a:p-a")
        duplicate = add_proxy(db, user_id, "stale-duplicate.example:9001:u-b:p-b")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()

    page = client.get("/dashboard/proxies").get_data(as_text=True)
    row_start = page.index("stale-duplicate.example:9001")
    row = page[row_start : page.index("</tr>", row_start)]
    assert 'class="badge excluded">Not earning</span>' in row
    assert ">Allow<" not in row


def test_not_earning_proxy_does_not_show_online_hours(app, client):
    user_id = _activate_user(app, client, "inventory-no-earning-hours@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "hours-canonical.example:9000:u-a:p-a")
        duplicate = add_proxy(db, user_id, "hours-duplicate.example:9001:u-b:p-b")
        old = datetime.now(UTC) - timedelta(hours=3)
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.88', "
            "egress_attestation_source='https_quorum', accumulated_online_seconds=3600, "
            "online_since=?, last_success_at=? WHERE id=?",
            (old.isoformat(), old.isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.88', "
            "egress_attestation_source='earnapp_tls', duplicate_of=?, accumulated_online_seconds=3600, "
            "accumulated_offline_seconds=1800, "
            "online_since=?, last_success_at=? WHERE id=?",
            (canonical, old.isoformat(), old.isoformat(), duplicate),
        )
        db.commit()

    page = client.get("/dashboard/proxies?identity=duplicate").get_data(as_text=True)
    row_start = page.index("hours-duplicate.example:9001")
    row = page[row_start : page.index("</tr>", row_start)]

    assert 'class="badge excluded">Not earning</span>' in row
    assert 'title="0.00 total hours"' in row
    assert 'title="0.50 total hours"' in row
    assert "30 minutes" in row
    assert "1 hour" not in row


def test_only_canonical_allow_and_risk_rows_show_online_hours(app, client):
    user_id = _activate_user(app, client, "inventory-earning-hours@example.com")
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        allow = add_proxy(db, user_id, "hours-allow.example:9000:u-a:p-a")
        risk = add_proxy(db, user_id, "hours-risk.example:9001:u-r:p-r")
        pending = add_proxy(db, user_id, "hours-pending.example:9002:u-p:p-p")
        awaiting = add_proxy(db, user_id, "hours-awaiting.example:9003:u-w:p-w")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.91', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=2)).isoformat(),
                now.isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                allow,
            ),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='risk', exit_ip='198.51.100.92', "
            "egress_attestation_source='earnapp_tls', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=1)).isoformat(),
                now.isoformat(),
                (now - timedelta(hours=1)).isoformat(),
                (now - timedelta(hours=1)).isoformat(),
                risk,
            ),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='pending', exit_ip='198.51.100.93', "
            "egress_attestation_source='https_quorum', accumulated_online_seconds=10800, "
            "online_since=?, last_success_at=? WHERE id=?",
            (now.isoformat(), now.isoformat(), pending),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', accumulated_online_seconds=14400, "
            "online_since=?, last_success_at=? WHERE id=?",
            (now.isoformat(), now.isoformat(), awaiting),
        )
        db.commit()

    page = client.get("/dashboard/proxies?sort=endpoint&direction=asc").get_data(as_text=True)

    def proxy_row(endpoint: str) -> str:
        start = page.index(endpoint)
        return page[start : page.index("</tr>", start)]

    assert 'title="2.00 total hours"' in proxy_row("hours-allow.example:9000")
    assert 'title="1.00 total hours"' in proxy_row("hours-risk.example:9001")
    assert 'title="0.00 total hours"' in proxy_row("hours-pending.example:9002")
    assert 'title="0.00 total hours"' in proxy_row("hours-awaiting.example:9003")


def test_online_sort_uses_displayed_earning_time(app, client):
    user_id = _activate_user(app, client, "inventory-sort-earning-hours@example.com")
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        low = add_proxy(db, user_id, "sort-low.example:9000:u:l")
        high = add_proxy(db, user_id, "sort-high.example:9001:u:h")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.101', "
            "egress_attestation_source='https_quorum', accumulated_online_seconds=100*3600, "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=1)).isoformat(),
                now.isoformat(),
                (now - timedelta(hours=1)).isoformat(),
                (now - timedelta(hours=1)).isoformat(),
                low,
            ),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.102', "
            "egress_attestation_source='https_quorum', accumulated_online_seconds=0, "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=2)).isoformat(),
                now.isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                high,
            ),
        )
        db.commit()

    page = client.get("/dashboard/proxies?sort=online&direction=desc").get_data(as_text=True)

    assert page.index("sort-high.example:9001") < page.index("sort-low.example:9000")


def test_offline_sort_includes_current_offline_interval(app, client):
    user_id = _activate_user(app, client, "inventory-sort-offline-hours@example.com")
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        stored = add_proxy(db, user_id, "sort-stored-offline.example:9000:u:s")
        active = add_proxy(db, user_id, "sort-active-offline.example:9001:u:a")
        db.execute(
            "UPDATE proxies SET status='online', accumulated_offline_seconds=? WHERE id=?",
            (3 * 3600, stored),
        )
        db.execute(
            "UPDATE proxies SET status='offline', accumulated_offline_seconds=0, offline_since=? WHERE id=?",
            ((now - timedelta(hours=5)).isoformat(), active),
        )
        db.commit()

    page = client.get("/dashboard/proxies?sort=offline&direction=desc").get_data(as_text=True)

    assert page.index("sort-active-offline.example:9001") < page.index("sort-stored-offline.example:9000")
