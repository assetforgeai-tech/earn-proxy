from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from html import unescape
from urllib.parse import parse_qs, urlparse

from conftest import login, login_admin, register

from app.db import get_db
from app.routes.admin import ADMIN_PROXY_STATUSES, _admin_proxy_page
from app.services.proxies import add_proxy
from app.services.users import create_user


def _seed_proxy(
    db,
    user_id: int,
    raw: str,
    *,
    status: str = "pending",
    protocol: str = "unknown",
    eligibility: str = "pending",
    country: str = "",
    exit_ip: str = "",
    duplicate_of: int | None = None,
    last_success_at: str | None = None,
    next_check_at: str | None = None,
    archived_at: str | None = None,
) -> int:
    proxy_id = add_proxy(db, user_id, raw)
    db.execute(
        """
        UPDATE proxies SET status=?, detected_protocol=?, eligibility=?, country_code=?,
            exit_ip=?, egress_attestation_source=?, duplicate_of=?, last_success_at=?,
            last_checked_at=?, next_check_at=?, archived_at=? WHERE id=?
        """,
        (
            status,
            protocol,
            eligibility,
            country,
            exit_ip or None,
            "https_quorum" if exit_ip else "",
            duplicate_of,
            last_success_at,
            last_success_at,
            next_check_at,
            archived_at,
            proxy_id,
        ),
    )
    return proxy_id


def _seed_admin_inventory(app) -> dict[str, int]:
    now = datetime.now(UTC)
    fresh = (now - timedelta(minutes=5)).isoformat()
    stale = (now - timedelta(hours=4)).isoformat()
    next_check = (now + timedelta(minutes=30)).isoformat()
    due = (now - timedelta(minutes=1)).isoformat()
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "first-owner@example.com", "password", status="active")
        second_user = create_user(db, "second-owner@example.com", "password", status="active")
        canonical = _seed_proxy(
            db,
            first_user,
            "us-canonical.example:9000:private-a:secret-a",
            status="online",
            protocol="socks5",
            eligibility="allow",
            country="US",
            exit_ip="198.51.100.10",
            last_success_at=fresh,
            next_check_at=next_check,
        )
        duplicate = _seed_proxy(
            db,
            second_user,
            "us-duplicate.example:9001:private-b:secret-b",
            status="online",
            protocol="socks5",
            eligibility="allow",
            country="US",
            exit_ip="198.51.100.10",
            duplicate_of=canonical,
            last_success_at=fresh,
            next_check_at=due,
        )
        _seed_proxy(
            db,
            second_user,
            "vn-offline.example:9002:private-c:secret-c",
            status="offline",
            protocol="http",
            eligibility="risk",
            country="VN",
            last_success_at=stale,
            next_check_at=next_check,
        )
        archived = _seed_proxy(
            db,
            first_user,
            "archived.example:9003:private-d:secret-d",
            status="offline",
            protocol="http",
            eligibility="pending",
            country="SG",
            archived_at=stale,
        )
        db.commit()
    return {"canonical": canonical, "duplicate": duplicate, "archived": archived}


def test_admin_proxy_inventory_is_global_credential_safe_and_paginated(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    response = client.get("/admin/proxies?per_page=25")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    page = response.get_data(as_text=True)
    assert "Proxy inventory" in page
    assert "3 total proxies" in page
    assert "Online" in page and "2" in page
    assert "Allow" in page and "2" in page
    assert "us-canonical.example:9000" in page
    assert "us-duplicate.example:9001" in page
    assert "vn-offline.example:9002" in page
    assert "archived.example:9003" not in page
    assert "private-a" not in page
    assert "secret-a" not in page
    assert 'data-nav="proxies" aria-current="page"' in page


def test_admin_proxy_inventory_supports_composable_filters_and_freshness(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    response = client.get(
        "/admin/proxies?owner=second-owner@example.com&endpoint=us-&status=online&protocol=socks5&"
        "eligibility=allow&identity=duplicate&country=US&freshness=due"
    )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Showing 1–1 of 1 proxies" in page
    assert "us-duplicate.example:9001" in page
    assert "us-canonical.example:9000" not in page
    assert "vn-offline.example:9002" not in page
    assert 'name="owner"' in page
    assert 'name="endpoint"' in page
    assert 'name="freshness"' in page
    assert "Clear filters" in page


def test_admin_proxy_inventory_active_quick_filters_toggle_off_individually(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    page = client.get(
        "/admin/proxies?q=example&status=online&protocol=socks5&eligibility=allow&identity=duplicate&"
        "country=US&freshness=due&per_page=25"
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
        "Duplicate": "identity",
    }
    for label, removed_filter in expected_filters.items():
        assert removed_filter not in active_links[label]
        assert active_links[label]["q"] == ["example"]
        assert active_links[label]["country"] == ["US"]
        assert active_links[label]["freshness"] == ["due"]
        assert active_links[label]["page"] == ["1"]
        assert all(
            name in active_links[label] for name in {"status", "protocol", "eligibility", "identity"} - {removed_filter}
        )


def test_admin_proxy_inventory_searches_owner_exit_ip_and_has_archived_scope(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    by_exit = client.get("/admin/proxies?q=198.51.100.10").get_data(as_text=True)
    archived = client.get("/admin/proxies?archived=archived").get_data(as_text=True)

    assert "us-canonical.example:9000" in by_exit
    assert "us-duplicate.example:9001" in by_exit
    assert "vn-offline.example:9002" not in by_exit
    assert "archived.example:9003" in archived
    assert "us-canonical.example:9000" not in archived
    assert "Archived" in archived


def test_admin_proxy_inventory_sort_and_invalid_controls_are_safe(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    response = client.get(
        "/admin/proxies?page=-10&per_page=999&sort=not-allowed&direction=sideways&status=not-a-status"
    )

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Showing 1–3 of 3 proxies" in page
    assert 'value="25" selected' in page
    assert 'name="sort"' in page
    assert 'aria-sort="descending"' in page


def test_admin_proxy_inventory_is_admin_only(app, client):
    register(client, "inventory-member@example.com", "member-password")
    login(client, "inventory-member@example.com", "member-password")

    assert client.get("/admin/proxies").status_code == 403


def test_admin_proxy_inventory_uses_real_server_side_pages(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "page-owner@example.com", "password", status="active")
        for index in range(26):
            _seed_proxy(db, user_id, f"page-{index:02d}.example:9000:u-{index}:p-{index}")
        db.commit()
    login_admin(client)

    page = client.get("/admin/proxies?per_page=25&page=2&sort=endpoint&direction=asc").get_data(as_text=True)

    assert "Showing 26–26 of 26 proxies" in page
    assert "page-25.example:9000" in page
    assert "page-00.example:9000" not in page
    assert "Page 2 of 2" in page


def test_admin_proxy_inventory_handles_sqlite_timestamps_consistently(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "freshness-owner@example.com", "password", status="active")
        fresh = add_proxy(db, user_id, "fresh-sqlite.example:9000:u-fresh:p-fresh")
        due = add_proxy(db, user_id, "due-sqlite.example:9001:u-due:p-due")
        stale = add_proxy(db, user_id, "stale-sqlite.example:9002:u-stale:p-stale")
        missing_success = add_proxy(db, user_id, "missing-success.example:9003:u-missing:p-missing")
        db.execute(
            "UPDATE proxies SET last_checked_at=datetime('now'), last_success_at=datetime('now','-5 minutes'), "
            "next_check_at=datetime('now','+30 minutes') WHERE id=?",
            (fresh,),
        )
        db.execute(
            "UPDATE proxies SET last_checked_at=datetime('now'), last_success_at=datetime('now','-5 minutes'), "
            "next_check_at=datetime('now','-1 minute') WHERE id=?",
            (due,),
        )
        db.execute(
            "UPDATE proxies SET last_checked_at=datetime('now'), last_success_at=datetime('now','-4 hours'), "
            "next_check_at=datetime('now','+30 minutes') WHERE id=?",
            (stale,),
        )
        db.execute(
            "UPDATE proxies SET last_checked_at=datetime('now'), last_success_at=NULL, "
            "next_check_at=datetime('now','+30 minutes') WHERE id=?",
            (missing_success,),
        )
        db.commit()
    login_admin(client)

    fresh_page = client.get("/admin/proxies?freshness=fresh").get_data(as_text=True)
    due_page = client.get("/admin/proxies?freshness=due").get_data(as_text=True)
    stale_page = client.get("/admin/proxies?freshness=stale").get_data(as_text=True)

    assert "fresh-sqlite.example:9000" in fresh_page
    assert "due-sqlite.example:9001" not in fresh_page
    assert "due-sqlite.example:9001" in due_page
    assert "stale-sqlite.example:9002" in stale_page
    assert "missing-success.example:9003" in stale_page


def test_admin_proxy_inventory_uses_record_scope_for_archived_rows(app, client):
    _seed_admin_inventory(app)
    login_admin(client)

    page = client.get("/admin/proxies?archived=archived").get_data(as_text=True)
    status_select = page.split('id="admin-proxy-status"', 1)[1].split("</select>", 1)[0]

    assert "archived" not in ADMIN_PROXY_STATUSES
    assert 'value="archived"' not in status_select
    assert "archived.example:9003" in page
    assert "1 archived" in page
    assert "3 active" in page


def test_admin_proxy_inventory_marks_malformed_schedule_metadata_due(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "malformed-freshness@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "malformed-schedule.example:9000:user:pass")
        db.execute(
            "UPDATE proxies SET last_checked_at=datetime('now'), last_success_at=datetime('now'), "
            "next_check_at='not-a-timestamp' WHERE id=?",
            (proxy_id,),
        )
        db.commit()
    login_admin(client)

    due_page = client.get("/admin/proxies?freshness=due").get_data(as_text=True)
    fresh_page = client.get("/admin/proxies?freshness=fresh").get_data(as_text=True)

    assert "malformed-schedule.example:9000" in due_page
    assert "malformed-schedule.example:9000" not in fresh_page
    assert "Check due" in due_page


def test_admin_proxy_inventory_query_never_selects_secret_columns(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "query-owner@example.com", "password", status="active")
        add_proxy(db, user_id, "query-safe.example:9000:private-user:private-pass")
        db.commit()
        statements: list[str] = []
        db.set_trace_callback(statements.append)
        try:
            with app.test_request_context("/admin/proxies"):
                _admin_proxy_page(db, {})
        finally:
            db.set_trace_callback(None)

    inventory_queries = [statement for statement in statements if "JOIN users u" in statement]
    assert inventory_queries
    assert all("SELECT p.*" not in statement for statement in inventory_queries)
    assert all("username_encrypted" not in statement for statement in inventory_queries)
    assert all("password_encrypted" not in statement for statement in inventory_queries)
