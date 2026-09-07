from __future__ import annotations

from conftest import login, login_admin, register

from app.db import get_db
from app.services.proxies import add_proxy, reconcile_exit_ip
from app.services.users import create_user


def test_admin_egress_duplicate_groups_are_global_and_credential_safe(app, client):
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "egress-first@example.com", "password", status="active")
        second_user = create_user(db, "egress-second@example.com", "password", status="active")
        first = add_proxy(db, first_user, "admin-a.example:9000:secret-user-a:secret-pass-a")
        second = add_proxy(db, second_user, "admin-b.example:9001:secret-user-b:secret-pass-b")
        add_proxy(db, second_user, "admin-unique.example:9002:secret-user-c:secret-pass-c")
        reconcile_exit_ip(db, first, "198.51.100.20")
        reconcile_exit_ip(db, second, "198.51.100.20", attestation_source="earnapp_tls")

    login_admin(client)
    response = client.get("/admin/egress-duplicates")

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "Duplicate egress groups" in page
    assert "198.51.100.20" in page
    assert "admin-a.example:9000" in page
    assert "admin-b.example:9001" not in page
    assert "2 proxies" in page
    assert "2 accounts" in page
    assert "secret-user-a" not in page
    assert "secret-pass-a" not in page
    assert "secret-user-b" not in page
    assert "secret-pass-b" not in page
    assert "admin-unique.example" not in page
    assert 'data-nav="egress_duplicates" aria-current="page"' in page

    detail = client.get("/admin/egress-duplicates/198.51.100.20")
    assert detail.status_code == 200
    detail_page = detail.get_data(as_text=True)
    assert "admin-a.example:9000" in detail_page
    assert "admin-b.example:9001" in detail_page
    assert "secret-user-a" not in detail_page
    assert "secret-pass-a" not in detail_page


def test_admin_egress_duplicate_groups_support_search_and_pagination(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "egress-pages@example.com", "password", status="active")
        for index in range(26):
            first = add_proxy(db, user_id, f"group-{index:02d}-a.example:9000:u-{index}-a:p-{index}-a")
            second = add_proxy(db, user_id, f"group-{index:02d}-b.example:9001:u-{index}-b:p-{index}-b")
            exit_ip = f"198.51.100.{index + 30}"
            reconcile_exit_ip(db, first, exit_ip)
            reconcile_exit_ip(db, second, exit_ip)

    login_admin(client)
    second_page = client.get("/admin/egress-duplicates?per_page=25&page=2").get_data(as_text=True)
    filtered = client.get("/admin/egress-duplicates?q=198.51.100.42").get_data(as_text=True)

    assert "26 groups" in second_page
    assert "Showing 26–26 of 26" in second_page
    assert "198.51.100.42" in filtered
    assert "Showing 1–1 of 1" in filtered
    assert 'name="q"' in filtered
    assert 'name="per_page"' in filtered


def test_egress_duplicate_workspace_is_admin_only(app, client):
    register(client, "egress-user@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='egress-user@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, "egress-user@example.com", "member-password")

    assert client.get("/admin/egress-duplicates").status_code == 403
    assert client.get("/admin/egress-duplicates/198.51.100.20").status_code == 403


def test_admin_egress_duplicate_members_are_paginated(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "egress-members@example.com", "password", status="active")
        for index in range(26):
            proxy_id = add_proxy(db, user_id, f"member-{index:02d}.example:9000:u-{index}:p-{index}")
            reconcile_exit_ip(db, proxy_id, "198.51.100.200")

    login_admin(client)
    page = client.get("/admin/egress-duplicates/198.51.100.200?per_page=25&page=2").get_data(as_text=True)

    assert "Showing 26–26 of 26 proxies" in page
    assert "member-25.example:9000" in page
    assert "member-00.example:9000" not in page
    assert 'name="per_page"' in page
