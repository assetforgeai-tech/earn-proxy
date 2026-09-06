from __future__ import annotations

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
