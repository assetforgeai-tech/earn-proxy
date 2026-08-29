from __future__ import annotations

import pytest

from app.db import get_db
from app.proxy_parser import ProxyParseError, parse_proxy
from app.services.proxies import (
    DuplicateCredential,
    add_proxy,
    reconcile_exit_ip,
    reveal_proxy,
)
from app.services.users import create_user


@pytest.mark.parametrize(
    ("raw", "protocol", "host", "port", "username", "password"),
    [
        (
            "dc.example.com:44198:user:pass:with:colon",
            "auto",
            "dc.example.com",
            44198,
            "user",
            "pass:with:colon",
        ),
        ("user:pass@10.1.2.3:1080", "auto", "10.1.2.3", 1080, "user", "pass"),
        (
            "socks5://user:pass@proxy.example:1080",
            "socks5",
            "proxy.example",
            1080,
            "user",
            "pass",
        ),
        ("http://proxy.example:8080", "http", "proxy.example", 8080, "", ""),
    ],
)
def test_proxy_parser_supports_common_formats(raw, protocol, host, port, username, password):
    parsed = parse_proxy(raw)
    assert (
        parsed.protocol,
        parsed.host,
        parsed.port,
        parsed.username,
        parsed.password,
    ) == (
        protocol,
        host,
        port,
        username,
        password,
    )


def test_proxy_parser_rejects_invalid_input():
    with pytest.raises(ProxyParseError):
        parse_proxy("not-a-proxy")


def test_proxy_credentials_are_encrypted_and_duplicate_is_global(app):
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "one@example.com", "password", status="active")
        second_user = create_user(db, "two@example.com", "password", status="active")

        proxy_id = add_proxy(db, first_user, "proxy.example:9000:alice:very-secret")
        stored = db.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
        assert "alice" not in stored["username_encrypted"]
        assert "very-secret" not in stored["password_encrypted"]
        assert reveal_proxy(stored).raw == "proxy.example:9000:alice:very-secret"

        with pytest.raises(DuplicateCredential):
            add_proxy(db, second_user, "proxy.example:9000:alice:very-secret")


def test_duplicate_fingerprint_cannot_be_bypassed_by_changing_protocol_hint(app):
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "one@example.com", "password", status="active")
        second_user = create_user(db, "two@example.com", "password", status="active")
        add_proxy(db, first_user, "http://alice:secret@proxy.example:9000")
        with pytest.raises(DuplicateCredential):
            add_proxy(db, second_user, "socks5://alice:secret@proxy.example:9000")


def test_earliest_verified_egress_is_canonical_globally(app):
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "one@example.com", "password", status="active")
        second_user = create_user(db, "two@example.com", "password", status="active")
        first = add_proxy(db, first_user, "p1.example:9001:u:p")
        second = add_proxy(db, second_user, "p2.example:9002:u:p")

        reconcile_exit_ip(db, first, "203.0.113.9")
        reconcile_exit_ip(db, second, "203.0.113.9")

        first_row = db.execute("SELECT * FROM proxies WHERE id = ?", (first,)).fetchone()
        second_row = db.execute("SELECT * FROM proxies WHERE id = ?", (second,)).fetchone()
        assert first_row["duplicate_of"] is None
        assert second_row["duplicate_of"] == first


def test_recently_offline_canonical_is_not_replaced_before_24_hours(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        first = add_proxy(db, user_id, "p1.example:9001:u:p")
        second = add_proxy(db, user_id, "p2.example:9002:u:p")
        reconcile_exit_ip(db, first, "203.0.113.10")
        db.execute(
            "UPDATE proxies SET status='offline', offline_since=datetime('now','-1 hour') WHERE id=?",
            (first,),
        )
        db.commit()
        reconcile_exit_ip(db, second, "203.0.113.10")
        rows = db.execute(
            "SELECT id, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (first, second),
        ).fetchall()
    assert rows[0]["duplicate_of"] is None
    assert rows[1]["duplicate_of"] == first


def test_proxy_changing_egress_is_removed_from_the_old_duplicate_group(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "move@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical.example:9001:u:p")
        moving = add_proxy(db, user_id, "moving.example:9002:u:p")
        replacement = add_proxy(db, user_id, "replacement.example:9003:u:p")
        reconcile_exit_ip(db, canonical, "198.51.100.1")
        reconcile_exit_ip(db, moving, "198.51.100.1")
        reconcile_exit_ip(db, replacement, "198.51.100.2")
        db.execute(
            "UPDATE proxies SET status='online', duplicate_of=? WHERE id=?",
            (canonical, moving),
        )
        db.commit()
        reconcile_exit_ip(db, moving, "198.51.100.2")
        rows = db.execute(
            "SELECT id, exit_ip, duplicate_of FROM proxies WHERE id IN (?,?,?) ORDER BY id",
            (canonical, moving, replacement),
        ).fetchall()
    values = {row["id"]: row for row in rows}
    assert values[moving]["exit_ip"] == "198.51.100.2"
    assert values[moving]["duplicate_of"] == replacement


def test_canonical_egress_change_rehomes_old_duplicates(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "move-canonical@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical.example:9001:u:p")
        old_duplicate = add_proxy(db, user_id, "old-duplicate.example:9002:u:p")
        new_canonical = add_proxy(db, user_id, "new-canonical.example:9003:u:p")
        reconcile_exit_ip(db, canonical, "198.51.100.3")
        reconcile_exit_ip(db, old_duplicate, "198.51.100.3")
        reconcile_exit_ip(db, new_canonical, "198.51.100.4")
        db.execute(
            "UPDATE proxies SET status='online', duplicate_of=? WHERE id=?",
            (canonical, old_duplicate),
        )
        db.commit()
        reconcile_exit_ip(db, canonical, "198.51.100.4")
        rows = db.execute(
            "SELECT id, exit_ip, duplicate_of FROM proxies WHERE id IN (?,?,?) ORDER BY id",
            (canonical, old_duplicate, new_canonical),
        ).fetchall()
    values = {row["id"]: row for row in rows}
    assert values[canonical]["exit_ip"] == "198.51.100.4"
    assert values[old_duplicate]["exit_ip"] == "198.51.100.3"
    assert values[old_duplicate]["duplicate_of"] is None


def test_user_dashboard_masks_credentials(app, client):
    from conftest import login, login_admin, register

    register(client)
    login_admin(client)
    with app.app_context():
        db = get_db()
        user_id = db.execute("SELECT id FROM users WHERE email = ?", ("member@example.com",)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client)
    client.post("/proxies", data={"raw_proxy": "edge.example:9000:private-user:private-pass"})

    page = client.get("/dashboard").get_data(as_text=True)
    assert "edge.example:9000" in page
    assert "private-user" not in page
    assert "private-pass" not in page
