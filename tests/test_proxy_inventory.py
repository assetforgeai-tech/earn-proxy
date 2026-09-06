from __future__ import annotations

import pytest

from app.db import get_db
from app.proxy_parser import ProxyParseError, parse_proxy
from app.services.proxies import (
    DuplicateCredential,
    add_proxy,
    bulk_add_proxies,
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
        ("user:pass@8.8.8.8:1080", "auto", "8.8.8.8", 1080, "user", "pass"),
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


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1:8080",
        "127.1:8080",
        "10.1.2.3:1080",
        "169.254.169.254:80",
        "2130706433:8080",
        "0x7f000001:8080",
        "017700000001:8080",
        "localhost:8080",
    ],
)
def test_proxy_parser_rejects_local_or_noncanonical_network_targets(raw):
    with pytest.raises(ProxyParseError):
        parse_proxy(raw)


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


def test_bulk_proxy_import_adds_multiline_input_and_ignores_blank_lines(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bulk@example.com", "password", status="active")

        result = bulk_add_proxies(
            db,
            user_id,
            """
            socks5://alice:first-secret@one.example:1080

            two.example:8080:bob:second-secret
            carol:third-secret@three.example:9000
            """,
            max_active_proxies=10,
        )
        rows = db.execute(
            "SELECT host,port,protocol_hint,status FROM proxies WHERE user_id=? ORDER BY id",
            (user_id,),
        ).fetchall()

    assert result.submitted == 3
    assert result.added == 3
    assert result.ignored_blank == 3
    assert result.duplicates == 0
    assert result.invalid == 0
    assert result.quota_skipped == 0
    assert [tuple(row) for row in rows] == [
        ("one.example", 1080, "socks5", "pending"),
        ("two.example", 8080, "auto", "pending"),
        ("three.example", 9000, "auto", "pending"),
    ]


def test_bulk_proxy_import_reports_global_and_within_batch_duplicates_without_secrets(app):
    with app.app_context():
        db = get_db()
        first_user = create_user(db, "bulk-first@example.com", "password", status="active")
        second_user = create_user(db, "bulk-second@example.com", "password", status="active")
        add_proxy(db, first_user, "existing.example:9000:alice:existing-secret")

        result = bulk_add_proxies(
            db,
            second_user,
            "\n".join(
                [
                    "existing.example:9000:alice:existing-secret",
                    "new.example:9001:bob:new-secret",
                    "http://bob:new-secret@new.example:9001",
                    "not-a-proxy:private-secret",
                ]
            ),
            max_active_proxies=10,
        )

    assert result.added == 1
    assert result.duplicates == 2
    assert result.invalid == 1
    assert [issue.line for issue in result.issues] == [1, 3, 4]
    serialized = str(result.as_dict())
    assert "existing-secret" not in serialized
    assert "new-secret" not in serialized
    assert "private-secret" not in serialized


def test_bulk_proxy_import_reports_malformed_urls_as_invalid_lines(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bulk-malformed@example.com", "password", status="active")

        result = bulk_add_proxies(
            db,
            user_id,
            "http://[broken.example:9000:user:secret",
            max_active_proxies=10,
        )

    assert result.added == 0
    assert result.invalid == 1
    assert result.issues[0].line == 1
    assert "secret" not in str(result.as_dict())


def test_bulk_proxy_import_partially_fills_remaining_quota_in_input_order(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bulk-quota@example.com", "password", status="active")
        add_proxy(db, user_id, "first.example:8000:u:first")

        result = bulk_add_proxies(
            db,
            user_id,
            "second.example:8001:u:second\nthird.example:8002:u:third",
            max_active_proxies=2,
        )
        hosts = [
            row["host"]
            for row in db.execute(
                "SELECT host FROM proxies WHERE user_id=? AND archived_at IS NULL ORDER BY id",
                (user_id,),
            ).fetchall()
        ]

    assert result.added == 1
    assert result.quota_skipped == 1
    assert result.issues[-1].category == "quota"
    assert hosts == ["first.example", "second.example"]


def test_bulk_proxy_import_bounds_safe_issue_details(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bulk-issue-limit@example.com", "password", status="active")
        result = bulk_add_proxies(
            db,
            user_id,
            ["not-a-proxy"] * 125,
            max_active_proxies=200,
            max_lines=200,
        )

    assert result.invalid == 125
    assert len(result.issues) == 100
    assert result.issues_truncated == 25
    assert result.as_dict()["issues_truncated"] == 25


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


def test_reconcile_exit_ip_clears_country_metadata_when_egress_changes(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "country-reset@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "country-reset.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.1', country_code='US' WHERE id=?",
            (proxy_id,),
        )
        db.commit()

        reconcile_exit_ip(db, proxy_id, "198.51.100.2")
        row = db.execute("SELECT exit_ip, country_code FROM proxies WHERE id=?", (proxy_id,)).fetchone()

    assert row["exit_ip"] == "198.51.100.2"
    assert row["country_code"] == ""


def test_unattested_legacy_exit_cannot_become_canonical_for_a_trusted_group(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "attested-canonical@example.com", "password", status="active")
        legacy = add_proxy(db, user_id, "legacy-canonical.example:9000:u:p")
        trusted = add_proxy(db, user_id, "trusted-canonical.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.25', egress_verified_at='2026-01-01T00:00:00+00:00' WHERE id=?",
            (legacy,),
        )
        db.commit()

        reconcile_exit_ip(db, trusted, "198.51.100.25", attestation_source="https_quorum")
        rows = db.execute(
            "SELECT id, duplicate_of, egress_attestation_source FROM proxies WHERE id IN (?,?) ORDER BY id",
            (legacy, trusted),
        ).fetchall()

    assert rows[0]["egress_attestation_source"] == ""
    assert rows[0]["duplicate_of"] is None
    assert rows[1]["egress_attestation_source"] == "https_quorum"
    assert rows[1]["duplicate_of"] is None


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

    page = client.get("/dashboard/proxies").get_data(as_text=True)
    assert "edge.example:9000" in page
    assert "private-user" not in page
    assert "private-pass" not in page
