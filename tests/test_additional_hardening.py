from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.proxy_parser import ProxyParseError, parse_proxy
from app.services.checks import (
    apply_earnapp_result,
    apply_health_result,
    archive_due_dead_proxies,
    claim_due_earnapp,
    claim_due_proxies,
)
from app.services.earnings import accrue_eligible_time, balances_for_user
from app.services.proxies import add_proxy, replace_proxy
from app.services.users import create_user


def test_stale_health_claim_can_be_reclaimed_even_if_next_check_was_reserved(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=?, check_claimed_until=? WHERE id=?",
            (
                (now + timedelta(minutes=60)).isoformat(),
                (now - timedelta(minutes=1)).isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        claimed = claim_due_proxies(db, now=now, limit=5)
    assert [row["id"] for row in claimed] == [proxy_id]


def test_earnapp_claim_ignores_an_active_claim(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', earnapp_next_check_at=?, earnapp_claimed_until=? WHERE id=?",
            (now.isoformat(), (now + timedelta(minutes=10)).isoformat(), proxy_id),
        )
        db.commit()
        assert claim_due_earnapp(db, now=now, limit=5) == []


def test_allow_verdict_starts_a_new_earning_probation_at_verdict_time(app):
    first = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    verdict_time = first + timedelta(hours=4)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='pending', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (first.isoformat(), first.isoformat(), first.isoformat(), proxy_id),
        )
        db.commit()
        apply_earnapp_result(db, proxy_id, {"verdict": "CID_SET", "reason": "cid"}, now=verdict_time)
        row = db.execute(
            "SELECT probation_started_at, accrual_cursor_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["probation_started_at"] == verdict_time.isoformat()
    assert row["accrual_cursor_at"] == verdict_time.isoformat()


@pytest.mark.parametrize(
    "raw",
    [
        "http://proxy.example:not-a-port",
        "proxy.example:8080:user:pass\nX-Injected: yes",
        "proxy.example:8080:user:\r\nheader",
    ],
)
def test_proxy_parser_rejects_malformed_or_control_character_credentials(raw):
    with pytest.raises(ProxyParseError):
        parse_proxy(raw)


def test_proxy_parser_rejects_oversized_fields_before_encryption():
    with pytest.raises(ProxyParseError):
        parse_proxy("proxy.example:8080:" + ("u" * 513) + ":password")
    with pytest.raises(ProxyParseError):
        parse_proxy("proxy.example:8080:user:" + ("p" * 2049))


def test_non_allow_period_is_not_backfilled_when_proxy_later_becomes_allow(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    allow_time = start + timedelta(hours=20)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='risk', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        apply_earnapp_result(db, proxy_id, {"verdict": "CID_SET"}, now=allow_time)
        accrue_eligible_time(db, now=allow_time + timedelta(hours=1))
        balance = balances_for_user(db, user_id)
    assert balance.pending_micro_usd > 0
    assert balance.pending_micro_usd < 10_000


def test_blocked_health_result_is_risk_and_not_operational(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        apply_health_result(db, proxy_id, {"status": "blocked", "error": "captive portal"}, now=now)
        row = db.execute(
            "SELECT status, eligibility, check_claimed_until FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["status"] == "blocked"
    assert row["eligibility"] == "risk"
    assert row["check_claimed_until"] is None


def test_stale_health_result_cannot_mark_replaced_proxy_online(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-health@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:old")
        generation = db.execute(
            "SELECT credential_generation FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()["credential_generation"]
        replace_proxy(db, proxy_id, user_id, "new.example:9001:u:new", now=now)

        apply_health_result(
            db,
            proxy_id,
            {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.20",
                "_credential_generation": generation,
            },
            now=now + timedelta(seconds=1),
        )
        row = db.execute(
            "SELECT host, status, detected_protocol, exit_ip FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["host"] == "new.example"
    assert row["status"] == "pending"
    assert row["detected_protocol"] == "unknown"
    assert row["exit_ip"] is None


def test_stale_earnapp_result_cannot_allow_replaced_proxy(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-earnapp@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:old")
        generation = db.execute(
            "SELECT credential_generation FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()["credential_generation"]
        replace_proxy(db, proxy_id, user_id, "new.example:9001:u:new", now=now)

        apply_earnapp_result(
            db,
            proxy_id,
            {
                "verdict": "CID_SET",
                "reason": "stale-cid",
                "_credential_generation": generation,
            },
            now=now + timedelta(seconds=1),
        )
        row = db.execute(
            "SELECT host, eligibility, earnapp_verdict FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["host"] == "new.example"
    assert row["eligibility"] == "pending"
    assert row["earnapp_verdict"] == ""


def test_archiving_dead_canonical_promotes_online_duplicate(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "canonical-promotion@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical.example:9000:u:canonical")
        duplicate = add_proxy(db, user_id, "duplicate.example:9001:u:duplicate")
        dead_since = now - timedelta(hours=25)
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.90', status='offline', offline_since=?, "
            "continuous_dead_since=? WHERE id=?",
            (dead_since.isoformat(), dead_since.isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.90', status='online', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()
        archive_due_dead_proxies(db, now=now)
        rows = db.execute(
            "SELECT id, status, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (canonical, duplicate),
        ).fetchall()
    assert rows[0]["status"] == "archived"
    assert rows[1]["status"] == "online"
    assert rows[1]["duplicate_of"] is None


def test_already_archived_canonical_can_rehome_online_duplicate(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "archived-canonical@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "archived.example:9000:u:canonical")
        duplicate = add_proxy(db, user_id, "archived-duplicate.example:9001:u:duplicate")
        dead_since = now - timedelta(hours=25)
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.91', status='archived', archived_at=?, offline_since=? WHERE id=?",
            (now.isoformat(), dead_since.isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.91', status='online', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()
        from app.services.proxies import promote_duplicate_if_due

        assert promote_duplicate_if_due(db, canonical, now=now) == duplicate
        row = db.execute("SELECT duplicate_of FROM proxies WHERE id=?", (duplicate,)).fetchone()
    assert row["duplicate_of"] is None


def test_replace_canonical_rehomes_online_duplicate(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replace-canonical@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "replace-canonical.example:9000:u:canonical")
        duplicate = add_proxy(db, user_id, "replace-duplicate.example:9001:u:duplicate")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.92', status='online' WHERE id=?",
            (canonical,),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.92', status='online', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()

        replace_proxy(db, canonical, user_id, "new-canonical.example:9010:u:new", now=now)
        row = db.execute("SELECT duplicate_of FROM proxies WHERE id=?", (duplicate,)).fetchone()
    assert row["duplicate_of"] is None
