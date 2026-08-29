from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.earnapp_probe import classify_verdict
from app.services.checks import (
    apply_earnapp_result,
    apply_health_result,
    checker_settings,
    claim_due_proxies,
)
from app.services.proxies import add_proxy
from app.services.users import create_user


def test_checker_defaults_to_sixty_minutes_and_concurrency_five(app):
    with app.app_context():
        settings = checker_settings(get_db())
    assert settings.health_interval_minutes == 60
    assert settings.health_concurrency == 5


def test_checker_concurrency_is_safely_capped_at_five(app):
    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='50' WHERE key='health_concurrency'")
        db.commit()
        settings = checker_settings(db)
    assert settings.health_concurrency == 5


def test_malformed_checker_setting_falls_back_to_safe_defaults(app):
    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='not-a-number' WHERE key='health_interval_minutes'")
        db.execute("UPDATE settings SET value='' WHERE key='health_concurrency'")
        db.commit()
        settings = checker_settings(db)
    assert settings.health_interval_minutes == 60
    assert settings.health_concurrency == 5


def test_health_claim_spreads_next_check_by_configured_interval(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=? WHERE id=?",
            ((now - timedelta(minutes=1)).isoformat(), proxy_id),
        )
        db.commit()
        claimed = claim_due_proxies(db, now=now, limit=5)
        row = db.execute("SELECT next_check_at FROM proxies WHERE id = ?", (proxy_id,)).fetchone()

    assert [item["id"] for item in claimed] == [proxy_id]
    assert datetime.fromisoformat(row["next_check_at"]) == now + timedelta(minutes=60)


def test_expired_claim_token_cannot_apply_a_late_health_result(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "claim-token@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "claim-token.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=? WHERE id=?",
            ((now - timedelta(minutes=1)).isoformat(), proxy_id),
        )
        db.commit()
        first = claim_due_proxies(db, now=now, limit=1)[0]
        db.execute(
            "UPDATE proxies SET check_claimed_until=? WHERE id=?",
            ((now - timedelta(minutes=1)).isoformat(), proxy_id),
        )
        db.commit()
        second = claim_due_proxies(db, now=now + timedelta(minutes=1), limit=1)[0]
        apply_health_result(
            db,
            proxy_id,
            {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.70",
                "_credential_generation": first["credential_generation"],
                "_check_claim_token": first["check_claim_token"],
            },
            now=now + timedelta(minutes=2),
        )
        row = db.execute(
            "SELECT status, check_claim_token FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["status"] == "pending"
    assert row["check_claim_token"] == second["check_claim_token"]


def test_transient_or_single_failure_does_not_mark_proxy_offline(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.4"},
            now=now,
        )
        apply_health_result(
            db,
            proxy_id,
            {"status": "inconclusive", "error": "probe timeout"},
            now=now + timedelta(hours=1),
        )
        apply_health_result(
            db,
            proxy_id,
            {"status": "dead", "error": "connection refused"},
            now=now + timedelta(hours=2),
        )
        row = db.execute("SELECT status, consecutive_failures FROM proxies WHERE id = ?", (proxy_id,)).fetchone()

    assert row["status"] == "online"
    assert row["consecutive_failures"] == 1


def test_three_confirmed_failures_mark_proxy_offline(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "http", "exit_ip": "198.51.100.4"},
            now=now,
        )
        for offset in (1, 2, 3):
            apply_health_result(
                db,
                proxy_id,
                {"status": "dead", "error": "connection refused"},
                now=now + timedelta(hours=offset),
            )
        row = db.execute("SELECT status, offline_since FROM proxies WHERE id = ?", (proxy_id,)).fetchone()

    assert row["status"] == "offline"
    assert row["offline_since"] is not None


def test_offline_transition_records_final_online_earning_interval(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "offline-accrual@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            """
            UPDATE proxies SET status='online', eligibility='allow', country_code='US',
                online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?
            """,
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        for offset in (1, 2, 3):
            apply_health_result(
                db,
                proxy_id,
                {"status": "dead", "error": "connection refused"},
                now=start + timedelta(hours=offset),
            )
        total = db.execute(
            "SELECT COALESCE(SUM(micro_usd), 0) AS total FROM earnings_ledger WHERE proxy_id=?",
            (proxy_id,),
        ).fetchone()["total"]
    assert total > 0


def test_earnapp_verdict_mapping_is_conservative():
    assert classify_verdict("CID_SET") == "allow"
    assert classify_verdict("BLACKLIST") == "risk"
    assert classify_verdict("DECLINE", "ip_quality.vpn") == "risk"
    assert classify_verdict("TIMEOUT") == "pending"
    assert classify_verdict("WSS_FAIL") == "pending"


def test_check_batch_is_spread_across_hour_for_large_inventory(app):
    from app.services.checks import batch_spacing_seconds

    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='60' WHERE key='health_interval_minutes'")
        db.execute("UPDATE settings SET value='5' WHERE key='health_concurrency'")
        db.commit()
        spacing = batch_spacing_seconds(db, due_count=30_000)
    assert spacing >= 0.5
    assert spacing <= 1.0


def test_earnapp_qualification_is_not_due_on_every_hourly_health_sweep(app):
    from app.services.checks import apply_earnapp_result, claim_due_earnapp

    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', earnapp_next_check_at=? WHERE id=?",
            (now.isoformat(), proxy_id),
        )
        db.commit()
        due = claim_due_earnapp(db, now=now, limit=5)
        apply_earnapp_result(db, proxy_id, {"verdict": "CID_SET", "reason": "cid"}, now=now)
        row = db.execute(
            "SELECT earnapp_next_check_at, eligibility FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert [item["id"] for item in due] == [proxy_id]
    assert row["eligibility"] == "allow"
    assert datetime.fromisoformat(row["earnapp_next_check_at"]) >= now + timedelta(hours=168)


def test_egress_change_schedules_new_earnapp_qualification(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.1', eligibility='allow', earnapp_next_check_at=? WHERE id=?",
            ((now + timedelta(days=7)).isoformat(), proxy_id),
        )
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.2"},
            now=now,
        )
        row = db.execute(
            "SELECT eligibility, earnapp_next_check_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
    assert row["eligibility"] == "pending"
    assert datetime.fromisoformat(row["earnapp_next_check_at"]) <= now


def test_egress_change_expires_pending_balance_from_previous_cycle(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "egress-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.1', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=24)).isoformat(),
                (now - timedelta(hours=24)).isoformat(),
                (now - timedelta(hours=24)).isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue = __import__("app.services.earnings", fromlist=["accrue_eligible_time"]).accrue_eligible_time
        accrue(db, now=now)
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.2"},
            now=now,
        )
        buckets = {
            row["bucket"]: int(row["total"])
            for row in db.execute(
                "SELECT bucket, COALESCE(SUM(micro_usd),0) AS total FROM earnings_ledger WHERE proxy_id=? GROUP BY bucket",
                (proxy_id,),
            ).fetchall()
        }
    assert buckets.get("pending", 0) == 0
    assert buckets.get("expired", 0) > 0


def test_eligibility_loss_expires_pending_cycle_and_restarts_probation(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "eligibility-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        accrue = __import__("app.services.earnings", fromlist=["accrue_eligible_time"]).accrue_eligible_time
        accrue(db, now=start + timedelta(hours=24))
        apply_earnapp_result(
            db,
            proxy_id,
            {"verdict": "BLACKLIST", "reason": "blocked"},
            now=start + timedelta(hours=25),
        )
        row = db.execute(
            "SELECT eligibility, probation_started_at, accrual_cursor_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
        pending = db.execute(
            "SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=? AND bucket='pending'",
            (proxy_id,),
        ).fetchone()["count"]
    assert row["eligibility"] == "risk"
    assert row["probation_started_at"] == (start + timedelta(hours=25)).isoformat()
    assert row["accrual_cursor_at"] == (start + timedelta(hours=25)).isoformat()
    assert pending == 0


def test_pending_cycle_unlocks_when_a_later_accrual_starts_at_boundary(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "boundary@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        boundary = start + timedelta(hours=168)
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        accrue = __import__("app.services.earnings", fromlist=["accrue_eligible_time"]).accrue_eligible_time
        accrue(db, now=boundary)
        accrue(db, now=boundary + timedelta(hours=1))
        pending = db.execute(
            "SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=? AND bucket='pending'",
            (proxy_id,),
        ).fetchone()["count"]
    assert pending == 0


def test_repeated_health_observations_do_not_refresh_egress_verification_time(app):
    first = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    second = first + timedelta(hours=1)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "timestamp@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.10"},
            now=first,
        )
        initial = db.execute("SELECT egress_verified_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()[
            "egress_verified_at"
        ]
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.10"},
            now=second,
        )
        final = db.execute("SELECT egress_verified_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()[
            "egress_verified_at"
        ]
    assert final == initial


def test_confirmed_offline_transition_expires_old_pending_probation_cycle(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "offline-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()
        accrue = __import__("app.services.earnings", fromlist=["accrue_eligible_time"]).accrue_eligible_time
        accrue(db, now=start + timedelta(hours=24))
        for hour in (25, 26, 27):
            apply_health_result(db, proxy_id, {"status": "dead"}, now=start + timedelta(hours=hour))
        row = db.execute(
            "SELECT status, probation_started_at, accrual_cursor_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()
        pending = db.execute(
            "SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=? AND bucket='pending'",
            (proxy_id,),
        ).fetchone()["count"]
    assert row["status"] == "offline"
    assert row["probation_started_at"] != start.isoformat()
    assert row["accrual_cursor_at"]
    assert pending == 0
