from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.earnapp_probe import classify_verdict
from app.services.checks import (
    apply_earnapp_result,
    apply_health_result,
    checker_settings,
    claim_due_earnapp,
    claim_due_proxies,
)
from app.services.proxies import add_proxy
from app.services.users import create_user


def test_checker_defaults_to_optimized_health_policy(app):
    with app.app_context():
        settings = checker_settings(get_db())
    assert settings.health_interval_minutes == 60
    assert settings.health_concurrency == 5
    assert settings.health_per_host_concurrency == 2
    assert settings.health_retry_first_minutes == 5
    assert settings.health_retry_second_minutes == 15
    assert settings.health_stale_minutes == 120


def test_checker_concurrency_and_per_host_limit_are_safely_capped(app):
    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='50' WHERE key='health_concurrency'")
        db.execute("UPDATE settings SET value='50' WHERE key='health_per_host_concurrency'")
        db.commit()
        settings = checker_settings(db)
    assert settings.health_concurrency == 20
    assert settings.health_per_host_concurrency == 3


def test_malformed_checker_setting_falls_back_to_safe_defaults(app):
    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='not-a-number' WHERE key='health_interval_minutes'")
        db.execute("UPDATE settings SET value='' WHERE key='health_concurrency'")
        db.execute("UPDATE settings SET value='bad' WHERE key='health_stale_minutes'")
        db.commit()
        settings = checker_settings(db)
    assert settings.health_interval_minutes == 60
    assert settings.health_concurrency == 5
    assert settings.health_stale_minutes == 120


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


def test_health_claim_orders_hosts_fairly_without_shrinking_the_global_batch(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "host-fairness@example.com", "password", status="active")
        ids = []
        for index, host in enumerate(["same.example", "same.example", "same.example", "same.example", "other.example"]):
            proxy_id = add_proxy(db, user_id, f"{host}:90{index}:u:p")
            ids.append(proxy_id)
            db.execute(
                "UPDATE proxies SET next_check_at=? WHERE id=?", ((now - timedelta(minutes=1)).isoformat(), proxy_id)
            )
        db.commit()
        claimed = claim_due_proxies(db, now=now, limit=5, per_host_limit=2)

    assert len(claimed) == 5
    assert {row["host"] for row in claimed} == {"same.example", "other.example"}
    assert sum(row["host"] == "same.example" for row in claimed) == 4


def test_claimers_skip_non_active_users_but_keep_paused_active_users(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        active = create_user(db, "claim-active@example.com", "password", status="active")
        blocked = create_user(db, "claim-blocked@example.com", "password", status="blocked")
        paused = create_user(db, "claim-paused@example.com", "password", status="active")
        active_id = add_proxy(db, active, "claim-active.example:9000:u:a")
        blocked_id = add_proxy(db, blocked, "claim-blocked.example:9001:u:b")
        paused_id = add_proxy(db, paused, "claim-paused.example:9002:u:c")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (paused,))
        db.execute(
            "UPDATE proxies SET status='online', next_check_at=?, earnapp_next_check_at=? WHERE id IN (?,?,?)",
            (now.isoformat(), now.isoformat(), active_id, blocked_id, paused_id),
        )
        db.commit()

        health = claim_due_proxies(db, now=now, limit=10)
        earnapp = claim_due_earnapp(db, now=now, limit=10)

    # ``Pause earn`` only pauses accrual review; it must not stop health,
    # qualification, or distribution for an otherwise active account.
    assert [row["id"] for row in health] == [active_id, paused_id]
    assert [row["id"] for row in earnapp] == [active_id, paused_id]


def test_health_claim_fairness_scans_beyond_a_large_first_host_run(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "host-starvation@example.com", "password", status="active")
        for index in range(20):
            proxy_id = add_proxy(db, user_id, f"same.example:91{index:02d}:u:p")
            db.execute(
                "UPDATE proxies SET next_check_at=? WHERE id=?",
                ((now - timedelta(minutes=1)).isoformat(), proxy_id),
            )
        for index, host in enumerate(("other.example", "third.example", "fourth.example")):
            other_id = add_proxy(db, user_id, f"{host}:92{index}0:u:p")
            db.execute(
                "UPDATE proxies SET next_check_at=? WHERE id=?",
                ((now - timedelta(minutes=1)).isoformat(), other_id),
            )
        db.commit()
        claimed = claim_due_proxies(db, now=now, limit=5, per_host_limit=2)

    assert len(claimed) == 5
    assert sum(row["host"] == "same.example" for row in claimed) == 2
    assert {row["host"] for row in claimed} == {
        "same.example",
        "other.example",
        "third.example",
        "fourth.example",
    }


def test_first_and_second_confirmed_failures_use_short_retry_windows(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "retry@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "retry.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', health_mode='fast', last_success_at=?, next_check_at=? WHERE id=?",
            ((now - timedelta(minutes=30)).isoformat(), now.isoformat(), proxy_id),
        )
        db.commit()

        apply_health_result(db, proxy_id, {"status": "dead", "failure_kind": "proxy"}, now=now)
        first = db.execute(
            "SELECT status, health_mode, consecutive_failures, next_check_at FROM proxies WHERE id=?", (proxy_id,)
        ).fetchone()
        apply_health_result(
            db,
            proxy_id,
            {"status": "dead", "failure_kind": "proxy"},
            now=now + timedelta(minutes=5),
        )
        second = db.execute(
            "SELECT status, health_mode, consecutive_failures, next_check_at FROM proxies WHERE id=?", (proxy_id,)
        ).fetchone()

    assert first["status"] == "online"
    assert first["health_mode"] == "strong"
    assert first["consecutive_failures"] == 1
    assert datetime.fromisoformat(first["next_check_at"]) == now + timedelta(minutes=5)
    assert second["status"] == "suspect"
    assert second["consecutive_failures"] == 2
    assert datetime.fromisoformat(second["next_check_at"]) == now + timedelta(minutes=20)


def test_third_confirmed_failure_marks_proxy_offline_and_success_recovers(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "recover@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "recover.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='suspect', health_mode='strong', consecutive_failures=2, online_since=?, last_success_at=? WHERE id=?",
            ((now - timedelta(hours=3)).isoformat(), (now - timedelta(minutes=30)).isoformat(), proxy_id),
        )
        db.commit()
        apply_health_result(db, proxy_id, {"status": "dead", "failure_kind": "proxy"}, now=now)
        offline = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        apply_health_result(
            db,
            proxy_id,
            {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.25",
                "latency_ms": 220,
                "probe_endpoint": "https://icanhazip.com",
                "next_probe_index": 2,
            },
            now=now + timedelta(minutes=2),
        )
        recovered = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()

    assert offline["status"] == "offline"
    assert recovered["status"] == "online"
    assert recovered["health_mode"] == "fast"
    assert recovered["consecutive_failures"] == 0
    assert recovered["last_success_at"] == (now + timedelta(minutes=2)).isoformat()
    assert recovered["last_latency_ms"] == 220
    assert recovered["last_probe_endpoint"] == "https://icanhazip.com"
    assert recovered["next_probe_index"] == 2


def test_probe_endpoint_failure_does_not_penalize_proxy_and_rotates_probe(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "endpoint@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "endpoint.example:9000:u:p")
        db.execute("UPDATE proxies SET status='online', consecutive_failures=1 WHERE id=?", (proxy_id,))
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {
                "status": "inconclusive",
                "failure_kind": "probe_endpoint",
                "probe_endpoint": "https://ifconfig.me/ip",
                "next_probe_index": 1,
            },
            now=now,
        )
        row = db.execute(
            "SELECT status, consecutive_failures, next_check_at, next_probe_index, failure_kind FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["status"] == "online"
    assert row["consecutive_failures"] == 1
    assert row["next_probe_index"] == 1


def test_fast_probe_endpoint_confirmation_does_not_increment_proxy_failures(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "endpoint-confirm@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "endpoint-confirm.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', health_mode='fast', consecutive_failures=0, "
            "check_claimed_until=?, check_claim_token=? WHERE id=?",
            ((now + timedelta(minutes=10)).isoformat(), "claim", proxy_id),
        )
        db.commit()

        apply_health_result(
            db,
            proxy_id,
            {
                "status": "needs_confirmation",
                "failure_kind": "probe_endpoint",
                "error": "probe endpoint DNS failure",
            },
            now=now,
        )
        row = db.execute(
            "SELECT status, consecutive_failures, next_check_at, check_claimed_until FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["status"] == "online"
    assert row["consecutive_failures"] == 0
    assert datetime.fromisoformat(row["next_check_at"]) == now + timedelta(minutes=5)
    assert row["check_claimed_until"] is None


def test_blocked_result_is_rescheduled_to_avoid_a_hot_check_loop(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "blocked-reschedule@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "blocked-reschedule.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET next_check_at=?, check_claimed_until=?, check_claim_token=? WHERE id=?",
            (now.isoformat(), (now + timedelta(minutes=10)).isoformat(), "claim", proxy_id),
        )
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {"status": "blocked", "failure_kind": "provider_blocked", "error": "captive portal"},
            now=now,
        )
        row = db.execute("SELECT status, next_check_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()

    assert row["status"] == "blocked"
    assert datetime.fromisoformat(row["next_check_at"]) == now + timedelta(minutes=60)


def test_fast_probe_change_is_rechecked_strongly_without_incrementing_failures(app):
    now = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "egress-confirm@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "egress-confirm.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', health_mode='fast', exit_ip='198.51.100.50', last_success_at=? WHERE id=?",
            ((now - timedelta(minutes=20)).isoformat(), proxy_id),
        )
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {
                "status": "needs_confirmation",
                "exit_ip": "198.51.100.51",
                "failure_kind": "egress_changed",
                "next_probe_index": 1,
            },
            now=now,
        )
        row = db.execute(
            "SELECT status, health_mode, consecutive_failures, exit_ip, next_check_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["status"] == "online"
    assert row["health_mode"] == "strong"
    assert row["consecutive_failures"] == 0
    assert row["exit_ip"] == "198.51.100.50"
    assert datetime.fromisoformat(row["next_check_at"]) == now


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
                online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?
            """,
            (
                start.isoformat(),
                (start + timedelta(hours=3)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
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


def test_due_backlog_is_processed_without_added_scheduler_delay(app):
    from app.services.checks import batch_spacing_seconds

    with app.app_context():
        db = get_db()
        db.execute("UPDATE settings SET value='60' WHERE key='health_interval_minutes'")
        db.execute("UPDATE settings SET value='5' WHERE key='health_concurrency'")
        db.commit()
        spacing = batch_spacing_seconds(db, due_count=30_000)
    assert spacing == 0


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
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip='198.51.100.1', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                (now - timedelta(hours=24)).isoformat(),
                now.isoformat(),
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


def test_egress_change_invalidates_an_inflight_earnapp_claim(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-earnapp-result@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', exit_ip='198.51.100.1', "
            "eligibility='pending', earnapp_claimed_until=?, earnapp_claim_token='old-claim', "
            "earnapp_next_check_at=? WHERE id=?",
            ((now + timedelta(minutes=5)).isoformat(), now.isoformat(), proxy_id),
        )
        db.commit()

        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.2"},
            now=now + timedelta(minutes=1),
        )
        apply_earnapp_result(
            db,
            proxy_id,
            {
                "verdict": "ALLOW",
                "reason": "late result from old egress",
                "_earnapp_claim_token": "old-claim",
            },
            now=now + timedelta(minutes=2),
        )
        row = db.execute(
            "SELECT eligibility, earnapp_claim_token, earnapp_next_check_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["eligibility"] == "pending"
    assert row["earnapp_claim_token"] is None
    assert datetime.fromisoformat(row["earnapp_next_check_at"]) <= now + timedelta(minutes=1)


def test_stale_recovery_invalidates_an_inflight_earnapp_claim(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-recovery-claim@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', exit_ip='198.51.100.3', "
            "eligibility='pending', online_since=?, last_success_at=?, earnapp_claimed_until=?, "
            "earnapp_claim_token='old-claim', earnapp_next_check_at=? WHERE id=?",
            (
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=3)).isoformat(),
                (now + timedelta(minutes=5)).isoformat(),
                now.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.3"},
            now=now,
        )
        apply_earnapp_result(
            db,
            proxy_id,
            {
                "verdict": "ALLOW",
                "reason": "late result from stale health epoch",
                "_earnapp_claim_token": "old-claim",
            },
            now=now + timedelta(minutes=1),
        )
        row = db.execute(
            "SELECT eligibility, earnapp_claim_token, earnapp_next_check_at FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["eligibility"] == "pending"
    assert row["earnapp_claim_token"] is None
    assert datetime.fromisoformat(row["earnapp_next_check_at"]) <= now


def test_live_health_result_preserves_probation_and_active_earnapp_claim(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    probation = (now - timedelta(hours=2)).isoformat()
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "health-write-integrity@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', detected_protocol='socks5', exit_ip='198.51.100.4', "
            "eligibility='allow', online_since=?, last_success_at=?, probation_started_at=?, "
            "accrual_cursor_at=?, earnapp_claimed_until=?, earnapp_claim_token='active-claim' WHERE id=?",
            (
                probation,
                probation,
                probation,
                probation,
                (now + timedelta(minutes=5)).isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.4"},
            now=now,
        )
        row = db.execute(
            "SELECT probation_started_at, accrual_cursor_at, earnapp_claim_token FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["probation_started_at"] == probation
    assert row["accrual_cursor_at"] == probation
    assert row["earnapp_claim_token"] == "active-claim"


def test_eligibility_loss_expires_pending_cycle_and_restarts_probation(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "eligibility-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=25)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
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
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (boundary + timedelta(hours=1)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
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
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=27)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
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
