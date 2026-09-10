from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.earnings import accrue_eligible_time, balances_for_user
from app.services.proxies import (
    add_proxy,
    archive_proxy,
    promote_duplicate_if_due,
    replace_proxy,
)
from app.services.users import create_user


def test_replace_updates_same_record_and_resets_probation(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:old-pass")
        replace_proxy(db, proxy_id, user_id, "new.example:9010:u:new-pass", now=now)
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    assert row["host"] == "new.example"
    assert row["status"] == "pending"
    assert row["probation_started_at"] == now.isoformat()


def test_replace_resets_fast_health_observation_state(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replace-health@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old-health.example:9000:u:p")
        db.execute(
            """
            UPDATE proxies SET status='online', detected_protocol='socks5', health_mode='fast',
                last_success_at=?, next_probe_index=2, last_probe_endpoint='https://icanhazip.com',
                last_latency_ms=120, failure_kind=''
            WHERE id=?
            """,
            ((now - timedelta(minutes=10)).isoformat(), proxy_id),
        )
        db.commit()
        replace_proxy(db, proxy_id, user_id, "new-health.example:9001:u:new", now=now)
        row = db.execute(
            "SELECT status, detected_protocol, health_mode, last_success_at, next_probe_index, last_probe_endpoint, last_latency_ms, failure_kind FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["status"] == "pending"
    assert row["detected_protocol"] == "unknown"
    assert row["health_mode"] == "strong"
    assert row["last_success_at"] is None
    assert row["next_probe_index"] == 0
    assert row["last_probe_endpoint"] == ""
    assert row["last_latency_ms"] is None
    assert row["failure_kind"] == ""


def test_replace_resets_operational_uptime_counters(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replace-uptime@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old-uptime.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET accumulated_online_seconds=?, accumulated_offline_seconds=?, "
            "continuous_dead_since=? WHERE id=?",
            (12 * 3600, 3 * 3600, (now - timedelta(hours=3)).isoformat(), proxy_id),
        )
        db.commit()

        replace_proxy(db, proxy_id, user_id, "new-uptime.example:9001:u:new", now=now)
        row = db.execute(
            "SELECT accumulated_online_seconds, accumulated_offline_seconds, continuous_dead_since "
            "FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["accumulated_online_seconds"] == 0
    assert row["accumulated_offline_seconds"] == 0
    assert row["continuous_dead_since"] is None


def test_archive_keeps_history_but_removes_operational_record(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        archive_proxy(db, proxy_id, user_id)
        row = db.execute("SELECT archived_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    assert row["archived_at"] is not None


def test_live_duplicate_is_promoted_after_canonical_offline_for_24_hours(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical.example:9001:u:p")
        duplicate = add_proxy(db, user_id, "duplicate.example:9002:u:p")
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.7', status='offline', offline_since=? WHERE id=?",
            ((now - timedelta(hours=25)).isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.7', status='online', duplicate_of=?, last_success_at=? WHERE id=?",
            (canonical, now.isoformat(), duplicate),
        )
        db.commit()
        promoted = promote_duplicate_if_due(db, canonical, now=now)
        rows = db.execute(
            "SELECT id, duplicate_of FROM proxies WHERE id IN (?,?) ORDER BY id",
            (canonical, duplicate),
        ).fetchall()
    assert promoted == duplicate
    assert rows[0]["duplicate_of"] == duplicate
    assert rows[1]["duplicate_of"] is None


def test_promoted_duplicate_starts_earning_at_promotion_instead_of_backfilling(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "promotion-earn@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical-earn.example:9001:u:p")
        duplicate = add_proxy(db, user_id, "duplicate-earn.example:9002:u:p")
        old = now - timedelta(days=10)
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.70', egress_attestation_source='https_quorum', "
            "status='offline', offline_since=? WHERE id=?",
            ((now - timedelta(hours=25)).isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.70', status='online', eligibility='allow', "
            "egress_attestation_source='earnapp_tls', country_code='US', duplicate_of=?, "
            "online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                canonical,
                old.isoformat(),
                now.isoformat(),
                old.isoformat(),
                old.isoformat(),
                duplicate,
            ),
        )
        db.commit()

        assert promote_duplicate_if_due(db, canonical, now=now) == duplicate
        accrue_eligible_time(db, now=now + timedelta(hours=1))
        balance = balances_for_user(db, user_id)

    one_hour = (1_000_000 * 3600) // (720 * 3600)
    assert balance.available_micro_usd == 0
    assert balance.pending_micro_usd == one_hour


def test_promoting_duplicate_expires_old_canonical_pending_earnings(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "promotion-expire@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical-expire.example:9001:u:p")
        duplicate = add_proxy(db, user_id, "duplicate-expire.example:9002:u:p")
        dead_since = now - timedelta(hours=25)
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.71', egress_attestation_source='https_quorum', "
            "status='offline', offline_since=? WHERE id=?",
            (dead_since.isoformat(), canonical),
        )
        db.execute(
            "UPDATE proxies SET exit_ip='198.51.100.71', egress_attestation_source='earnapp_tls', "
            "status='online', eligibility='allow', duplicate_of=?, last_success_at=? WHERE id=?",
            (canonical, now.isoformat(), duplicate),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (
                user_id,
                canonical,
                (now - timedelta(hours=8)).isoformat(),
                (now - timedelta(hours=7)).isoformat(),
                1000,
                (now - timedelta(hours=7)).isoformat(),
            ),
        )
        db.commit()

        assert promote_duplicate_if_due(db, canonical, now=now) == duplicate
        ledger = db.execute(
            "SELECT bucket FROM earnings_ledger WHERE proxy_id=? ORDER BY id",
            (canonical,),
        ).fetchall()

    assert [row["bucket"] for row in ledger] == ["expired"]
