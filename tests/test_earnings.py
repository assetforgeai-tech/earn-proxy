import contextlib
import threading
from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.checks import apply_health_result
from app.services.earnings import accrue_eligible_time, balances_for_user, earning_online_seconds_for_proxies
from app.services.proxies import add_proxy, reconcile_exit_ip, replace_proxy
from app.services.users import create_user


def test_earnings_accrue_immediately_but_unlock_after_168_hours(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.1', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=169)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        first = balances_for_user(db, user_id)
        accrue_eligible_time(db, now=start + timedelta(hours=169))
        unlocked = balances_for_user(db, user_id)

    assert first.pending_micro_usd > 0
    assert first.available_micro_usd == 0
    assert unlocked.available_micro_usd > first.available_micro_usd
    assert unlocked.pending_micro_usd == 0


def test_pause_earn_stops_new_accrual(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (user_id,))
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.2', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balances = balances_for_user(db, user_id)

    assert balances.pending_micro_usd == 0
    assert balances.available_micro_usd == 0


def test_long_gap_splits_probation_before_unlocking_available_balance(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "long-gap@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.3', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=240)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=240))
        buckets = {
            row["bucket"]: int(row["micro_usd"])
            for row in db.execute(
                "SELECT bucket, COALESCE(SUM(micro_usd), 0) AS micro_usd FROM earnings_ledger WHERE proxy_id=? GROUP BY bucket",
                (proxy_id,),
            ).fetchall()
        }
    assert buckets.get("pending", 0) == 0
    assert buckets["available"] > 0


def test_replacing_proxy_expires_old_pending_cycle_without_touching_available(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replace-cycle@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.4', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        replace_proxy(
            db,
            proxy_id,
            user_id,
            "new.example:9001:u:new",
            now=start + timedelta(hours=24),
        )
        row = db.execute(
            "SELECT bucket, COALESCE(SUM(micro_usd), 0) AS total FROM earnings_ledger WHERE proxy_id=? GROUP BY bucket",
            (proxy_id,),
        ).fetchall()
        buckets = {item["bucket"]: int(item["total"]) for item in row}
    assert buckets.get("pending", 0) == 0
    assert buckets.get("expired", 0) > 0


def test_concurrent_accrual_does_not_create_overlapping_ledger_intervals(app, monkeypatch):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "accrual-race@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "race.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.5', "
            "egress_attestation_source='https_quorum', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=2)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

    barrier = threading.Barrier(2)
    from app.services import earnings as earnings_service

    original_add = earnings_service._add_ledger_entry

    def synchronized_add(*args, **kwargs):
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=0.5)
        return original_add(*args, **kwargs)

    monkeypatch.setattr(earnings_service, "_add_ledger_entry", synchronized_add)

    def accrue_at(end):
        with app.app_context():
            accrue_eligible_time(get_db(), now=end)

    threads = [
        threading.Thread(target=accrue_at, args=(start + timedelta(hours=1),)),
        threading.Thread(target=accrue_at, args=(start + timedelta(hours=2),)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    with app.app_context():
        rows = (
            get_db()
            .execute(
                "SELECT started_at, ended_at FROM earnings_ledger WHERE proxy_id=? ORDER BY started_at, ended_at",
                (proxy_id,),
            )
            .fetchall()
        )
    for previous, current in zip(rows, rows[1:], strict=False):
        assert datetime.fromisoformat(current["started_at"]) >= datetime.fromisoformat(previous["ended_at"])


def test_stale_health_does_not_accrue_or_backfill_an_unobserved_gap(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "stale-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "stale.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip=?, "
            "egress_attestation_source='https_quorum', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                "198.51.100.60",
                start.isoformat(),
                start.isoformat(),
                start.isoformat(),
                (start - timedelta(days=8)).isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=3))
        before_recovery = balances_for_user(db, user_id)
        apply_health_result(
            db,
            proxy_id,
            {"status": "live", "protocol": "socks5", "exit_ip": "198.51.100.60"},
            now=start + timedelta(hours=4),
        )
        accrue_eligible_time(db, now=start + timedelta(hours=5))
        after_recovery = balances_for_user(db, user_id)

    two_hours = (1_000_000 * 2 * 3600) // (720 * 3600)
    one_hour = (1_000_000 * 3600) // (720 * 3600)
    assert before_recovery.available_micro_usd == two_hours
    assert after_recovery.available_micro_usd == two_hours
    assert after_recovery.pending_micro_usd == one_hour


def test_online_row_without_successful_health_observation_does_not_accrue(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "unverified-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "unverified.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.6', "
            "egress_attestation_source='https_quorum', "
            "online_since=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), start.isoformat(), start.isoformat(), proxy_id),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balance = balances_for_user(db, user_id)
        cursor = db.execute("SELECT accrual_cursor_at FROM proxies WHERE id=?", (proxy_id,)).fetchone()[
            "accrual_cursor_at"
        ]

    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0
    assert cursor == start.isoformat()


def test_earning_online_seconds_excludes_pre_eligibility_operational_time(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    eligible_at = start + timedelta(hours=3)
    now = start + timedelta(hours=5)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "earning-hours-projection@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "earning-hours-projection.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.61', "
            "egress_attestation_source='https_quorum', accumulated_online_seconds=5*3600, online_since=?, "
            "last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (start.isoformat(), now.isoformat(), eligible_at.isoformat(), eligible_at.isoformat(), proxy_id),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, 0, 'pending', ?)",
            (user_id, proxy_id, eligible_at.isoformat(), (start + timedelta(hours=4)).isoformat(), now.isoformat()),
        )
        db.commit()
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        values = earning_online_seconds_for_proxies(db, [row], now=now, health_stale_minutes=120)

    assert values[proxy_id] == 2 * 60 * 60


def test_earning_online_seconds_is_zero_for_currently_non_earning_rows(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    now = start + timedelta(hours=5)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "non-earning-hours-projection@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "non-earning-hours-projection.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='pending', exit_ip='198.51.100.62', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, accrual_cursor_at=? WHERE id=?",
            (start.isoformat(), now.isoformat(), start.isoformat(), proxy_id),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, 0, 'available', ?)",
            (user_id, proxy_id, start.isoformat(), (start + timedelta(hours=2)).isoformat(), now.isoformat()),
        )
        db.commit()
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        values = earning_online_seconds_for_proxies(db, [row], now=now, health_stale_minutes=120)

    assert values[proxy_id] == 0


def test_earning_online_seconds_excludes_previous_replaced_credential(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    replaced_at = start + timedelta(hours=5)
    now = replaced_at + timedelta(hours=2)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "replaced-hours-projection@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "old-hours-projection.example:9000:u:p")
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, 0, 'available', ?)",
            (user_id, proxy_id, start.isoformat(), replaced_at.isoformat(), replaced_at.isoformat()),
        )
        db.commit()

        replace_proxy(db, proxy_id, user_id, "new-hours-projection.example:9001:u:new", now=replaced_at)
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', "
            "exit_ip='198.51.100.63', egress_attestation_source='https_quorum', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (replaced_at.isoformat(), now.isoformat(), replaced_at.isoformat(), replaced_at.isoformat(), proxy_id),
        )
        db.commit()
        accrue_eligible_time(db, now=now)
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        values = earning_online_seconds_for_proxies(db, [row], now=now, health_stale_minutes=120)

    assert values[proxy_id] == 2 * 60 * 60


def test_earning_online_seconds_drops_ledger_interval_started_before_replace(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    replaced_at = start + timedelta(hours=5)
    now = replaced_at + timedelta(hours=2)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "crossing-replace-hours@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "crossing-old.example:9000:u:p")
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, 0, 'available', ?)",
            (user_id, proxy_id, start.isoformat(), (start + timedelta(hours=10)).isoformat(), now.isoformat()),
        )
        db.commit()

        replace_proxy(db, proxy_id, user_id, "crossing-new.example:9001:u:new", now=replaced_at)
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', "
            "exit_ip='198.51.100.64', egress_attestation_source='https_quorum', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (replaced_at.isoformat(), now.isoformat(), replaced_at.isoformat(), replaced_at.isoformat(), proxy_id),
        )
        db.commit()
        row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
        values = earning_online_seconds_for_proxies(db, [row], now=now, health_stale_minutes=120)

    assert values[proxy_id] == 2 * 60 * 60


def test_online_pending_row_without_verified_egress_does_not_accrue(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "unverified-egress-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "unverified-egress-earnings.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='pending', country_code='US', "
            "online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balance = balances_for_user(db, user_id)

    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0


def test_duplicate_egress_allow_row_never_accrues(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "duplicate-egress-earnings@example.com", "password", status="active")
        canonical = add_proxy(db, user_id, "canonical-earnings.example:9000:u:c")
        duplicate = add_proxy(db, user_id, "duplicate-earnings.example:9001:u:d")
        db.execute(
            "UPDATE proxies SET status='offline', eligibility='allow', country_code='US', exit_ip='198.51.100.70', "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                canonical,
            ),
        )
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip='198.51.100.70', "
            "egress_attestation_source='earnapp_tls', duplicate_of=?, online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                canonical,
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                duplicate,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        ledger = db.execute("SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=?", (duplicate,)).fetchone()
        balance = balances_for_user(db, user_id)

    assert ledger["count"] == 0
    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0


def test_allow_online_row_without_trusted_egress_does_not_accrue(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "untrusted-allow-earnings@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "untrusted-allow.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', online_since=?, "
            "last_success_at=?, accrual_cursor_at=?, probation_started_at=?, exit_ip=NULL, "
            "egress_attestation_source='' WHERE id=?",
            (
                start.isoformat(),
                (start + timedelta(hours=24)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                proxy_id,
            ),
        )
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=24))
        balance = balances_for_user(db, user_id)

    assert balance.pending_micro_usd == 0
    assert balance.available_micro_usd == 0


def test_rehomed_duplicate_expires_pending_earnings(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "rehomed-duplicate@example.com", "password", status="active")
        current_canonical = add_proxy(db, user_id, "current-canonical.example:9000:u:c")
        rehomed = add_proxy(db, user_id, "rehomed.example:9001:u:r")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', country_code='US', exit_ip=?, "
            "egress_attestation_source='https_quorum', online_since=?, last_success_at=?, "
            "accrual_cursor_at=?, probation_started_at=? WHERE id=?",
            (
                "198.51.100.120",
                start.isoformat(),
                (start + timedelta(hours=2)).isoformat(),
                start.isoformat(),
                start.isoformat(),
                current_canonical,
            ),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (
                user_id,
                current_canonical,
                start.isoformat(),
                (start + timedelta(hours=1)).isoformat(),
                1000,
                (start + timedelta(hours=1)).isoformat(),
            ),
        )
        db.execute(
            "UPDATE proxies SET created_at=?, updated_at=? WHERE id=?",
            ((start - timedelta(hours=1)).isoformat(), (start - timedelta(hours=1)).isoformat(), rehomed),
        )
        db.commit()

        reconcile_exit_ip(db, rehomed, "198.51.100.120")
        row = db.execute(
            "SELECT duplicate_of FROM proxies WHERE id=?",
            (current_canonical,),
        ).fetchone()
        pending = db.execute(
            "SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=? AND bucket='pending'",
            (current_canonical,),
        ).fetchone()
        expired = db.execute(
            "SELECT COUNT(*) AS count FROM earnings_ledger WHERE proxy_id=? AND bucket='expired'",
            (current_canonical,),
        ).fetchone()

    assert row["duplicate_of"] == rehomed
    assert pending["count"] == 0
    assert expired["count"] == 1
