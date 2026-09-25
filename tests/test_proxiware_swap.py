from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.services.proxiware_swap import (
    ACTIVE_SWAP_STATES,
    SwapDecision,
    cancel_swap,
    claim_next_swap,
    ensure_proxiware_swap_schema,
    get_provider_secret_metadata,
    mark_swap_blocked,
    mark_swap_failed,
    mark_swap_success,
    queue_eligible_swaps,
    request_manual_swap,
    save_provider_secret,
)
from app.services.settings import set_setting


def test_security_schema_migrates_legacy_unscoped_tables(tmp_path):
    database = sqlite3.connect(tmp_path / "legacy-provider-security.db")
    database.row_factory = sqlite3.Row
    database.executescript(
        """
        CREATE TABLE provider_credentials (
            name TEXT PRIMARY KEY,
            secret_encrypted TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );
        CREATE TABLE provider_action_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            attempted_at TEXT NOT NULL
        );
        CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    ensure_proxiware_swap_schema(database)

    credential_columns = {
        row["name"] for row in database.execute('PRAGMA table_info("provider_credentials")').fetchall()
    }
    attempt_columns = {
        row["name"] for row in database.execute('PRAGMA table_info("provider_action_attempts")').fetchall()
    }
    indexes = {row["name"] for row in database.execute('PRAGMA index_list("provider_action_attempts")').fetchall()}
    database.close()

    assert "provider" in credential_columns
    assert "provider" in attempt_columns
    assert "provider_action_attempts_provider_idx" in indexes


def _seed_subscription(db, *, eligible_count=500, connections=100, quota=1, cooldown=None):
    ensure_proxiware_swap_schema(db)
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC).isoformat()
    db.execute(
        """
        INSERT INTO provider_subscriptions
            (provider, external_id, network, location, quantity, status,
             eligible_count, connections, swap_quota, first_seen_at, last_seen_at, created_at, updated_at)
        VALUES ('proxiware', 'sub-1', 'isp', 'US', 1, 'active', ?, ?, ?, ?, ?, ?, ?)
        """,
        (eligible_count, connections, quota, now, now, now, now),
    )
    sub_id = db.execute("SELECT id FROM provider_subscriptions WHERE external_id='sub-1'").fetchone()["id"]
    db.execute(
        """
        INSERT INTO provider_assignments
            (subscription_id, provider, external_id, host, port, status,
             qualification, provider_eligible, live_status, country,
             dashboard_assignment_id, dashboard_eligible, dashboard_connections,
             dashboard_observed_at, dashboard_source,
             assigned_at, last_seen_at, created_at, updated_at)
        VALUES (?, 'proxiware', 'assignment-1', 'proxy.example', 8080, 'active',
                'risk', 1, 'live', 'US', 'dashboard-1', 1, 10, ?,
                'provider_dashboard', ?, ?, ?, ?)
        """,
        (sub_id, now, now, now, now, now),
    )
    db.commit()
    return int(sub_id)


def _seed_foreign_job(db):
    ensure_proxiware_swap_schema(db)
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC).isoformat()
    db.execute(
        """
        INSERT INTO provider_subscriptions
            (provider, external_id, status, created_at, updated_at)
        VALUES ('other-provider', 'foreign-subscription', 'active', ?, ?)
        """,
        (now, now),
    )
    subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        """
        INSERT INTO swap_jobs
            (provider, subscription_id, state, reason, created_at, updated_at)
        VALUES ('other-provider', ?, 'pending', 'foreign', ?, ?)
        """,
        (subscription_id, now, now),
    )
    db.commit()
    return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def test_queue_requires_all_guards_and_creates_one_durable_job(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        assert queue_eligible_swaps(db, now=now) == 0
        job = db.execute("SELECT * FROM swap_jobs WHERE subscription_id=?", (sub_id,)).fetchone()
    assert job["state"] == "pending"
    assert job["reason"] == "queued"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("live_status", "dead", "not_live"),
        ("qualification", "dead", "not_risk"),
        ("provider_eligible", 0, "provider_ineligible"),
    ],
)
def test_queue_skips_failed_assignment_guards(app, field, value, reason):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        db.execute(f"UPDATE provider_assignments SET {field}=? WHERE subscription_id=?", (value, sub_id))
        db.commit()
        assert queue_eligible_swaps(db, now=now) == 0
        decision = SwapDecision.for_subscription(db, sub_id, now=now)
    assert decision.allowed is False
    assert decision.reason == reason


def test_success_persists_mapping_and_enforces_sixty_second_cooldown(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=success_at) == 1
        job_id = db.execute("SELECT id FROM swap_jobs WHERE subscription_id=?", (sub_id,)).fetchone()["id"]
        mark_swap_success(
            db,
            job_id,
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=success_at,
        )
        job = db.execute("SELECT * FROM swap_jobs WHERE id=?", (job_id,)).fetchone()
        mapping = db.execute("SELECT * FROM swap_mappings WHERE swap_job_id=?", (job_id,)).fetchone()
        assignment = db.execute(
            "SELECT replacement_ready_at FROM provider_assignments WHERE external_id='assignment-2'"
        ).fetchone()
    assert job["state"] == "success"
    assert mapping["old_assignment_external_id"] == "assignment-1"
    assert mapping["new_assignment_external_id"] == "assignment-2"
    assert assignment is not None
    assert assignment["replacement_ready_at"] == (success_at + timedelta(seconds=60)).isoformat()


def test_success_uses_configured_cooldown_but_never_less_than_sixty_seconds(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        set_setting(db, "proxiware_cooldown_seconds", "120")
        assert queue_eligible_swaps(db, now=success_at) == 1
        job_id = db.execute("SELECT id FROM swap_jobs WHERE subscription_id=?", (sub_id,)).fetchone()["id"]
        mark_swap_success(
            db,
            job_id,
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=success_at,
        )
        assignment = db.execute(
            "SELECT replacement_ready_at FROM provider_assignments WHERE external_id='assignment-2'"
        ).fetchone()
    assert assignment["replacement_ready_at"] == (success_at + timedelta(seconds=120)).isoformat()


def test_success_disables_distribution_until_replacement_is_requalified(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        db.execute(
            "UPDATE provider_assignments SET distribution_enabled=1 WHERE subscription_id=?",
            (sub_id,),
        )
        db.commit()
        assert queue_eligible_swaps(db, now=success_at) == 1
        job_id = db.execute("SELECT id FROM swap_jobs WHERE subscription_id=?", (sub_id,)).fetchone()["id"]
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id,provider,external_id,host,port,status,qualification,
                provider_eligible,live_status,distribution_enabled,assigned_at,last_seen_at,
                created_at,updated_at
            ) VALUES(?, 'proxiware','assignment-2','new.example',8080,'active','allow',1,'live',1,?,?,?,?)
            """,
            (sub_id, success_at.isoformat(), success_at.isoformat(), success_at.isoformat(), success_at.isoformat()),
        )
        db.commit()

        mark_swap_success(
            db,
            job_id,
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=success_at,
        )

        rows = db.execute(
            "SELECT external_id,status,qualification,live_status,provider_eligible,distribution_enabled "
            "FROM provider_assignments WHERE subscription_id=? ORDER BY id",
            (sub_id,),
        ).fetchall()

    assert tuple(rows[0]) == ("assignment-1", "replaced", "risk", "live", 1, 0)
    assert tuple(rows[1]) == ("assignment-2", "pending", "pending", "pending", 0, 0)


def test_blocked_security_errors_pause_auto_swap_and_do_not_retry(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        queue_eligible_swaps(db, now=now)
        job_id = db.execute("SELECT id FROM swap_jobs WHERE subscription_id=?", (sub_id,)).fetchone()["id"]
        mark_swap_blocked(db, job_id, error_code="captcha_required", blocked_at=now)
        job = db.execute("SELECT * FROM swap_jobs WHERE id=?", (job_id,)).fetchone()
        setting = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()
        assert queue_eligible_swaps(db, now=now + timedelta(hours=1)) == 0
    assert job["state"] == "blocked"
    assert job["reason"] == "manual_action_required"
    assert setting["value"] == "0"


def test_secret_storage_is_encrypted_write_only_and_blank_preserves(app):
    with app.app_context():
        db = get_db()
        save_provider_secret(db, "api_key", "secret-api-key")
        row = db.execute("SELECT * FROM provider_credentials WHERE name='api_key'").fetchone()
        assert row["secret_encrypted"] != "secret-api-key"
        assert get_provider_secret_metadata(db)["api_key"]["configured"] is True
        save_provider_secret(db, "api_key", "")
        assert db.execute("SELECT secret_encrypted FROM provider_credentials WHERE name='api_key'").fetchone()[0]


def test_active_swap_states_are_explicit():
    assert frozenset({"pending", "running"}) == ACTIVE_SWAP_STATES


def test_auto_swap_is_disabled_by_default(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        assert queue_eligible_swaps(db, now=now) == 0


def test_allow_assignment_is_not_swapped(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        db.execute("UPDATE provider_assignments SET qualification='allow' WHERE subscription_id=?", (sub_id,))
        db.commit()
        assert queue_eligible_swaps(db, now=now) == 0
        assert SwapDecision.for_subscription(db, sub_id, now=now).reason == "not_risk"


def test_duplicate_egress_assignment_is_not_swapped(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        db.execute("UPDATE provider_assignments SET duplicate_egress=1 WHERE subscription_id=?", (sub_id,))
        db.commit()
        assert queue_eligible_swaps(db, now=now) == 0
        decision = SwapDecision.for_subscription(db, sub_id, now=now)
    assert decision.reason == "duplicate_egress"


def test_swap_requires_fresh_dashboard_eligibility_and_connections(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assignment_id = db.execute(
            "SELECT id FROM provider_assignments WHERE subscription_id=?", (sub_id,)
        ).fetchone()["id"]
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dash-1', dashboard_eligible=0, "
            "dashboard_connections=1, dashboard_observed_at=?, dashboard_source='provider_dashboard' WHERE id=?",
            (now.isoformat(), assignment_id),
        )
        db.commit()

        decision = SwapDecision.for_subscription(db, sub_id, now=now)

    assert decision.allowed is False
    assert decision.reason == "provider_ineligible"


def test_swap_rejects_stale_dashboard_observation(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        assignment_id = db.execute(
            "SELECT id FROM provider_assignments WHERE subscription_id=?", (sub_id,)
        ).fetchone()["id"]
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dash-1', dashboard_eligible=1, "
            "dashboard_connections=1, dashboard_observed_at=?, dashboard_source='provider_dashboard' WHERE id=?",
            ((now - timedelta(hours=1)).isoformat(), assignment_id),
        )
        db.commit()

        decision = SwapDecision.for_subscription(db, sub_id, now=now)

    assert decision.allowed is False
    assert decision.reason == "dashboard_stale"


def test_expired_running_claim_is_recovered_after_restart(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        queue_eligible_swaps(db, now=now)
        first = claim_next_swap(db, now=now, claim_seconds=30)
        second = claim_next_swap(db, now=now + timedelta(seconds=31), claim_seconds=30)
    assert first is not None
    assert second is not None
    assert second["id"] == first["id"]
    assert second["claim_token"] != first["claim_token"]


def test_retry_is_bounded_then_blocks(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        queue_eligible_swaps(db, now=now)
        first = claim_next_swap(db, now=now)
        assert mark_swap_failed(db, first["id"], error_code="provider_timeout", retry_limit=2) == "pending"
        second = claim_next_swap(db, now=now + timedelta(seconds=1))
        assert mark_swap_failed(db, second["id"], error_code="provider_timeout", retry_limit=2) == "blocked"


def test_stale_worker_cannot_complete_reclaimed_swap(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        queue_eligible_swaps(db, now=now)
        stale = claim_next_swap(db, now=now, claim_seconds=30)
        current = claim_next_swap(db, now=now + timedelta(seconds=31), claim_seconds=30)
        with pytest.raises(ValueError, match="claim"):
            mark_swap_success(
                db,
                stale["id"],
                old_assignment_external_id="assignment-1",
                new_assignment_external_id="assignment-2",
                success_at=now + timedelta(seconds=32),
                claim_token=stale["claim_token"],
            )
        mark_swap_success(
            db,
            current["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=now + timedelta(seconds=32),
            claim_token=current["claim_token"],
        )


def test_proxiware_claim_ignores_jobs_owned_by_another_provider(app):
    with app.app_context():
        db = get_db()
        foreign_job_id = _seed_foreign_job(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert claim_next_swap(db) is None
        row = db.execute("SELECT state, attempts FROM swap_jobs WHERE id=?", (foreign_job_id,)).fetchone()
    assert tuple(row) == ("pending", 0)


def test_proxiware_cancel_cannot_target_jobs_owned_by_another_provider(app):
    with app.app_context():
        db = get_db()
        foreign_job_id = _seed_foreign_job(db)
        with pytest.raises(LookupError):
            cancel_swap(db, foreign_job_id)
        row = db.execute("SELECT state FROM swap_jobs WHERE id=?", (foreign_job_id,)).fetchone()
    assert row["state"] == "pending"


def test_proxiware_state_transitions_cannot_target_jobs_owned_by_another_provider(app):
    with app.app_context():
        db = get_db()
        foreign_job_id = _seed_foreign_job(db)
        with pytest.raises(LookupError):
            mark_swap_failed(db, foreign_job_id, error_code="provider_timeout")
        with pytest.raises(LookupError):
            mark_swap_blocked(db, foreign_job_id, error_code="manual_action_required")
        row = db.execute("SELECT state FROM swap_jobs WHERE id=?", (foreign_job_id,)).fetchone()
    assert row["state"] == "pending"


def test_proxiware_success_cannot_target_job_owned_by_another_provider(app):
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        foreign_job_id = _seed_foreign_job(db)
        with pytest.raises(LookupError):
            mark_swap_success(
                db,
                foreign_job_id,
                old_assignment_external_id="assignment-1",
                new_assignment_external_id="assignment-2",
            )
        job = db.execute("SELECT state FROM swap_jobs WHERE id=?", (foreign_job_id,)).fetchone()
        mapping = db.execute(
            "SELECT id FROM swap_mappings WHERE swap_job_id=?",
            (foreign_job_id,),
        ).fetchone()
    assert job["state"] == "pending"
    assert mapping is None


def test_swap_success_rejects_cross_subscription_assignment_mapping(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        first_sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=success_at) == 1
        job = db.execute(
            "SELECT id,old_assignment_id FROM swap_jobs WHERE subscription_id=?",
            (first_sub_id,),
        ).fetchone()
        db.execute(
            """
            INSERT INTO provider_subscriptions
                (provider, external_id, status, eligible_count, connections, swap_quota,
                 first_seen_at, last_seen_at, created_at, updated_at)
            VALUES ('proxiware', 'sub-2', 'active', 500, 10, 2, ?, ?, ?, ?)
            """,
            tuple([success_at.isoformat()] * 4),
        )
        second_sub_id = db.execute("SELECT id FROM provider_subscriptions WHERE external_id='sub-2'").fetchone()["id"]
        db.execute(
            """
            INSERT INTO provider_assignments
                (subscription_id, provider, external_id, host, port, status,
                 qualification, provider_eligible, live_status, country,
                 assigned_at, last_seen_at, created_at, updated_at)
            VALUES (?, 'proxiware', 'foreign-new', 'foreign.example', 8080, 'active',
                    'pending', 0, 'pending', 'US', ?, ?, ?, ?)
            """,
            (second_sub_id, *tuple([success_at.isoformat()] * 4)),
        )
        db.commit()

        with pytest.raises(ValueError, match="subscription"):
            mark_swap_success(
                db,
                int(job["id"]),
                old_assignment_external_id="assignment-1",
                new_assignment_external_id="foreign-new",
                success_at=success_at,
            )

        stored_job = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        mapping = db.execute("SELECT id FROM swap_mappings WHERE swap_job_id=?", (job["id"],)).fetchone()
    assert stored_job["state"] == "pending"
    assert mapping is None


@pytest.mark.parametrize(
    ("field", "value"),
    [("qualification", "allow"), ("live_status", "dead"), ("duplicate_egress", 1)],
)
def test_manual_swap_revalidates_all_guards_except_auto_swap(app, field, value):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        job_id = db.execute(
            "SELECT id FROM swap_jobs WHERE subscription_id=?",
            (sub_id,),
        ).fetchone()["id"]
        db.execute(
            f"UPDATE provider_assignments SET {field}=? WHERE subscription_id=?",
            (value, sub_id),
        )
        set_setting(db, "proxiware_auto_swap", "0")
        db.commit()
        with pytest.raises(ValueError, match="guards"):
            request_manual_swap(db, job_id, now=now)
        state = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job_id,)).fetchone()["state"]
    assert state == "pending"
