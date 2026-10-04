from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.crypto import encrypt_secret
from app.db import get_db
from app.services.proxiware_swap import (
    ACTIVE_SWAP_STATES,
    SwapDecision,
    SwapReconciliationPending,
    begin_swap_batch_mutation,
    cancel_swap,
    claim_next_swap,
    claim_next_swap_batch,
    ensure_proxiware_swap_schema,
    get_provider_secret_metadata,
    mark_provider_applied,
    mark_reconciliation_required,
    mark_swap_blocked,
    mark_swap_failed,
    mark_swap_success,
    queue_eligible_swaps,
    reconcile_provider_applied_swaps,
    request_manual_swap,
    revalidate_swap_job,
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


def test_swap_schema_preserves_callers_transaction(tmp_path):
    database = sqlite3.connect(tmp_path / "swap-transaction.db")
    database.row_factory = sqlite3.Row
    database.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    database.execute("INSERT INTO settings(key,value,updated_at) VALUES('sentinel','before','now')")
    database.commit()

    database.execute("UPDATE settings SET value='after' WHERE key='sentinel'")
    ensure_proxiware_swap_schema(database)
    database.rollback()

    row = database.execute("SELECT value FROM settings WHERE key='sentinel'").fetchone()
    assert row["value"] == "before"
    database.close()


def test_ready_swap_schema_does_not_write_when_another_connection_holds_lock(tmp_path):
    """Schema checks on a ready database must stay read-only."""

    database_path = tmp_path / "swap-schema-lock.db"
    bootstrap = sqlite3.connect(database_path)
    bootstrap.row_factory = sqlite3.Row
    bootstrap.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    ensure_proxiware_swap_schema(bootstrap)
    bootstrap.execute("DELETE FROM settings WHERE key='proxiware_schema_version'")
    bootstrap.commit()
    bootstrap.close()

    holder = sqlite3.connect(database_path, timeout=0.1)
    subject = sqlite3.connect(database_path, timeout=0.1)
    holder.row_factory = sqlite3.Row
    subject.row_factory = sqlite3.Row
    holder.execute("PRAGMA journal_mode=WAL")
    subject.execute("PRAGMA journal_mode=WAL")
    holder.execute("BEGIN IMMEDIATE")
    try:
        ensure_proxiware_swap_schema(subject)
    finally:
        holder.rollback()
        holder.close()
        subject.close()


def test_swap_schema_uses_assignment_scoped_active_job_fence(app):
    with app.app_context():
        db = get_db()
        indexes = {row["name"]: row for row in db.execute('PRAGMA index_list("swap_jobs")').fetchall()}
        assignment_index = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='swap_jobs_one_active_assignment_idx'"
        ).fetchone()
        mutation_index = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='swap_jobs_one_mutation_subscription_idx'"
        ).fetchone()
        mutation_meta = next(
            row
            for row in db.execute('PRAGMA index_list("swap_jobs")').fetchall()
            if row["name"] == "swap_jobs_one_mutation_subscription_idx"
        )
        batch_index = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='swap_batches_one_active_subscription_idx'"
        ).fetchone()

    assert "swap_jobs_one_active_idx" not in indexes
    assert "swap_jobs_one_active_v2_idx" not in indexes
    assert assignment_index is not None
    assert "old_assignment_id" in str(assignment_index["sql"])
    assert mutation_index is not None
    assert "subscription_id" in str(mutation_index["sql"])
    assert int(mutation_meta["unique"]) == 0
    assert batch_index is not None


def test_swap_schema_migrates_legacy_subscription_fence(app):
    with app.app_context():
        db = get_db()
        db.execute("DROP INDEX IF EXISTS swap_jobs_one_active_assignment_idx")
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS swap_jobs_one_active_v2_idx "
            "ON swap_jobs(subscription_id) "
            "WHERE state IN ('pending','running','mutating','provider_applied','reconciliation_required')"
        )
        db.commit()

        ensure_proxiware_swap_schema(db)

        indexes = {row["name"] for row in db.execute('PRAGMA index_list("swap_jobs")').fetchall()}

    assert "swap_jobs_one_active_v2_idx" not in indexes
    assert "swap_jobs_one_active_assignment_idx" in indexes


def test_swap_schema_quarantines_duplicate_mutations_per_subscription(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC).isoformat()
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        db.execute(
            "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
            "provider_eligible,live_status,created_at,updated_at) VALUES(?, 'proxiware','assignment-2',"
            "'proxy-2.example',8081,'active','risk',1,'live',?,?)",
            (sub_id, now, now),
        )
        assignment_ids = [
            int(row["id"])
            for row in db.execute(
                "SELECT id FROM provider_assignments WHERE subscription_id=? ORDER BY id", (sub_id,)
            ).fetchall()
        ]
        db.execute("DROP INDEX IF EXISTS swap_jobs_one_active_assignment_idx")
        db.execute("DROP INDEX IF EXISTS swap_jobs_one_mutation_subscription_idx")
        for assignment_id in assignment_ids:
            db.execute(
                "INSERT INTO swap_jobs(provider,subscription_id,old_assignment_id,state,created_at,updated_at) "
                "VALUES('proxiware',?,?, 'mutating',?,?)",
                (sub_id, assignment_id, now, now),
            )
        db.commit()

        ensure_proxiware_swap_schema(db)
        rows = db.execute(
            "SELECT state,reason FROM swap_jobs WHERE subscription_id=? ORDER BY id", (sub_id,)
        ).fetchall()

    assert [row["state"] for row in rows].count("mutating") == 1
    assert [row["state"] for row in rows].count("blocked") == 1
    assert rows[1]["reason"] == "migration_conflict"


def test_swap_schema_migration_preserves_mixed_state_batch_reservation(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC).isoformat()
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        db.execute(
            "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
            "provider_eligible,live_status,created_at,updated_at) VALUES(?,'proxiware','assignment-2',"
            "'proxy-2.example',8081,'active','risk',1,'live',?,?)",
            (sub_id, now, now),
        )
        ids = [
            row["id"]
            for row in db.execute(
                "SELECT id FROM provider_assignments WHERE subscription_id=? ORDER BY id", (sub_id,)
            ).fetchall()
        ]
        for assignment_id, state in zip(ids, ("running", "mutating"), strict=True):
            db.execute(
                "INSERT INTO swap_jobs(provider,subscription_id,old_assignment_id,state,claim_token,created_at,updated_at) "
                "VALUES('proxiware',?,?,?,?,?,?)",
                (sub_id, assignment_id, state, "shared-batch-claim", now, now),
            )
        db.execute("DROP INDEX swap_batches_one_active_subscription_idx")
        db.commit()

        ensure_proxiware_swap_schema(db)
        batch = db.execute("SELECT id,state FROM swap_batches WHERE subscription_id=?", (sub_id,)).fetchone()
        rows = db.execute("SELECT batch_id FROM swap_jobs WHERE subscription_id=? ORDER BY id", (sub_id,)).fetchall()

    assert batch["state"] == "mutating"
    assert len({row["batch_id"] for row in rows}) == 1


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


def _advance_to_provider_applied(db, *, now, new_external_id="assignment-2"):
    set_setting(db, "proxiware_auto_swap", "1")
    assert queue_eligible_swaps(db, now=now) == 1
    job = claim_next_swap(db, now=now)
    revalidate_swap_job(
        db,
        job["id"],
        now=now,
        claim_token=job["claim_token"],
        enter_mutation=True,
    )
    mark_provider_applied(
        db,
        job["id"],
        old_assignment_external_id="assignment-1",
        new_assignment_external_id=new_external_id,
        applied_at=now,
        claim_token=job["claim_token"],
    )
    return job


def _seed_replacement_evidence(
    db,
    subscription_id,
    *,
    external_id="assignment-2",
    observed_at,
    username="replacement-user",
    password="replacement-password",
    dashboard_assignment_id="dashboard-new",
):
    timestamp = observed_at.isoformat()
    db.execute(
        """
        INSERT INTO provider_assignments(
            subscription_id,provider,external_id,host,port,username_encrypted,password_encrypted,
            status,qualification,provider_eligible,live_status,protocol,distribution_enabled,
            dashboard_assignment_id,dashboard_eligible,dashboard_connections,dashboard_observed_at,
            dashboard_source,assigned_at,last_seen_at,created_at,updated_at
        ) VALUES(?, 'proxiware', ?, 'new.example', 1080, ?, ?, 'active', 'pending', 1,
                 'pending', 'socks5', 0, ?, 1, 1, ?, 'provider_dashboard', ?, ?, ?, ?)
        """,
        (
            subscription_id,
            external_id,
            encrypt_secret(username) if username else "",
            encrypt_secret(password) if password else "",
            dashboard_assignment_id,
            timestamp,
            timestamp,
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    db.commit()


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


def test_queue_batches_each_non_allow_assignment_in_a_subscription(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                dashboard_assignment_id, dashboard_eligible, dashboard_connections,
                dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-2', 'proxy-2.example', 8081, 'active',
                      'risk', 1, 'live', 'US', 'dashboard-2', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")

        assert queue_eligible_swaps(db, now=now, limit=20) == 2
        rows = db.execute(
            "SELECT old_assignment_id FROM swap_jobs WHERE subscription_id=? ORDER BY old_assignment_id",
            (sub_id,),
        ).fetchall()

    assert [int(row["old_assignment_id"]) for row in rows] == [1, 2]


def test_default_scheduler_queues_more_than_twenty_eligible_siblings(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    timestamp = now.isoformat()
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        for index in range(2, 22):
            db.execute(
                "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
                "provider_eligible,live_status,country,dashboard_assignment_id,dashboard_eligible,dashboard_connections,"
                "dashboard_observed_at,dashboard_source,assigned_at,last_seen_at,created_at,updated_at) "
                "VALUES(?,'proxiware',?, ?,8081,'active','risk',1,'live','US',?,1,10,?,'provider_dashboard',?,?,?,?)",
                (
                    sub_id,
                    f"assignment-{index}",
                    f"proxy-{index}.example",
                    f"dashboard-{index}",
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")

        assert queue_eligible_swaps(db, now=now) == 21


def test_claimed_batch_fences_all_sibling_mutations_together(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        for index in range(2, 4):
            db.execute(
                "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
                "provider_eligible,live_status,country,dashboard_assignment_id,dashboard_eligible,dashboard_connections,"
                "dashboard_observed_at,dashboard_source,assigned_at,last_seen_at,created_at,updated_at) "
                "VALUES(?,'proxiware',?, ?,8081,'active','risk',1,'live','US',?,1,10,?,'provider_dashboard',?,?,?,?)",
                (
                    sub_id,
                    f"assignment-{index}",
                    f"proxy-{index}.example",
                    f"dashboard-{index}",
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")
        set_setting(db, "proxiware_allow_mutation", "1")
        assert queue_eligible_swaps(db, now=now) == 3

        batch = claim_next_swap_batch(db, now=now)
        assert len(batch) == 3
        assert len({row["batch_id"] for row in batch}) == 1
        assert len({row["claim_token"] for row in batch}) == 1
        assert claim_next_swap_batch(db, now=now) == []

        recovered = claim_next_swap_batch(db, now=now + timedelta(seconds=301))
        assert len(recovered) == 3
        assert len({row["claim_token"] for row in recovered}) == 1
        assert recovered[0]["claim_token"] != batch[0]["claim_token"]

        mutation = begin_swap_batch_mutation(
            db,
            batch_id=recovered[0]["batch_id"],
            claim_token=recovered[0]["claim_token"],
            now=now + timedelta(seconds=301),
        )
        assert len(mutation) == 3
        assert {row["state"] for row in mutation} == {"mutating"}
        assert len({row["mutation_started_at"] for row in mutation}) == 1
        assert claim_next_swap_batch(db, now=now + timedelta(seconds=302)) == []


def test_manual_claim_respects_reconciling_batch_fence(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        queue_eligible_swaps(db, now=now)
        batch = claim_next_swap_batch(db, now=now)[0]
        job_id = int(batch["id"])
        db.execute("UPDATE swap_batches SET state='reconciling' WHERE id=?", (batch["batch_id"],))
        db.execute(
            "UPDATE swap_jobs SET state='pending',batch_id=NULL,claim_token=NULL,claimed_until=NULL WHERE id=?",
            (job_id,),
        )
        db.commit()

        assert claim_next_swap(db, now=now + timedelta(seconds=1), job_id=job_id) is None


def test_queue_reserves_finite_swap_quota_across_sibling_assignments(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=1)
        timestamp = now.isoformat()
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                dashboard_assignment_id, dashboard_eligible, dashboard_connections,
                dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-2', 'proxy-2.example', 8081, 'active',
                      'risk', 1, 'live', 'US', 'dashboard-2', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")

        assert queue_eligible_swaps(db, now=now, limit=20) == 1


def test_pending_sibling_waits_until_existing_mutation_reconciles(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                dashboard_assignment_id, dashboard_eligible, dashboard_connections,
                dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-2', 'proxy-2.example', 8081, 'active',
                      'risk', 1, 'live', 'US', 'dashboard-2', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now, limit=20) == 2
        first = claim_next_swap(db, now=now)
        assert claim_next_swap(db, now=now) is None
        revalidate_swap_job(
            db,
            first["id"],
            now=now,
            claim_token=first["claim_token"],
            enter_mutation=True,
        )

        assert claim_next_swap(db, now=now) is None


def test_allow_assignment_does_not_hide_risk_sibling_from_queue(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        risk_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-1'").fetchone()["id"]
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                dashboard_assignment_id, dashboard_eligible, dashboard_connections,
                dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-allow', 'allow.example', 8081, 'active',
                      'allow', 1, 'live', 'US', 'dashboard-allow', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")

        assert queue_eligible_swaps(db, now=now, limit=20) == 1
        queued = db.execute("SELECT old_assignment_id FROM swap_jobs").fetchone()

    assert int(queued["old_assignment_id"]) == int(risk_id)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("live_status", "dead"),
        ("qualification", "pending"),
        ("provider_eligible", 0),
        ("duplicate_egress", 1),
    ],
)
def test_queue_skips_non_swappable_sibling_without_hiding_valid_risk(app, field, value):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        valid_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-1'").fetchone()["id"]
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                duplicate_egress, dashboard_assignment_id, dashboard_eligible,
                dashboard_connections, dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-invalid', 'invalid.example', 8081, 'active',
                      'risk', 1, 'live', 'US', 0, 'dashboard-invalid', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.execute(f"UPDATE provider_assignments SET {field}=? WHERE external_id='assignment-invalid'", (value,))
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")

        assert queue_eligible_swaps(db, now=now, limit=20) == 1
        queued = db.execute("SELECT old_assignment_id FROM swap_jobs").fetchone()

    assert int(queued["old_assignment_id"]) == int(valid_id)


def test_sibling_assignment_is_not_blocked_by_previous_swap_cooldown(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=-1)
        timestamp = now.isoformat()
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id, provider, external_id, host, port, status,
                qualification, provider_eligible, live_status, country,
                dashboard_assignment_id, dashboard_eligible, dashboard_connections,
                dashboard_observed_at, dashboard_source,
                assigned_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'proxiware', 'assignment-2', 'proxy-2.example', 8081, 'active',
                      'risk', 1, 'live', 'US', 'dashboard-2', 1, 10, ?,
                      'provider_dashboard', ?, ?, ?, ?)
            """,
            (sub_id, timestamp, timestamp, timestamp, timestamp, timestamp),
        )
        db.execute(
            "UPDATE provider_subscriptions SET last_swap_success_at=? WHERE id=?",
            (timestamp, sub_id),
        )
        db.commit()

        assignment_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-2'").fetchone()[
            "id"
        ]
        decision = SwapDecision.for_subscription(
            db,
            sub_id,
            now=now,
            assignment_id=assignment_id,
        )

    assert decision.allowed is True
    assert decision.assignment_id == assignment_id


def test_explicit_assignment_guard_does_not_drift_to_latest_assignment(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        approved_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-1'").fetchone()[
            "id"
        ]
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id,provider,external_id,host,port,status,qualification,
                provider_eligible,live_status,dashboard_assignment_id,dashboard_eligible,
                dashboard_connections,dashboard_observed_at,dashboard_source,
                assigned_at,last_seen_at,created_at,updated_at
            ) VALUES(?, 'proxiware','assignment-newer','newer.example',8080,'active','risk',
                     1,'live','dashboard-newer',1,10,?,'provider_dashboard',?,?,?,?)
            """,
            (sub_id, now.isoformat(), *tuple([now.isoformat()] * 4)),
        )
        db.commit()

        decision = SwapDecision.for_subscription(db, sub_id, now=now, assignment_id=approved_id)

    assert decision.allowed is True
    assert decision.assignment_id == approved_id


def test_dashboard_evidence_is_authoritative_when_subscription_counts_are_absent(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute(
            "UPDATE provider_subscriptions SET eligible_count=NULL,connections=NULL WHERE id=?",
            (sub_id,),
        )
        db.commit()

        decision = SwapDecision.for_subscription(db, sub_id, now=now)

    assert decision.allowed is True
    assert decision.reason == "ready"


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
    reconciled_at = success_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        job = _advance_to_provider_applied(db, now=success_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at)
        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )
        stored_job = db.execute("SELECT * FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        mapping = db.execute("SELECT * FROM swap_mappings WHERE swap_job_id=?", (job["id"],)).fetchone()
        assignment = db.execute(
            "SELECT status,qualification,live_status,replacement_ready_at,qualification_next_check_at "
            "FROM provider_assignments WHERE external_id='assignment-2'"
        ).fetchone()
    assert stored_job["state"] == "success"
    assert mapping["old_assignment_external_id"] == "assignment-1"
    assert mapping["new_assignment_external_id"] == "assignment-2"
    assert assignment is not None
    assert tuple(assignment[:3]) == ("active", "pending", "pending")
    assert assignment["replacement_ready_at"] == (reconciled_at + timedelta(seconds=60)).isoformat()
    assert assignment["qualification_next_check_at"] == assignment["replacement_ready_at"]


def test_success_invalidates_qualification_claim_taken_before_reconciliation(app):
    from app.services.proxiware_qualification import qualify_proxiware_assignment

    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = mutation_at + timedelta(seconds=1)
    stale_claim = "pre-reconciliation-claim"
    probe_calls: list[str] = []
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        job = _advance_to_provider_applied(db, now=mutation_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at)
        replacement_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-2'").fetchone()[
            "id"
        ]
        db.execute(
            "UPDATE provider_assignments SET qualification_claim_token=?, qualification_claimed_until=? WHERE id=?",
            (stale_claim, (reconciled_at + timedelta(minutes=15)).isoformat(), replacement_id),
        )
        db.commit()

        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )

        with pytest.raises(LookupError):
            qualify_proxiware_assignment(
                db,
                replacement_id,
                probe=lambda _proxy: probe_calls.append("probe") or {"status": "dead"},
                eligibility=lambda _proxy: {},
                now=reconciled_at + timedelta(seconds=2),
                claim_token=stale_claim,
            )
        row = db.execute(
            "SELECT qualification,live_status,qualification_claim_token,qualification_claimed_until "
            "FROM provider_assignments WHERE id=?",
            (replacement_id,),
        ).fetchone()

    assert probe_calls == []
    assert tuple(row) == ("pending", "pending", None, None)


def test_success_uses_configured_cooldown_but_never_less_than_sixty_seconds(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = success_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_cooldown_seconds", "120")
        job = _advance_to_provider_applied(db, now=success_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at)
        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )
        assignment = db.execute(
            "SELECT replacement_ready_at FROM provider_assignments WHERE external_id='assignment-2'"
        ).fetchone()
    assert assignment["replacement_ready_at"] == (reconciled_at + timedelta(seconds=120)).isoformat()


def test_success_deletes_old_assignment_and_keeps_swap_audit(app):
    success_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = success_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute(
            "UPDATE provider_assignments SET distribution_enabled=1 WHERE subscription_id=?",
            (sub_id,),
        )
        old_assignment_id = db.execute(
            "SELECT id FROM provider_assignments WHERE external_id='assignment-1'"
        ).fetchone()["id"]
        db.commit()
        job = _advance_to_provider_applied(db, now=success_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at)

        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )

        old_assignment = db.execute("SELECT id FROM provider_assignments WHERE id=?", (old_assignment_id,)).fetchone()
        replacement = db.execute(
            "SELECT id,external_id,status,qualification,live_status,provider_eligible,distribution_enabled "
            "FROM provider_assignments WHERE external_id='assignment-2'"
        ).fetchone()
        stored_job = db.execute(
            "SELECT state,old_assignment_id,new_assignment_id,mutation_old_assignment_external_id,"
            "mutation_new_assignment_external_id FROM swap_jobs WHERE id=?",
            (job["id"],),
        ).fetchone()
        mapping = db.execute(
            "SELECT old_assignment_external_id,new_assignment_external_id FROM swap_mappings WHERE swap_job_id=?",
            (job["id"],),
        ).fetchone()

    assert old_assignment is None
    assert tuple(replacement[1:]) == ("assignment-2", "active", "pending", "pending", 1, 0)
    assert tuple(stored_job) == ("success", old_assignment_id, replacement["id"], "assignment-1", "assignment-2")
    assert tuple(mapping) == ("assignment-1", "assignment-2")


def test_schema_repairs_a_successful_replacement_left_pending(app):
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute(
            "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,"
            "provider_eligible,live_status,replacement_ready_at,created_at,updated_at) "
            "VALUES(?,'proxiware','stuck-replacement','new.example',8080,'pending','pending',1,'pending',?,?,?)",
            (
                sub_id,
                datetime(2026, 9, 24, 12, 1, tzinfo=UTC).isoformat(),
                "2026-09-24T12:00:00+00:00",
                "2026-09-24T12:00:00+00:00",
            ),
        )
        replacement_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.execute(
            "INSERT INTO swap_jobs(provider,subscription_id,new_assignment_id,state,created_at,updated_at) "
            "VALUES('proxiware',?,?,'success',?,?)",
            (sub_id, replacement_id, "2026-09-24T12:00:00+00:00", "2026-09-24T12:00:00+00:00"),
        )
        db.commit()

        ensure_proxiware_swap_schema(db)
        row = db.execute(
            "SELECT status,qualification_next_check_at FROM provider_assignments WHERE id=?", (replacement_id,)
        ).fetchone()

    assert row["status"] == "active"
    assert row["qualification_next_check_at"] == "2026-09-24T12:01:00+00:00"


def test_requalified_risk_replacement_can_queue_the_next_auto_swap(app):
    from app.services.proxiware_qualification import qualify_proxiware_assignment

    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = mutation_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db, quota=2)
        job = _advance_to_provider_applied(db, now=mutation_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at)
        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )
        replacement_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-2'").fetchone()[
            "id"
        ]
        qualification_at = reconciled_at + timedelta(seconds=61)
        result = qualify_proxiware_assignment(
            db,
            replacement_id,
            probe=lambda _proxy: {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.92",
                "egress_trusted": True,
            },
            eligibility=lambda _proxy: {"verdict": "BLACKLIST", "reason": "earnapp_blacklist"},
            now=qualification_at,
            check_interval_seconds=3600,
        )
        queued = queue_eligible_swaps(db, now=qualification_at)

    assert result.qualification == "risk"
    assert queued == 1


def test_success_requires_worker_claim_and_decryptable_replacement_credentials(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = mutation_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        job = _advance_to_provider_applied(db, now=mutation_at)
        _seed_replacement_evidence(db, sub_id, observed_at=reconciled_at, username="", password="")

        with pytest.raises(ValueError, match="claim"):
            mark_swap_success(
                db,
                job["id"],
                old_assignment_external_id="assignment-1",
                new_assignment_external_id="assignment-2",
                success_at=reconciled_at,
            )
        with pytest.raises(SwapReconciliationPending, match="credential"):
            mark_swap_success(
                db,
                job["id"],
                old_assignment_external_id="assignment-1",
                new_assignment_external_id="assignment-2",
                success_at=reconciled_at,
                claim_token=job["claim_token"],
            )

        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        mapping = db.execute("SELECT id FROM swap_mappings WHERE swap_job_id=?", (job["id"],)).fetchone()
    assert stored["state"] == "provider_applied"
    assert mapping is None


def test_reconciliation_resolves_replacement_external_id_from_provider_new_address(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    reconciled_at = mutation_at + timedelta(seconds=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_provider_applied(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_address="51.194.85.9",
            applied_at=mutation_at,
            claim_token=job["claim_token"],
        )
        _seed_replacement_evidence(
            db,
            sub_id,
            external_id="official-replacement-id",
            observed_at=reconciled_at,
        )
        db.execute("UPDATE provider_assignments SET host='51.194.85.9' WHERE external_id='official-replacement-id'")
        db.commit()

        mark_swap_success(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            success_at=reconciled_at,
            claim_token=job["claim_token"],
        )
        stored = db.execute("SELECT state,new_assignment_id FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        mapping = db.execute("SELECT new_assignment_external_id FROM swap_mappings").fetchone()

    assert stored["state"] == "success"
    assert stored["new_assignment_id"]
    assert mapping["new_assignment_external_id"] == "official-replacement-id"


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
        mutation = db.execute("SELECT value FROM settings WHERE key='proxiware_allow_mutation'").fetchone()
        assert queue_eligible_swaps(db, now=now + timedelta(hours=1)) == 0
    assert job["state"] == "blocked"
    assert job["reason"] == "manual_action_required"
    assert setting["value"] == "0"
    assert mutation["value"] == "0"


def test_secret_storage_is_encrypted_write_only_and_blank_preserves(app):
    with app.app_context():
        db = get_db()
        save_provider_secret(db, "api_key", "secret-api-key")
        row = db.execute("SELECT * FROM provider_credentials WHERE name='api_key'").fetchone()
        assert row["secret_encrypted"] != "secret-api-key"
        assert get_provider_secret_metadata(db)["api_key"]["configured"] is True
        save_provider_secret(db, "api_key", "")
        assert db.execute("SELECT secret_encrypted FROM provider_credentials WHERE name='api_key'").fetchone()[0]


def test_active_swap_states_include_mutation_and_reconciliation():
    assert frozenset({"pending", "running", "mutating", "provider_applied", "reconciliation_required"}) == (
        ACTIVE_SWAP_STATES
    )


def test_expired_subscription_is_not_swap_eligible(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute(
            "UPDATE provider_subscriptions SET expires_at=?, status='active' WHERE id=?",
            (int((now - timedelta(seconds=1)).timestamp()), sub_id),
        )
        db.commit()

        assert SwapDecision.for_subscription(db, sub_id, now=now).reason == "manual_action_required"


def test_mutation_fence_is_not_reclaimed_or_canceled(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        job = claim_next_swap(db, now=now, claim_seconds=30)
        decision = revalidate_swap_job(
            db,
            job["id"],
            now=now,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        assert decision.allowed is True
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        assert stored["state"] == "mutating"
        assert claim_next_swap(db, now=now + timedelta(hours=1)) is None
        with pytest.raises(LookupError, match="terminal"):
            cancel_swap(db, job["id"], now=now + timedelta(seconds=1))
        assert db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()["state"] == "mutating"


def test_mutation_fence_invalidates_pre_mutation_dashboard_evidence(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute(
            "UPDATE provider_assignments SET distribution_enabled=1 WHERE subscription_id=?",
            (sub_id,),
        )
        db.commit()
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        job = claim_next_swap(db, now=now)
        revalidate_swap_job(
            db,
            job["id"],
            now=now,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        row = db.execute(
            "SELECT dashboard_assignment_id,dashboard_eligible,dashboard_connections,"
            "dashboard_observed_at,dashboard_source,distribution_enabled FROM provider_assignments "
            "WHERE subscription_id=?",
            (sub_id,),
        ).fetchone()

    assert tuple(row) == (None, None, None, None, "", 0)


def test_provider_response_requires_reconciliation_before_success(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        job = claim_next_swap(db, now=now)
        revalidate_swap_job(db, job["id"], now=now, claim_token=job["claim_token"], enter_mutation=True)
        mark_provider_applied(
            db,
            job["id"],
            old_assignment_external_id="assignment-1",
            new_assignment_external_id="assignment-2",
            applied_at=now,
            claim_token=job["claim_token"],
        )
        stored = db.execute("SELECT state,new_assignment_id FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        assert stored["state"] == "provider_applied"
        assert stored["new_assignment_id"] is None
        assert db.execute("SELECT COUNT(*) FROM swap_mappings WHERE swap_job_id=?", (job["id"],)).fetchone()[0] == 0
        assert db.execute("SELECT id FROM provider_assignments WHERE external_id='assignment-2'").fetchone() is None


def test_unknown_provider_outcome_requires_reconciliation_and_disables_auto_swap(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        job = claim_next_swap(db, now=now)
        revalidate_swap_job(db, job["id"], now=now, claim_token=job["claim_token"], enter_mutation=True)
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=now,
            claim_token=job["claim_token"],
        )
        stored = db.execute("SELECT state,error_code FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        setting = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()
    assert tuple(stored) == ("reconciliation_required", "provider_timeout")
    assert setting["value"] == "0"


def test_reconciliation_required_with_fresh_unchanged_identity_releases_subscription(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        # A later read-only sync and dashboard observation prove the original
        # assignment is still present with the same dashboard identity.
        db.execute(
            "UPDATE provider_assignments SET last_seen_at=?, dashboard_observed_at=?, "
            "dashboard_assignment_id='dashboard-1', dashboard_eligible=1, dashboard_connections=10, "
            "dashboard_source='provider_dashboard' WHERE subscription_id=?",
            (observed_at.isoformat(), observed_at.isoformat(), sub_id),
        )
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute(
            "SELECT state,reason,error_code,claim_token,claimed_until FROM swap_jobs WHERE id=?",
            (job["id"],),
        ).fetchone()
        batch_state = db.execute("SELECT state FROM swap_batches WHERE id=?", (job["batch_id"],)).fetchone()["state"]

    assert result["reconciled_no_provider_change"] == 1
    assert tuple(stored) == ("blocked", "reconciled_no_provider_change", "provider_timeout", None, None)
    assert batch_state == "complete"


def test_interrupted_batch_is_frozen_and_sync_is_queued(app):
    from app.services.proxiware_swap import recover_interrupted_swap_batches

    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        set_setting(db, "proxiware_auto_swap_intent", "1")
        set_setting(db, "proxiware_allow_mutation", "1")
        assert queue_eligible_swaps(db, now=now) == 1
        claimed = claim_next_swap_batch(db, now=now)[0]
        assert begin_swap_batch_mutation(db, batch_id=claimed["batch_id"], claim_token=claimed["claim_token"], now=now)
        db.execute("UPDATE swap_batches SET claimed_until=NULL WHERE id=?", (claimed["batch_id"],))
        assert recover_interrupted_swap_batches(db, now=now + timedelta(seconds=329)) == {
            "batches": 0,
            "jobs": 0,
        }
        db.commit()

        recovered = recover_interrupted_swap_batches(db, now=now + timedelta(seconds=331))
        job = db.execute("SELECT state,error_code FROM swap_jobs WHERE id=?", (claimed["id"],)).fetchone()
        batch = db.execute("SELECT state FROM swap_batches WHERE id=?", (claimed["batch_id"],)).fetchone()
        runtime = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()
        intent = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap_intent'").fetchone()
        from app.services.proxiware_credentials import restore_auto_swap_intent

        assert restore_auto_swap_intent(db, now=now + timedelta(seconds=331)) is False
        runtime_after_resume_attempt = db.execute(
            "SELECT value FROM settings WHERE key='proxiware_auto_swap'"
        ).fetchone()["value"]
        queued_syncs = db.execute(
            "SELECT COUNT(*) FROM provider_sync_runs WHERE provider='proxiware' AND status='queued'"
        ).fetchone()[0]
        claim_again = claim_next_swap_batch(db, now=now + timedelta(seconds=332))

    assert recovered == {"batches": 1, "jobs": 1}
    assert tuple(job) == ("reconciliation_required", "worker_restart_during_mutation")
    assert batch["state"] == "reconciling"
    assert runtime["value"] == "0"
    assert runtime_after_resume_attempt == "0"
    assert intent["value"] == "1"
    assert queued_syncs == 1
    assert claim_again == []


def test_reconciliation_required_ignores_unrelated_fresh_dashboard_assignment(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dashboard-1', dashboard_eligible=1, "
            "dashboard_connections=10, dashboard_observed_at=?, dashboard_source='provider_dashboard', "
            "last_seen_at=? WHERE subscription_id=? AND external_id='assignment-1'",
            (observed_at.isoformat(), observed_at.isoformat(), sub_id),
        )
        _seed_replacement_evidence(db, sub_id, observed_at=observed_at)
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["reconciled_no_provider_change"] == 1
    assert stored["state"] == "blocked"


def test_reconciliation_required_closes_unchanged_target_in_multi_assignment_subscription(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        db.execute("UPDATE provider_subscriptions SET quantity=2 WHERE id=?", (sub_id,))
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dashboard-1', dashboard_eligible=1, "
            "dashboard_connections=10, dashboard_observed_at=?, dashboard_source='provider_dashboard', "
            "last_seen_at=? WHERE subscription_id=? AND external_id='assignment-1'",
            (observed_at.isoformat(), observed_at.isoformat(), sub_id),
        )
        _seed_replacement_evidence(db, sub_id, observed_at=observed_at)
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["reconciled_no_provider_change"] == 1
    assert stored["state"] == "blocked"


def test_reconciliation_required_keeps_pending_until_dashboard_covers_fresh_api_candidate(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dashboard-1', dashboard_eligible=1, "
            "dashboard_connections=10, dashboard_observed_at=?, dashboard_source='provider_dashboard', "
            "last_seen_at=? WHERE subscription_id=? AND external_id='assignment-1'",
            (observed_at.isoformat(), observed_at.isoformat(), sub_id),
        )
        _seed_replacement_evidence(db, sub_id, observed_at=observed_at)
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id=NULL, dashboard_observed_at=NULL, "
            "dashboard_source='', last_seen_at=? WHERE external_id='assignment-2'",
            (observed_at.isoformat(),),
        )
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["pending"] == 1
    assert stored["state"] == "reconciliation_required"


def test_reconciliation_required_does_not_release_on_stale_no_change_evidence(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    evidence_at = mutation_at + timedelta(minutes=1)
    reconciled_at = mutation_at + timedelta(hours=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_dashboard_max_age_seconds", "300")
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id='dashboard-1', dashboard_eligible=1, "
            "dashboard_connections=10, dashboard_observed_at=?, dashboard_source='provider_dashboard', "
            "last_seen_at=? WHERE subscription_id=?",
            (evidence_at.isoformat(), evidence_at.isoformat(), sub_id),
        )
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=reconciled_at)
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["pending"] == 1
    assert stored["state"] == "reconciliation_required"


def test_reconciliation_required_can_finalize_after_fresh_replacement_evidence(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET missing_at=?, status='missing' WHERE external_id='assignment-1'",
            (observed_at.isoformat(),),
        )
        db.execute(
            "UPDATE swap_jobs SET mutation_new_assignment_external_id='assignment-2' WHERE id=?",
            (job["id"],),
        )
        _seed_replacement_evidence(db, sub_id, observed_at=observed_at)
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state,new_assignment_id FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["success"] == 1
    assert tuple(stored) == ("success", stored["new_assignment_id"])
    assert stored["new_assignment_id"] is not None


def test_reconciliation_required_resolves_single_fresh_replacement_without_provider_response(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET missing_at=?, status='missing' WHERE external_id='assignment-1'",
            (observed_at.isoformat(),),
        )
        db.execute(
            "UPDATE provider_subscriptions SET last_seen_at=? WHERE id=?",
            (observed_at.isoformat(), sub_id),
        )
        _seed_replacement_evidence(
            db,
            sub_id,
            observed_at=observed_at,
            dashboard_assignment_id="dashboard-1",
        )
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state,new_assignment_id FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["success"] == 1
    assert stored["state"] == "success"
    assert stored["new_assignment_id"] is not None


def test_reconciliation_required_does_not_infer_replacement_with_different_dashboard_identity(app):
    mutation_at = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    observed_at = mutation_at + timedelta(minutes=1)
    with app.app_context():
        db = get_db()
        sub_id = _seed_subscription(db)
        set_setting(db, "proxiware_auto_swap", "1")
        assert queue_eligible_swaps(db, now=mutation_at) == 1
        job = claim_next_swap(db, now=mutation_at)
        revalidate_swap_job(
            db,
            job["id"],
            now=mutation_at,
            claim_token=job["claim_token"],
            enter_mutation=True,
        )
        mark_reconciliation_required(
            db,
            job["id"],
            error_code="provider_timeout",
            required_at=mutation_at,
            claim_token=job["claim_token"],
        )
        db.execute(
            "UPDATE provider_assignments SET missing_at=?, status='missing' WHERE external_id='assignment-1'",
            (observed_at.isoformat(),),
        )
        db.execute(
            "UPDATE provider_subscriptions SET last_seen_at=? WHERE id=?",
            (observed_at.isoformat(), sub_id),
        )
        _seed_replacement_evidence(db, sub_id, observed_at=observed_at)
        db.commit()

        result = reconcile_provider_applied_swaps(db, now=observed_at)
        stored = db.execute("SELECT state,new_assignment_id FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()

    assert result["pending"] == 1
    assert stored["state"] == "reconciliation_required"
    assert stored["new_assignment_id"] is None


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
        assignment_id = db.execute("SELECT id FROM provider_assignments WHERE subscription_id=?", (sub_id,)).fetchone()[
            "id"
        ]
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
        assignment_id = db.execute("SELECT id FROM provider_assignments WHERE subscription_id=?", (sub_id,)).fetchone()[
            "id"
        ]
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
            revalidate_swap_job(
                db,
                stale["id"],
                now=now + timedelta(seconds=32),
                claim_token=stale["claim_token"],
                enter_mutation=True,
            )
        decision = revalidate_swap_job(
            db,
            current["id"],
            now=now + timedelta(seconds=32),
            claim_token=current["claim_token"],
            enter_mutation=True,
        )
        stored = db.execute("SELECT state FROM swap_jobs WHERE id=?", (current["id"],)).fetchone()
    assert decision.allowed is True
    assert stored["state"] == "mutating"


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
        _seed_subscription(db)
        job = _advance_to_provider_applied(db, now=success_at, new_external_id="foreign-new")
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
                success_at=success_at + timedelta(seconds=1),
                claim_token=job["claim_token"],
            )

        stored_job = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job["id"],)).fetchone()
        mapping = db.execute("SELECT id FROM swap_mappings WHERE swap_job_id=?", (job["id"],)).fetchone()
    assert stored_job["state"] == "provider_applied"
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
