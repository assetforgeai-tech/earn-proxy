from __future__ import annotations

from datetime import UTC, datetime

from app.db import get_db
from app.services.proxies import add_proxy, reconcile_exit_ip
from app.services.proxiware_qualification import qualify_proxiware_assignment
from app.services.proxiware_swap import ensure_proxiware_swap_schema
from app.services.users import create_user


def _provider_assignment(db, external_id="provider-1", host="provider.example"):
    ensure_proxiware_swap_schema(db)
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    db.execute(
        """
        INSERT INTO provider_subscriptions
            (provider, external_id, status, first_seen_at, last_seen_at, created_at, updated_at)
        VALUES ('proxiware','sub-qual','active',?,?,?,?)
        """,
        (now, now, now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        """
        INSERT INTO provider_assignments
            (subscription_id, provider, external_id, host, port, username_encrypted,
             password_encrypted, status, qualification, provider_eligible, live_status,
             assigned_at, last_seen_at, created_at, updated_at,dashboard_assignment_id,
             dashboard_eligible,dashboard_connections,dashboard_observed_at,dashboard_source)
        VALUES (?, 'proxiware', ?, ?, 8080, '', '', 'active', 'pending', 1, 'pending', ?, ?, ?, ?,
                'dashboard-qualification',1,10,?,'provider_dashboard')
        """,
        (sub_id, external_id, host, now, now, now, now, now),
    )
    db.commit()
    return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def test_live_allow_assignment_becomes_distribution_eligible(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db)
        result = qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.10",
                "egress_trusted": True,
            },
            eligibility=lambda _proxy: {"verdict": "CID_SET", "reason": ""},
        )
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()

    assert result.qualification == "allow"
    assert row["live_status"] == "live"
    assert row["qualification"] == "allow"
    assert row["exit_ip"] == "198.51.100.10"
    assert row["distribution_enabled"] == 1


def test_inconclusive_probe_stays_pending_and_not_distribution_eligible(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db)
        result = qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {"status": "inconclusive", "failure_kind": "probe_endpoint"},
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()

    assert result.qualification == "pending"
    assert row["live_status"] == "inconclusive"
    assert row["qualification"] == "pending"
    assert row["distribution_enabled"] == 0


def test_provider_duplicate_egress_is_checked_against_user_inventory(app):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "owner@example.com", "password", status="active")
        user_proxy_id = add_proxy(db, user_id, "user.example:8080:user:pass")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', exit_ip=?, "
            "egress_attestation_source='https_quorum', egress_verified_at=? WHERE id=?",
            ("198.51.100.20", datetime.now(UTC).isoformat(), user_proxy_id),
        )
        assignment_id = _provider_assignment(db, host="provider-duplicate.example")
        result = qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {"status": "live", "exit_ip": "198.51.100.20", "egress_trusted": True},
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()

    assert result.reason == "duplicate_egress"
    assert row["duplicate_egress"] == 1
    assert row["distribution_enabled"] == 0


def test_provider_qualification_does_not_create_user_earnings(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db)
        qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {"status": "live", "exit_ip": "198.51.100.30", "egress_trusted": True},
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )
        count = db.execute("SELECT COUNT(*) AS count FROM earnings_ledger").fetchone()["count"]

    assert count == 0


def test_provider_allow_is_not_distributed_when_provider_marks_assignment_ineligible(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db, external_id="provider-ineligible")
        db.execute("UPDATE provider_assignments SET provider_eligible=0 WHERE id=?", (assignment_id,))
        db.commit()
        result = qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.77",
                "egress_trusted": True,
            },
            eligibility=lambda _proxy: {"verdict": "CID_SET", "reason": "eligible"},
        )
        row = db.execute(
            "SELECT distribution_enabled FROM provider_assignments WHERE id=?", (assignment_id,)
        ).fetchone()

    assert result.qualification == "allow"
    assert result.distribution_enabled is False
    assert row["distribution_enabled"] == 0


def test_unknown_provider_protocol_is_passed_to_auto_detection(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db, external_id="provider-auto")
        observed = {}

        def probe(proxy):
            observed["protocol"] = proxy["protocol"]
            return {
                "status": "live",
                "protocol": "socks5",
                "exit_ip": "198.51.100.40",
                "egress_trusted": True,
            }

        qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=probe,
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )

    assert observed["protocol"] == "auto"


def test_provider_qualification_works_with_provider_only_database(app, tmp_path):
    # The provider worker must not require the user-inventory table when run
    # against an isolated provider database.
    import sqlite3

    database = tmp_path / "provider-only.db"
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")
    connection.commit()
    connection.close()
    isolated = app.config.copy()
    isolated.update({"DATABASE": str(database), "TESTING": True})
    from app import create_app

    provider_app = create_app(isolated)
    with provider_app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db, external_id="provider-only")
        result = qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {"status": "live", "exit_ip": "198.51.100.44", "egress_trusted": True},
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )

    assert result.qualification == "allow"


def test_provider_duplicate_is_global_when_user_is_added_after_provider(app):
    with app.app_context():
        db = get_db()
        assignment_id = _provider_assignment(db, external_id="provider-first")
        qualify_proxiware_assignment(
            db,
            assignment_id,
            probe=lambda _proxy: {
                "status": "live",
                "exit_ip": "198.51.100.41",
                "egress_trusted": True,
            },
            eligibility=lambda _proxy: {"verdict": "CID_SET"},
        )
        user_id = create_user(db, "late-user@example.com", "password", status="active")
        user_proxy_id = add_proxy(db, user_id, "late-user.example:8080:user:pass")
        db.execute("UPDATE proxies SET status='online', eligibility='allow' WHERE id=?", (user_proxy_id,))
        reconcile_exit_ip(db, user_proxy_id, "198.51.100.41", attestation_source="https_quorum")

        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()
        # A later user identity must make the provider record non-distributable
        # even though the provider qualification happened first.
        assert row["duplicate_egress"] == 1
        assert row["distribution_enabled"] == 0
