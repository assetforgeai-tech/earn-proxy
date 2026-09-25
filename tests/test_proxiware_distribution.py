from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.crypto import encrypt_secret
from app.db import get_db
from app.services.proxies import add_proxy, reconcile_exit_ip
from app.services.proxiware_qualification import _ensure_columns
from app.services.settings import set_setting
from app.services.users import create_user


def _assignment(db, *, exit_ip="198.51.100.80", duplicate=0, qualification="allow"):
    _ensure_columns(db)
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,created_at,updated_at) "
        "VALUES('proxiware','sub-feed','active',?,?,?,?)",
        (now, now, now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        """
        INSERT INTO provider_assignments(
            subscription_id,provider,external_id,host,port,username_encrypted,password_encrypted,
            status,qualification,provider_eligible,live_status,exit_ip,assigned_at,last_seen_at,
            created_at,updated_at,protocol,last_checked_at,egress_verified_at,duplicate_egress,
            distribution_enabled
        ) VALUES(?, 'proxiware','feed-1','provider-feed.example',9000,?,?, 'active',?,1,'live',?,?,?,?,?,'socks5',?,?,?,1)
        """,
        (
            sub_id,
            encrypt_secret("provider-user"),
            encrypt_secret("provider-pass"),
            qualification,
            exit_ip,
            now,
            now,
            now,
            now,
            now,
            now,
            duplicate,
        ),
    )
    db.commit()


def test_provider_proxy_is_exported_only_when_admin_distribution_toggle_is_on(app, client):
    with app.app_context():
        db = get_db()
        _assignment(db)

    headers = {"X-API-Key": "internal-test-key"}
    assert client.get("/api/v1/proxy-raw", headers=headers).get_data(as_text=True) == ""

    with app.app_context():
        set_setting(get_db(), "proxiware_distribution_enabled", "1")
    response = client.get("/api/v1/proxy-raw?format=json", headers=headers)

    assert response.status_code == 200
    assert response.get_json() == [
        {
            "endpoint": "provider-feed.example:9000",
            "protocol": "socks5",
            "raw": "provider-feed.example:9000:provider-user:provider-pass",
            "status": "Allow",
            "type": "raw",
        }
    ]


def test_provider_duplicate_or_risk_proxy_is_never_exported(app, client):
    with app.app_context():
        db = get_db()
        _assignment(db, duplicate=1)
        set_setting(db, "proxiware_distribution_enabled", "1")

    response = client.get("/api/v1/proxy-raw", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True) == ""


def test_distribution_query_fails_closed_for_late_user_egress_duplicate(app, client):
    with app.app_context():
        db = get_db()
        _assignment(db, exit_ip="198.51.100.81")
        user_id = create_user(db, "global-duplicate@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "user-duplicate.example:8000:user:pass")
        db.execute("UPDATE proxies SET status='online', eligibility='allow' WHERE id=?", (proxy_id,))
        reconcile_exit_ip(db, proxy_id, "198.51.100.81", attestation_source="https_quorum")
        # Simulate a stale provider flag to prove the export query itself is a
        # final safety boundary, not just a cache of reconciliation state.
        db.execute("UPDATE provider_assignments SET duplicate_egress=0, distribution_enabled=1")
        db.commit()
        set_setting(db, "proxiware_distribution_enabled", "1")

    response = client.get("/api/v1/proxy-raw", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True) == ""


def test_provider_proxy_in_replacement_cooldown_is_never_exported(app, client):
    with app.app_context():
        db = get_db()
        _assignment(db)
        db.execute(
            "UPDATE provider_assignments SET replacement_ready_at=?",
            ((datetime.now(UTC) + timedelta(minutes=5)).isoformat(),),
        )
        db.commit()
        set_setting(db, "proxiware_distribution_enabled", "1")

    response = client.get("/api/v1/proxy-raw", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True) == ""


def test_provider_proxy_with_active_swap_job_is_never_exported(app, client):
    with app.app_context():
        db = get_db()
        _assignment(db)
        assignment = db.execute("SELECT id,subscription_id FROM provider_assignments").fetchone()
        now = datetime.now(UTC).isoformat()
        db.execute(
            """
            INSERT INTO swap_jobs(
                provider,subscription_id,old_assignment_id,state,reason,created_at,updated_at
            ) VALUES('proxiware',?,?, 'pending','queued',?,?)
            """,
            (assignment["subscription_id"], assignment["id"], now, now),
        )
        db.commit()
        set_setting(db, "proxiware_distribution_enabled", "1")

    response = client.get("/api/v1/proxy-raw", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True) == ""
