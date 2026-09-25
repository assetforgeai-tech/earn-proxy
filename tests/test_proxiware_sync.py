from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import app.services.proxiware as proxiware_service
from app.crypto import decrypt_secret
from app.db import get_db
from app.services.proxiware import (
    SyncAlreadyRunning,
    SyncCancelled,
    SyncLeaseLost,
    SyncResult,
    claim_sync_run,
    enqueue_sync_run,
    request_sync_cancel,
    sync_proxiware_inventory,
)


class FakeClient:
    def __init__(self, subscriptions, proxies, *, fail=False):
        self.subscriptions = subscriptions
        self.proxies = proxies
        self.fail = fail

    def list_subscriptions(self, network="isp"):
        if self.fail:
            raise RuntimeError("provider unavailable")
        return self.subscriptions

    def list_subscription_proxies(self, subscription_id):
        if self.fail:
            raise RuntimeError("provider unavailable")
        return self.proxies.get(int(subscription_id), [])


def _client():
    return FakeClient(
        [
            {
                "id": 10,
                "network": "isp",
                "location": "us",
                "quantity": 2,
                "expires_at": 1_800_000_000,
                "auto_renew": False,
                "status": "active",
                "eligible": 900,
                "connections": 2,
            }
        ],
        {
            10: [
                {
                    "id": 100,
                    "host": "proxy.example",
                    "port": 41000,
                    "username": "user",
                    "password": "pass",
                    "country": "US",
                }
            ]
        },
    )


def test_first_sync_persists_subscription_assignment_and_run(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        result = sync_proxiware_inventory(get_db(), _client(), now=now)
        assert isinstance(result, SyncResult)
        assert result.added == 2
        assert result.updated == 0
        assert result.missing == 0
        assert result.errors == 0

        subscription = get_db().execute("SELECT * FROM provider_subscriptions").fetchone()
        assignment = get_db().execute("SELECT * FROM provider_assignments").fetchone()
        run = get_db().execute("SELECT * FROM provider_sync_runs").fetchone()

        assert decrypt_secret(assignment["username_encrypted"]) == "user"
        assert decrypt_secret(assignment["password_encrypted"]) == "pass"

    assert subscription["provider"] == "proxiware"
    assert subscription["external_id"] == "10"
    assert subscription["eligible_count"] == 900
    assert assignment["external_id"] == "100"
    assert assignment["subscription_id"] == subscription["id"]
    assert run["status"] == "success"
    assert run["added_count"] == 2


def test_sync_records_elapsed_duration(app, monkeypatch):
    ticks = iter((100.0, 100.125))
    monkeypatch.setattr("app.services.proxiware.monotonic", lambda: next(ticks))
    with app.app_context():
        sync_proxiware_inventory(get_db(), _client())
        run = get_db().execute("SELECT duration_ms FROM provider_sync_runs").fetchone()
    assert run["duration_ms"] == 125


def test_repeated_sync_is_idempotent(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        first = sync_proxiware_inventory(get_db(), _client(), now=now)
        second = sync_proxiware_inventory(get_db(), _client(), now=now)
        assert first.added == 2
        assert second.added == 0
        assert second.updated == 0
        assert get_db().execute("SELECT COUNT(*) AS n FROM provider_subscriptions").fetchone()["n"] == 1
        assert get_db().execute("SELECT COUNT(*) AS n FROM provider_assignments").fetchone()["n"] == 1


def test_sync_marks_removed_records_missing_without_deleting_them(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        sync_proxiware_inventory(get_db(), _client(), now=now)
        result = sync_proxiware_inventory(
            get_db(),
            FakeClient([], {}),
            now=datetime(2026, 9, 24, 13, 0, tzinfo=UTC),
        )
        subscription = get_db().execute("SELECT status, missing_at FROM provider_subscriptions").fetchone()
        assignment = get_db().execute("SELECT status, missing_at FROM provider_assignments").fetchone()

    assert result.missing == 2
    assert subscription["status"] == "missing"
    assert subscription["missing_at"]
    assert assignment["status"] == "missing"
    assert assignment["missing_at"]


def test_malformed_rows_are_counted_and_valid_rows_still_sync(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    client = FakeClient(
        [{"id": 10, "network": "isp"}, {"network": "isp"}],
        {10: [{"id": 100, "host": "proxy.example", "port": 41000}, {"id": 101, "port": 41001}]},
    )
    with app.app_context():
        result = sync_proxiware_inventory(get_db(), client, now=now)
        assert result.added == 2
        assert result.errors == 2
        assert get_db().execute("SELECT COUNT(*) AS n FROM provider_subscriptions").fetchone()["n"] == 1
        assert get_db().execute("SELECT COUNT(*) AS n FROM provider_assignments").fetchone()["n"] == 1


def test_missing_provider_eligibility_fails_closed(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        result = sync_proxiware_inventory(
            get_db(),
            FakeClient(
                [{"id": 10, "network": "isp"}],
                {10: [{"id": 100, "host": "proxy.example", "port": 41000}]},
            ),
            now=now,
        )
        row = get_db().execute("SELECT provider_eligible FROM provider_assignments").fetchone()

    assert result.errors == 0
    assert row["provider_eligible"] == 0


def test_provider_failure_rolls_back_inventory_and_records_failed_run(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        with pytest.raises(RuntimeError):
            sync_proxiware_inventory(get_db(), FakeClient([], {}, fail=True), now=now)
        assert get_db().execute("SELECT COUNT(*) AS n FROM provider_subscriptions").fetchone()["n"] == 0
        run = get_db().execute("SELECT status, error_code FROM provider_sync_runs").fetchone()

    assert run["status"] == "failed"
    assert run["error_code"] == "provider_error"


def test_sync_claim_is_single_owner_and_cancel_is_durable(app):
    with app.app_context():
        db = get_db()
        first = claim_sync_run(db)
        assert first is not None
        assert claim_sync_run(db) is None
        assert request_sync_cancel(db, first["run_id"]) is True
        row = db.execute("SELECT cancel_requested FROM provider_sync_runs WHERE id=?", (first["run_id"],)).fetchone()
        assert row["cancel_requested"] == 1


def test_sync_reports_already_running_without_provider_call(app):
    with app.app_context():
        db = get_db()
        claim_sync_run(db)
        with pytest.raises(SyncAlreadyRunning):
            sync_proxiware_inventory(db, _client())


def test_sync_claim_recovers_running_row_without_lease(app):
    old = datetime(2026, 9, 24, 10, 0, tzinfo=UTC).isoformat()
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO provider_sync_runs(provider,started_at,status,claimed_until) VALUES('proxiware',?,'running',NULL)",
            (old,),
        )
        db.commit()
        claim = claim_sync_run(db, now=datetime(2026, 9, 24, 12, 0, tzinfo=UTC), lease_seconds=60)
        rows = db.execute("SELECT status,error_code FROM provider_sync_runs ORDER BY id").fetchall()

    assert claim is not None
    assert rows[0]["status"] == "failed"
    assert rows[0]["error_code"] == "lease_expired"


def test_sync_claim_reaps_expired_lease(app):
    old = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        stale = claim_sync_run(db, now=old, lease_seconds=60)
        claim = claim_sync_run(db, now=old.replace(hour=12), lease_seconds=60)
        row = db.execute("SELECT status,error_code FROM provider_sync_runs WHERE id=?", (stale["run_id"],)).fetchone()

    assert claim is not None
    assert row["status"] == "failed"
    assert row["error_code"] == "lease_expired"


def test_stale_sync_owner_cannot_finalize_after_lease_reclaim(app, monkeypatch):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    original_claim = proxiware_service.claim_sync_run

    def short_claim(db, *, now=None, **kwargs):
        return original_claim(db, now=now, lease_seconds=60, **kwargs)

    monkeypatch.setattr(proxiware_service, "claim_sync_run", short_claim)

    class ReclaimClient(FakeClient):
        def list_subscription_proxies(self, subscription_id):
            with app.app_context():
                reclaimed = original_claim(get_db(), now=now + timedelta(seconds=61), lease_seconds=60)
                assert reclaimed is not None
            return super().list_subscription_proxies(subscription_id)

    with app.app_context():
        with pytest.raises(SyncLeaseLost):
            sync_proxiware_inventory(
                get_db(),
                ReclaimClient(
                    [{"id": 10, "network": "isp"}],
                    {10: [{"id": 100, "host": "stale.example", "port": 8080}]},
                ),
                now=now,
            )
        rows = get_db().execute("SELECT id,status,error_code FROM provider_sync_runs ORDER BY id").fetchall()
        inventory_count = get_db().execute("SELECT COUNT(*) AS count FROM provider_subscriptions").fetchone()["count"]

    assert tuple(rows[0]) == (1, "failed", "lease_expired")
    assert tuple(rows[1]) == (2, "running", "")
    assert inventory_count == 0


def test_sync_cancel_does_not_mark_inventory_success(app):
    class CancelClient(FakeClient):
        def list_subscriptions(self, network="isp"):
            with app.app_context():
                db = get_db()
                row = db.execute(
                    "SELECT id FROM provider_sync_runs WHERE provider='proxiware' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                request_sync_cancel(db, row["id"])
            return super().list_subscriptions(network)

    with app.app_context():
        db = get_db()
        with pytest.raises(SyncCancelled):
            sync_proxiware_inventory(db, CancelClient([], {}))
        row = db.execute("SELECT status,cancel_requested FROM provider_sync_runs ORDER BY id DESC LIMIT 1").fetchone()
        assert row["status"] == "canceled"
        assert row["cancel_requested"] == 1


def test_sync_persists_each_subscription_before_fetching_the_next(app):
    subscriptions = [{"id": 10, "network": "isp"}, {"id": 20, "network": "isp"}]
    proxies = {
        10: [{"id": 100, "host": "first.example", "port": 41000}],
        20: [{"id": 200, "host": "second.example", "port": 42000}],
    }

    class StreamingClient(FakeClient):
        def list_subscription_proxies(self, subscription_id):
            if int(subscription_id) == 20:
                count = (
                    get_db()
                    .execute("SELECT COUNT(*) AS count FROM provider_assignments WHERE external_id='100'")
                    .fetchone()["count"]
                )
                assert count == 1
            return super().list_subscription_proxies(subscription_id)

    with app.app_context():
        result = sync_proxiware_inventory(get_db(), StreamingClient(subscriptions, proxies))

    assert result.added == 4


def test_sync_does_not_reset_local_qualification_when_provider_omits_probe_fields(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(db, _client(), now=now)
        db.execute(
            "UPDATE provider_assignments SET live_status='live', qualification='allow', "
            "provider_eligible=1, exit_ip='203.0.113.10', duplicate_egress=0, distribution_enabled=1"
        )
        db.commit()
        sync_proxiware_inventory(db, _client(), now=now.replace(hour=13))
        row = db.execute(
            "SELECT live_status,qualification,provider_eligible,exit_ip,distribution_enabled FROM provider_assignments"
        ).fetchone()

    assert tuple(row) == ("live", "allow", 1, "203.0.113.10", 1)


def test_enqueued_sync_is_claimed_by_inventory_worker(app):
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        queued = enqueue_sync_run(db, now=now)
        assert queued is not None
        assert queued["status"] == "queued"

        result = sync_proxiware_inventory(db, _client(), now=now)
        row = db.execute(
            "SELECT status,claim_token,claimed_until FROM provider_sync_runs WHERE id=?",
            (queued["run_id"],),
        ).fetchone()

    assert result.run_id == queued["run_id"]
    assert tuple(row) == ("success", None, None)


def test_only_one_queued_or_running_sync_is_allowed(app):
    with app.app_context():
        db = get_db()
        first = enqueue_sync_run(db)
        second = enqueue_sync_run(db)

    assert first is not None
    assert second is None


def test_queued_sync_can_be_canceled_before_worker_claims_it(app):
    with app.app_context():
        db = get_db()
        queued = enqueue_sync_run(db)
        assert request_sync_cancel(db, queued["run_id"]) is True
        row = db.execute(
            "SELECT status,cancel_requested FROM provider_sync_runs WHERE id=?",
            (queued["run_id"],),
        ).fetchone()

    assert tuple(row) == ("canceled", 1)
