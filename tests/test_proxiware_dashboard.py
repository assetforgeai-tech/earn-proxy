from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.services.proxiware import sync_proxiware_inventory
from app.services.proxiware_dashboard import (
    DashboardObservationError,
    ProxiwareDashboardObserver,
    apply_dashboard_observation,
)


class FakeClient:
    def list_subscriptions(self, _network="isp"):
        return [{"id": 39277, "network": "isp", "location": "us", "quantity": 1}]

    def list_subscription_proxies(self, _subscription_id):
        return [
            {
                "id": "api-assignment",
                "host": "51.194.85.8",
                "port": 1337,
                "username": "user",
                "password": "pass",
                "protocol": "socks5",
            }
        ]


class RecordingTransport:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def request_json(self, method, path, *, body=None):
        self.calls.append((method, path, body))
        return self.payload


def test_observer_normalizes_only_safe_dashboard_fields():
    transport = RecordingTransport(
        {
            "proxies": [
                {
                    "assignment_id": 141943,
                    "subscription_id": 39277,
                    "addr": "51.194.85.8",
                    "eligible": True,
                    "connections": 5,
                    "username": "must-not-be-returned",
                    "password": "must-not-be-returned",
                }
            ],
            "swap_connection_limit": 1000,
        }
    )

    rows = ProxiwareDashboardObserver(transport).observe(subscription_id="39277")

    assert transport.calls == [("GET", "/api/static/networks/isp/proxies", None)]
    assert len(rows) == 1
    assert rows[0].assignment_id == "141943"
    assert rows[0].subscription_id == "39277"
    assert rows[0].address == "51.194.85.8"
    assert rows[0].eligible is True
    assert rows[0].connections == 5
    assert "password" not in repr(rows[0]).lower()
    assert "username" not in repr(rows[0]).lower()


def test_apply_dashboard_observation_maps_assignment_and_records_freshness(app):
    observed_at = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    transport = RecordingTransport(
        {
            "proxies": [
                {
                    "assignment_id": 141943,
                    "subscription_id": 39277,
                    "addr": "51.194.85.8",
                    "eligible": True,
                    "connections": 5,
                }
            ]
        }
    )
    snapshot = ProxiwareDashboardObserver(transport, now=lambda: observed_at).observe(subscription_id="39277")[0]

    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(db, FakeClient(), now=observed_at)
        assignment_id = apply_dashboard_observation(db, snapshot, now=observed_at)
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()

    assert row["dashboard_assignment_id"] == "141943"
    assert row["dashboard_eligible"] == 1
    assert row["dashboard_connections"] == 5
    assert row["dashboard_observed_at"] == observed_at.isoformat()
    assert row["dashboard_source"] == "provider_dashboard"
    assert row["provider_eligible"] == 1


def test_official_api_sync_cannot_overwrite_fresh_dashboard_observation(app):
    observed_at = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    snapshot = ProxiwareDashboardObserver(
        RecordingTransport(
            {
                "proxies": [
                    {
                        "assignment_id": 141943,
                        "subscription_id": 39277,
                        "addr": "51.194.85.8",
                        "eligible": True,
                        "connections": 5,
                    }
                ]
            }
        ),
        now=lambda: observed_at,
    ).observe(subscription_id="39277")[0]

    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(db, FakeClient(), now=observed_at)
        apply_dashboard_observation(db, snapshot, now=observed_at)
        sync_proxiware_inventory(db, FakeClient(), now=observed_at + timedelta(minutes=5))
        row = db.execute(
            "SELECT dashboard_assignment_id,dashboard_eligible,dashboard_connections,dashboard_observed_at "
            "FROM provider_assignments WHERE external_id='api-assignment'"
        ).fetchone()

    assert tuple(row) == ("141943", 1, 5, observed_at.isoformat())


def test_identity_change_invalidates_dashboard_observation(app):
    observed_at = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    snapshot = ProxiwareDashboardObserver(
        RecordingTransport(
            {
                "proxies": [
                    {
                        "assignment_id": 141943,
                        "subscription_id": 39277,
                        "addr": "51.194.85.8",
                        "eligible": True,
                        "connections": 5,
                    }
                ]
            }
        ),
        now=lambda: observed_at,
    ).observe(subscription_id="39277")[0]

    class ReplacementClient(FakeClient):
        def list_subscription_proxies(self, _subscription_id):
            row = super().list_subscription_proxies(_subscription_id)[0]
            return [{**row, "host": "51.194.85.9"}]

    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(db, FakeClient(), now=observed_at)
        apply_dashboard_observation(db, snapshot, now=observed_at)
        sync_proxiware_inventory(db, ReplacementClient(), now=observed_at + timedelta(minutes=5))
        row = db.execute(
            "SELECT dashboard_assignment_id,dashboard_eligible,dashboard_connections,dashboard_observed_at "
            "FROM provider_assignments WHERE external_id='api-assignment'"
        ).fetchone()

    assert tuple(row) == (None, None, None, None)


@pytest.mark.parametrize(
    "payload",
    [
        {"proxies": [{"assignment_id": 1, "subscription_id": 39277, "addr": "", "eligible": True}]},
        {"proxies": [{"assignment_id": 1, "subscription_id": 39277, "addr": "51.194.85.8", "connections": -1}]},
    ],
)
def test_observer_rejects_invalid_payload(payload):
    with pytest.raises(DashboardObservationError):
        ProxiwareDashboardObserver(RecordingTransport(payload)).observe(subscription_id="39277")


def test_observer_ignores_rows_from_other_subscriptions():
    rows = ProxiwareDashboardObserver(
        RecordingTransport(
            {"proxies": [{"assignment_id": 1, "subscription_id": 99999, "addr": "51.194.85.8"}]}
        )
    ).observe(subscription_id="39277")

    assert rows == []
