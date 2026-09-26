from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from time import sleep

from app.db import get_db
from app.proxiware_browser_service import ProxiwareBrowserRunner
from app.services.proxiware import sync_proxiware_inventory
from app.services.proxiware_credentials import store_provider_session
from app.services.proxiware_dashboard import DashboardAssignment
from app.services.proxiware_swap import ensure_proxiware_swap_schema


class FakeClient:
    def list_subscriptions(self, _network="isp"):
        return [{"id": 39277, "network": "isp", "location": "us", "quantity": 1}]

    def list_subscription_proxies(self, _subscription_id):
        return [{"id": "api-assignment", "host": "51.194.85.8", "port": 1337, "protocol": "socks5"}]


def _seed_inventory(app, now: datetime) -> None:
    with app.app_context():
        sync_proxiware_inventory(get_db(), FakeClient(), now=now)


def _seed_session(app, now: datetime) -> None:
    with app.app_context():
        store_provider_session(
            get_db(),
            [{"name": "session", "value": "opaque"}],
            expires_at=now + timedelta(hours=1),
            now=now,
        )


def test_browser_runner_applies_scoped_dashboard_snapshot(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)

    class Adapter:
        def restore_session(self, cookies):
            assert cookies == [{"name": "session", "value": "opaque"}]

        def observe_dashboard(self, *, subscription_id):
            assert subscription_id == "39277"
            return [
                DashboardAssignment(
                    assignment_id="dashboard-1",
                    subscription_id="39277",
                    address="51.194.85.8",
                    eligible=True,
                    connections=12,
                    observed_at=now,
                )
            ]

        def swap_assignment(self, _job):
            raise AssertionError("observation worker must not mutate provider")

    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now)

    assert runner.run_once() == {"status": "ok", "observed": 1, "subscriptions": 1}
    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT dashboard_assignment_id,dashboard_eligible,dashboard_connections "
                "FROM provider_assignments WHERE external_id='api-assignment'"
            )
            .fetchone()
        )
    assert tuple(row) == ("dashboard-1", 1, 12)


def test_browser_runner_fails_closed_when_adapter_is_missing(app):
    now = datetime.now(UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)
    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: None)

    assert runner.run_once() == {"status": "manual_action_required", "observed": 0, "subscriptions": 1}
    with app.app_context():
        value = (
            get_db()
            .execute("SELECT value FROM settings WHERE key='proxiware_browser_worker_status'")
            .fetchone()["value"]
        )
    assert value == "manual_action_required"


def test_browser_observer_never_builds_a_mutation_capable_adapter(app, monkeypatch):
    app.config.update(
        PROXIWARE_BROWSER_ENABLED=True,
        PROXIWARE_BROWSER_ALLOW_MUTATION=True,
    )
    captured = {}

    def build(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("app.proxiware_browser_service.build_browser_adapter", build)

    ProxiwareBrowserRunner(app=app)._configured_adapter()

    assert captured["allow_mutation"] is False


def test_browser_runner_blocks_expired_provider_session(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        expired = (now - timedelta(minutes=1)).isoformat()
        db.execute(
            "INSERT INTO provider_sessions(provider,state,expires_at,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET state=excluded.state,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
            ("proxiware", "active", expired, now.isoformat()),
        )
        db.commit()

    calls = []
    runner = ProxiwareBrowserRunner(
        app=app,
        adapter_factory=lambda: calls.append("created") or object(),
        now=lambda: now,
    )

    assert runner.run_once() == {"status": "manual_action_required", "observed": 0, "subscriptions": 1}
    assert calls == []


def test_browser_runner_marks_corrupt_session_as_manual_action_required(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        db.execute(
            "INSERT INTO provider_sessions(provider,state,cookie_encrypted,expires_at,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET state=excluded.state,cookie_encrypted=excluded.cookie_encrypted,"
            "expires_at=excluded.expires_at,updated_at=excluded.updated_at",
            ("proxiware", "active", "not-a-fernet-token", (now + timedelta(hours=1)).isoformat(), now.isoformat()),
        )
        db.commit()

    result = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: object(), now=lambda: now).run_once()

    assert result["status"] == "manual_action_required"
    with app.app_context():
        row = (
            get_db()
            .execute("SELECT state,last_error_code FROM provider_sessions WHERE provider='proxiware'")
            .fetchone()
        )
    assert tuple(row) == ("manual_action_required", "invalid_session")


def test_browser_runner_idle_sleep_refreshes_heartbeat(app):
    runner = ProxiwareBrowserRunner(app=app, interval_seconds=120)
    runner._stop.wait = lambda _seconds: True

    runner._wait_with_heartbeat(120)

    with app.app_context():
        values = dict(
            get_db().execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_browser_worker_%'").fetchall()
        )
    assert values["proxiware_browser_worker_status"] == "sleeping"
    assert values["proxiware_browser_worker_heartbeat_at"]


def test_browser_runner_rejects_cross_subscription_snapshot(app, monkeypatch):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)

    applied = []
    monkeypatch.setattr(
        "app.proxiware_browser_service.apply_dashboard_snapshot",
        lambda _db, _subscription_id, snapshots, **_kwargs: applied.extend(snapshots),
    )

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            assert subscription_id == "39277"
            return [
                DashboardAssignment(
                    assignment_id="wrong-subscription-assignment",
                    subscription_id="other-subscription",
                    address="51.194.85.8:1337",
                    eligible=True,
                    connections=1,
                    observed_at=now,
                )
            ]

    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now)

    result = runner.run_once()

    assert result["status"] == "manual_action_required"
    assert applied == []
    with app.app_context():
        row = (
            get_db()
            .execute("SELECT dashboard_assignment_id FROM provider_assignments WHERE external_id='api-assignment'")
            .fetchone()
        )
    assert row["dashboard_assignment_id"] is None


def test_browser_runner_empty_snapshot_is_degraded_not_success(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            assert subscription_id == "39277"
            return []

    result = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now).run_once()

    assert result == {"status": "degraded", "observed": 0, "subscriptions": 1, "error_code": "empty_snapshot"}
    with app.app_context():
        session = get_db().execute("SELECT state FROM provider_sessions WHERE provider='proxiware'").fetchone()
    assert session["state"] == "active"


def test_browser_runner_transport_failure_is_degraded_without_expiring_session(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            raise TimeoutError("provider timeout")

    result = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now).run_once()

    assert result["status"] == "degraded"
    assert result["error_code"] == "provider_timeout"
    with app.app_context():
        session = get_db().execute("SELECT state FROM provider_sessions WHERE provider='proxiware'").fetchone()
    assert session["state"] == "active"


def test_browser_runner_refreshes_heartbeat_while_observation_is_active(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)
    entered = Event()
    release = Event()

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            entered.set()
            release.wait(2)
            return [DashboardAssignment("dashboard-1", subscription_id, "51.194.85.8:1337", True, 1, now)]

    runner = ProxiwareBrowserRunner(
        app=app,
        adapter_factory=lambda: Adapter(),
        now=lambda: now,
        heartbeat_interval_seconds=0.05,
    )
    thread = Thread(target=runner.run_once)
    thread.start()
    assert entered.wait(1)
    sleep(0.12)
    with app.app_context():
        status = (
            get_db()
            .execute("SELECT value FROM settings WHERE key='proxiware_browser_worker_status'")
            .fetchone()["value"]
        )
    release.set()
    thread.join(2)

    assert status == "running"
    assert not thread.is_alive()


def test_browser_runner_persists_next_observation_and_restart_skips_not_due_subscription(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)
    calls = []

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            calls.append(subscription_id)
            return [DashboardAssignment("dashboard-1", subscription_id, "51.194.85.8:1337", True, 1, now)]

    assert (
        ProxiwareBrowserRunner(
            app=app,
            adapter_factory=lambda: Adapter(),
            now=lambda: now,
            interval_seconds=300,
        ).run_once()["status"]
        == "ok"
    )
    restarted = ProxiwareBrowserRunner(
        app=app,
        adapter_factory=lambda: Adapter(),
        now=lambda: now + timedelta(seconds=60),
        interval_seconds=300,
    )

    assert restarted.run_once() == {"status": "idle", "observed": 0, "subscriptions": 0}
    assert calls == ["39277"]
    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT dashboard_next_observe_at,dashboard_observation_failures "
                "FROM provider_subscriptions WHERE external_id='39277'"
            )
            .fetchone()
        )
    assert row["dashboard_next_observe_at"] == (now + timedelta(seconds=300)).isoformat()
    assert row["dashboard_observation_failures"] == 0


def test_browser_runner_persists_bounded_retry_backoff_after_transport_failure(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    _seed_session(app, now)

    class Adapter:
        def restore_session(self, _cookies):
            return None

        def observe_dashboard(self, *, subscription_id):
            raise TimeoutError("provider timeout")

    result = ProxiwareBrowserRunner(
        app=app,
        adapter_factory=lambda: Adapter(),
        now=lambda: now,
        interval_seconds=300,
    ).run_once()

    assert result["status"] == "degraded"
    with app.app_context():
        row = (
            get_db()
            .execute(
                "SELECT dashboard_next_observe_at,dashboard_observation_failures,dashboard_last_error_code "
                "FROM provider_subscriptions WHERE external_id='39277'"
            )
            .fetchone()
        )
    retry_at = datetime.fromisoformat(row["dashboard_next_observe_at"])
    assert timedelta(seconds=30) <= retry_at - now <= timedelta(seconds=300)
    assert row["dashboard_observation_failures"] == 1
    assert row["dashboard_last_error_code"] == "provider_timeout"


def test_browser_service_disabled_does_not_initialize_application(monkeypatch):
    import app.proxiware_browser_service as service

    monkeypatch.delenv("EARN_PROXY_PROXIWARE_BROWSER_ENABLED", raising=False)
    monkeypatch.setattr(service, "create_app", lambda: (_ for _ in ()).throw(AssertionError("app initialized")))
    monkeypatch.setattr(sys, "argv", ["proxiware_browser_service", "--once"])

    assert service.main() == 0
