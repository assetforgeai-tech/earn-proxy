from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from time import sleep

from app.db import get_db
from app.proxiware_browser_service import ProxiwareBrowserRunner
from app.services.proxiware import sync_proxiware_inventory
from app.services.proxiware_credentials import save_provider_credentials, store_provider_session
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
        PROXIWARE_CDP_LOCK_PATH="observer.lock",
    )
    captured = {}

    def build(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("app.proxiware_browser_service.build_browser_adapter", build)

    ProxiwareBrowserRunner(app=app)._configured_adapter()

    assert captured["allow_mutation"] is False
    assert captured["lock_path"] == "observer.lock"


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


def test_browser_runner_renews_expired_session_with_captcha_before_observing(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    with app.app_context():
        db = get_db()
        app.config["PROXIWARE_WORKER_FERNET_KEY"] = app.config["FERNET_KEY"]
        save_provider_credentials(
            db,
            {
                "login_email": "owner@example.com",
                "login_password": "provider-password",
                "captcha_api_key": "captcha-key",
            },
        )
        db.execute(
            "INSERT INTO provider_sessions(provider,state,expires_at,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET state=excluded.state,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
            ("proxiware", "active", (now - timedelta(minutes=1)).isoformat(), now.isoformat()),
        )
        db.commit()

    calls = []

    class Adapter:
        def renew(self, *, email, password, captcha_token):
            calls.append(("renew", email, password, captcha_token))
            return {
                "cookies": [{"name": "session", "value": "new", "domain": "app.proxiware.com", "path": "/"}],
                "fingerprint_observed": True,
            }

        def restore_session(self, cookies):
            calls.append(("restore", cookies))

        def observe_dashboard(self, *, subscription_id):
            return [DashboardAssignment("dashboard-1", subscription_id, "51.194.85.8:1337", True, 1, now)]

    class Captcha:
        def solve_hcaptcha(self, *, site_key, page_url):
            calls.append(("captcha", site_key, page_url))
            return "token"

    app.config.update(
        RUNTIME_PROFILE="proxiware_worker",
        PROXIWARE_HCAPTCHA_SITE_KEY="site-key",
        PROXIWARE_LOGIN_URL="https://app.proxiware.com/auth/login",
    )
    app.extensions["proxiware_captcha_adapter_factory"] = lambda _key: Captcha()

    result = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now).run_once()

    assert result["status"] == "ok"
    assert calls[0] == ("captcha", "site-key", "https://app.proxiware.com/auth/login")
    assert calls[1] == ("renew", "owner@example.com", "provider-password", "token")
    assert calls[2][0] == "restore"


def test_browser_runner_preserves_renewal_error_code_after_captcha_failure(app):
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    _seed_inventory(app, now)
    with app.app_context():
        db = get_db()
        app.config["PROXIWARE_WORKER_FERNET_KEY"] = app.config["FERNET_KEY"]
        save_provider_credentials(
            db,
            {
                "login_email": "owner@example.com",
                "login_password": "provider-password",
                "captcha_api_key": "captcha-key",
            },
        )
        db.execute(
            "INSERT INTO provider_sessions(provider,state,expires_at,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET state=excluded.state,expires_at=excluded.expires_at,updated_at=excluded.updated_at",
            ("proxiware", "active", (now - timedelta(minutes=1)).isoformat(), now.isoformat()),
        )
        db.commit()

    class Adapter:
        def renew(self, **_kwargs):
            raise RuntimeError("captcha provider unavailable")

        def restore_session(self, _cookies):
            raise AssertionError("expired session must not be restored")

        def observe_dashboard(self, *, subscription_id):
            raise AssertionError("observation must wait for renewal")

    class Captcha:
        def solve_hcaptcha(self, **_kwargs):
            raise RuntimeError("captcha provider unavailable")

    app.config.update(
        RUNTIME_PROFILE="proxiware_worker",
        PROXIWARE_HCAPTCHA_SITE_KEY="site-key",
        PROXIWARE_LOGIN_URL="https://app.proxiware.com/auth/login",
    )
    app.extensions["proxiware_captcha_adapter_factory"] = lambda _key: Captcha()

    result = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: Adapter(), now=lambda: now).run_once()

    assert result == {"status": "manual_action_required", "observed": 0, "subscriptions": 1}
    with app.app_context():
        session = (
            get_db()
            .execute("SELECT state,last_error_code FROM provider_sessions WHERE provider='proxiware'")
            .fetchone()
        )
    assert tuple(session) == ("manual_action_required", "captcha_timeout")


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
    now = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
    runner = ProxiwareBrowserRunner(app=app, interval_seconds=120, now=lambda: now)
    runner._stop.wait = lambda _seconds: True

    runner._wait_with_heartbeat(120)

    with app.app_context():
        values = dict(
            get_db().execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_browser_worker_%'").fetchall()
        )
    assert values["proxiware_browser_worker_status"] == "sleeping"
    assert values["proxiware_browser_worker_heartbeat_at"]
    assert values["proxiware_browser_worker_next_wake_at"] == (now + timedelta(seconds=120)).isoformat()


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
    monkeypatch.setattr(service, "create_worker_app", lambda: (_ for _ in ()).throw(AssertionError("app initialized")))
    monkeypatch.setattr(sys, "argv", ["proxiware_browser_service", "--once"])

    assert service.main() == 0


def test_browser_runner_polls_due_reconciliation_when_auto_swap_is_enabled(app):
    from app.services.settings import set_setting

    with app.app_context():
        db = get_db()
        set_setting(db, "proxiware_auto_swap", "1")
        current = datetime.now(UTC)
        now = current.isoformat()
        db.execute(
            "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,"
            "dashboard_next_observe_at,created_at,updated_at) "
            "VALUES('proxiware','poll-sub','active',?,?,?,?,?)",
            (now, now, (current - timedelta(seconds=1)).isoformat(), now, now),
        )
        subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.execute(
            "INSERT INTO swap_jobs(provider,subscription_id,state,created_at,updated_at) "
            "VALUES('proxiware',?,'provider_applied',?,?)",
            (subscription_id, now, now),
        )
        db.commit()

    waits: list[float] = []
    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: None, interval_seconds=300)
    runner.run_once = lambda: {"status": "idle", "observed": 0, "subscriptions": 0}
    runner._wait_for_handoff = lambda seconds: waits.append(seconds)

    assert runner.run_forever(max_cycles=2) == 2
    assert waits == [5.0]


def test_browser_runner_polls_due_dashboard_observation_when_auto_swap_is_enabled(app):
    from app.services.settings import set_setting

    with app.app_context():
        db = get_db()
        set_setting(db, "proxiware_auto_swap", "1")
        current = datetime.now(UTC)
        now = current.isoformat()
        db.execute(
            "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,"
            "dashboard_next_observe_at,created_at,updated_at) "
            "VALUES('proxiware','due-observation','active',?,?,?,?,?)",
            (now, now, (current - timedelta(seconds=1)).isoformat(), now, now),
        )
        db.commit()

    waits: list[float] = []
    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: None, interval_seconds=300)
    runner.run_once = lambda: {"status": "idle", "observed": 0, "subscriptions": 0}
    runner._wait_for_handoff = lambda seconds: waits.append(seconds)

    assert runner.run_forever(max_cycles=2) == 2
    assert waits == [5.0]


def test_browser_runner_wakes_when_reconciliation_arrives_during_idle_wait(app):
    from app.services.settings import set_setting

    with app.app_context():
        set_setting(get_db(), "proxiware_auto_swap", "1")

    waits: list[float] = []

    def wait(seconds):
        waits.append(seconds)
        if len(waits) == 1:
            with app.app_context():
                db = get_db()
                now = datetime.now(UTC).isoformat()
                db.execute(
                    "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,"
                    "dashboard_next_observe_at,created_at,updated_at) "
                    "VALUES('proxiware','arrived-sub','active',?,?,?,?,?)",
                    (now, now, now, now, now),
                )
                subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO swap_jobs(provider,subscription_id,state,created_at,updated_at) "
                    "VALUES('proxiware',?,'provider_applied',?,?)",
                    (subscription_id, now, now),
                )
                db.commit()
        return len(waits) > 1

    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: None, interval_seconds=300)
    runner.run_once = lambda: {"status": "idle", "observed": 0, "subscriptions": 0}
    runner._stop.wait = wait

    assert runner.run_forever(max_cycles=2) == 2
    assert waits == [5.0]


def test_browser_runner_keeps_periodic_interval_without_reconciliation(app):
    from app.services.settings import set_setting

    with app.app_context():
        set_setting(get_db(), "proxiware_auto_swap", "1")

    waits: list[float] = []
    runner = ProxiwareBrowserRunner(app=app, adapter_factory=lambda: None, interval_seconds=300)
    runner._wait_for_handoff = lambda seconds: waits.append(seconds)

    assert runner.run_forever(max_cycles=2) == 2
    assert waits == [300.0]
