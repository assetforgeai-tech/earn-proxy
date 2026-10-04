from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Event
from time import monotonic

from app.db import get_db
from app.services.proxiware_swap import ensure_proxiware_swap_schema, queue_eligible_swaps
from app.services.settings import get_setting, set_setting


def _seed(db):
    ensure_proxiware_swap_schema(db)
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    db.execute(
        """
        INSERT INTO provider_subscriptions
            (provider, external_id, status, eligible_count, connections, swap_quota,
             first_seen_at, last_seen_at, created_at, updated_at)
        VALUES ('proxiware','sub-worker','active',500,10,2,?,?,?,?)
        """,
        (now, now, now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        """
        INSERT INTO provider_assignments
            (subscription_id, provider, external_id, host, port, status, qualification,
             provider_eligible, live_status, dashboard_assignment_id, dashboard_eligible,
             dashboard_connections, dashboard_observed_at, dashboard_source,
             assigned_at, last_seen_at, created_at, updated_at)
        VALUES (?, 'proxiware','old-worker','proxy.example',8080,'active','risk',1,'live',
                'dashboard-worker',1,10,?,'provider_dashboard',?,?,?,?)
        """,
        (sub_id, now, now, now, now, now),
    )
    db.commit()
    return int(sub_id)


def _queue(app):
    with app.app_context():
        db = get_db()
        sub_id = _seed(db)
        set_setting(db, "proxiware_auto_swap", "1")
        set_setting(db, "proxiware_allow_mutation", "1")
        assert queue_eligible_swaps(db) == 1
        return sub_id


def test_safe_swap_error_preserves_provider_response_codes():
    from app.proxiware_swap_service import safe_swap_error
    from app.services.proxiware_browser import BrowserProviderResponseError

    assert safe_swap_error(BrowserProviderResponseError("provider_mutation_rejected")) == "provider_mutation_rejected"
    assert (
        safe_swap_error(BrowserProviderResponseError("provider_response_unconfirmed"))
        == "provider_response_unconfirmed"
    )


def test_swap_runner_waits_for_read_only_reconciliation_after_provider_response(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)

    class Adapter:
        def swap(self, job):
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter())
    result = runner.run_once()

    assert result["status"] == "reconciliation_required"
    with app.app_context():
        row = get_db().execute("SELECT state FROM swap_jobs").fetchone()
        mapping = get_db().execute("SELECT * FROM swap_mappings").fetchone()
        sync = (
            get_db()
            .execute("SELECT status FROM provider_sync_runs WHERE provider='proxiware' ORDER BY id DESC LIMIT 1")
            .fetchone()
        )
    assert row["state"] == "provider_applied"
    assert mapping is None
    assert sync["status"] == "queued"


def test_auto_swap_runner_queues_an_eligible_subscription_before_claiming(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    with app.app_context():
        db = get_db()
        _seed(db)
        set_setting(db, "proxiware_auto_swap", "1")
        set_setting(db, "proxiware_allow_mutation", "1")

    class Adapter:
        def swap(self, _job):
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "reconciliation_required"
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("provider_applied", 1)


def test_swap_runner_defers_stale_dashboard_job_and_requests_refresh(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    stale_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with app.app_context():
        db = get_db()
        db.execute("UPDATE provider_assignments SET dashboard_observed_at=?", (stale_at,))
        db.commit()

    calls = []

    class Adapter:
        def swap(self, _job):
            calls.append("swap")
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result == {"status": "deferred", "job_id": 1, "error_code": "dashboard_stale"}
    assert calls == []
    with app.app_context():
        db = get_db()
        job = db.execute("SELECT state,error_code,claim_token,claimed_until FROM swap_jobs WHERE id=1").fetchone()
        subscription = db.execute(
            "SELECT dashboard_next_observe_at FROM provider_subscriptions WHERE provider='proxiware'"
        ).fetchone()
    assert job["state"] == "pending"
    assert job["error_code"] == "dashboard_stale"
    assert job["claim_token"] is None
    assert datetime.fromisoformat(job["claimed_until"]) > datetime.now(UTC)
    assert datetime.fromisoformat(subscription["dashboard_next_observe_at"]) <= datetime.now(UTC)


def test_swap_runner_passes_scoped_dashboard_identity_to_adapter(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    seen = {}

    class Adapter:
        def swap(self, job):
            seen.update(
                dashboard_assignment_id=job["dashboard_assignment_id"],
                old_assignment_external_id=job["old_assignment_external_id"],
                subscription_external_id=job["subscription_external_id"],
            )
            return {
                "old_assignment_external_id": "old-worker",
                "new_assignment_external_id": "new-worker",
            }

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "reconciliation_required"
    assert seen == {
        "dashboard_assignment_id": "dashboard-worker",
        "old_assignment_external_id": "old-worker",
        "subscription_external_id": "sub-worker",
    }


def test_swap_runner_uses_identity_captured_by_the_mutation_fence(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    seen = {}

    class Adapter:
        def swap(self, job):
            seen["dashboard_assignment_id"] = job["dashboard_assignment_id"]
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    def factory(_job):
        db = get_db()
        db.execute("UPDATE provider_assignments SET dashboard_assignment_id='dashboard-fenced'")
        db.commit()
        return Adapter()

    result = ProxiwareSwapRunner(app=app, adapter_factory=factory).run_once()

    assert result["status"] == "reconciliation_required"
    assert seen == {"dashboard_assignment_id": "dashboard-fenced"}


def test_swap_runner_freezes_unknown_outcome_after_mutation_starts(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)

    class Adapter:
        def swap(self, job):
            raise RuntimeError("captcha_required")

    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter())
    result = runner.run_once()

    assert result["status"] == "reconciliation_required"
    with app.app_context():
        row = get_db().execute("SELECT state,error_code FROM swap_jobs").fetchone()
        setting = get_db().execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()
    assert row["state"] == "reconciliation_required"
    assert row["error_code"] == "captcha_required"
    assert setting["value"] == "0"


def test_swap_runner_hard_times_out_provider_io_and_freezes_reconciliation(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    entered = Event()
    release = Event()

    class HangingAdapter:
        def swap(self, _job):
            entered.set()
            release.wait(5)
            return {
                "old_assignment_external_id": "old-worker",
                "new_assignment_external_id": "late-worker",
            }

    runner = ProxiwareSwapRunner(
        app=app,
        adapter_factory=lambda: HangingAdapter(),
        mutation_timeout_seconds=0.05,
    )
    started = monotonic()
    result = runner.run_once()
    elapsed = monotonic() - started

    assert entered.is_set()
    assert elapsed < 1.0
    assert result == {"status": "reconciliation_required", "job_id": 1, "error_code": "provider_timeout"}
    with app.app_context():
        db = get_db()
        row = db.execute("SELECT state,error_code FROM swap_jobs").fetchone()
        setting = db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()
    assert tuple(row) == ("reconciliation_required", "provider_timeout")
    assert setting["value"] == "0"
    release.set()


def test_swap_runner_reports_disabled_without_busy_loop_when_auto_swap_is_off(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: None)
    assert runner.run_once() == {"status": "disabled"}
    with app.app_context():
        values = dict(
            get_db().execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_swap_worker_%'").fetchall()
        )
    assert values["proxiware_swap_worker_status"] == "disabled"
    assert values["proxiware_swap_worker_heartbeat_at"]


def test_swap_runner_does_not_claim_jobs_while_worker_is_paused(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    with app.app_context():
        set_setting(get_db(), "proxiware_swap_worker_paused", "1")
    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: None)
    assert runner.run_once() == {"status": "paused"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("pending", 0)


def test_global_proxiware_pause_does_not_claim_swap_or_disable_distribution(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    with app.app_context():
        db = get_db()
        set_setting(db, "proxiware_automation_paused", "1")
        set_setting(db, "proxiware_distribution_enabled", "1")
    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: None)

    assert runner.run_once() == {"status": "paused"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
        distribution = (
            get_db()
            .execute("SELECT value FROM settings WHERE key='proxiware_distribution_enabled'")
            .fetchone()["value"]
        )
    assert tuple(row) == ("pending", 0)
    assert distribution == "1"


def test_swap_runner_does_not_claim_jobs_when_auto_swap_is_off(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    _queue(app)
    with app.app_context():
        set_setting(get_db(), "proxiware_auto_swap", "0")
    runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: None)
    assert runner.run_once() == {"status": "disabled"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("pending", 0)


def test_runtime_pause_with_live_session_does_not_restore_auto_swap_intent(app):
    from app.services.proxiware_credentials import store_provider_session

    _queue(app)
    with app.app_context():
        store_provider_session(
            get_db(), [{"name": "session", "value": "opaque"}], expires_at=datetime.now(UTC) + timedelta(hours=1)
        )
        set_setting(get_db(), "proxiware_auto_swap", "0")
        set_setting(get_db(), "proxiware_auto_swap_intent", "1")
    app.config.update(PROXIWARE_BROWSER_ENABLED=True, PROXIWARE_BROWSER_ALLOW_MUTATION=True)

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "disabled"}
    with app.app_context():
        assert get_db().execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()[0] == "0"


def test_configured_swap_runner_does_not_claim_when_mutation_adapter_is_disabled(app):
    _queue(app)
    app.config.update(PROXIWARE_BROWSER_ENABLED=True, PROXIWARE_BROWSER_ALLOW_MUTATION=False)

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "manual_action_required", "error_code": "adapter_missing"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("pending", 0)


def test_configured_swap_runner_requires_runtime_allow_mutation_policy(app):
    _queue(app)
    app.config.update(
        PROXIWARE_BROWSER_ENABLED=True,
        PROXIWARE_BROWSER_ALLOW_MUTATION=True,
        PROXIWARE_BROWSER_DRY_RUN=False,
    )
    with app.app_context():
        set_setting(get_db(), "proxiware_allow_mutation", "0")

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "mutation_disabled"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
        readiness = get_setting(get_db(), "proxiware_swap_worker_mutation_ready", "")
    assert tuple(row) == ("pending", 0)
    assert readiness == "0"


def test_adapter_without_mutation_capability_is_blocked_before_mutating(app):
    _queue(app)

    class ReadOnlyAdapter:
        allow_mutation = False

        def swap(self, _job):
            raise AssertionError("read-only adapter reached provider mutation")

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(
            app=app,
            adapter_factory=lambda: ReadOnlyAdapter(),
        )
        .run_once()
    )

    assert result == {"status": "blocked", "job_id": 1, "error_code": "manual_action_required"}
    with app.app_context():
        row = get_db().execute("SELECT state,error_code,mutation_started_at FROM swap_jobs").fetchone()
    assert tuple(row) == ("blocked", "manual_action_required", None)


def test_configured_swap_runner_builds_the_guarded_browser_adapter(app, monkeypatch):
    _queue(app)
    from app.services.proxiware_credentials import store_provider_session

    with app.app_context():
        store_provider_session(
            get_db(),
            [{"name": "session", "value": "opaque"}],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    app.config.update(
        PROXIWARE_BROWSER_ENABLED=True,
        PROXIWARE_BROWSER_ALLOW_MUTATION=True,
        PROXIWARE_CDP_URL="http://127.0.0.1:9222",
        PROXIWARE_CDP_LOCK_PATH="swap.lock",
    )
    built = []

    class Adapter:
        allow_mutation = True

        def restore_session(self, _cookies):
            return None

        def swap(self, _job):
            return {"old_assignment_external_id": "old-worker", "new_assignment_address": "51.194.85.9"}

    def build(**kwargs):
        built.append(kwargs)
        return Adapter()

    monkeypatch.setattr("app.proxiware_swap_service.build_browser_adapter", build)

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result["status"] == "reconciliation_required"
    assert built == [
        {
            "enabled": True,
            "cdp_url": "http://127.0.0.1:9222",
            "dashboard_url": "https://app.proxiware.com/static/proxy/isp",
            "login_url": "https://app.proxiware.com/auth/login?redirect=%2F",
            "lock_path": "swap.lock",
            "allow_mutation": True,
        }
    ]


def test_configured_swap_runner_requires_an_active_unexpired_session_before_claim(app):
    _queue(app)
    app.config.update(
        PROXIWARE_BROWSER_ENABLED=True,
        PROXIWARE_BROWSER_ALLOW_MUTATION=True,
        PROXIWARE_HCAPTCHA_SITE_KEY="site-key",
    )

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "manual_action_required", "error_code": "session_expired"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("pending", 0)


def test_configured_swap_runner_preserves_renewal_error_during_cooldown(app):
    _queue(app)
    app.config.update(PROXIWARE_BROWSER_ENABLED=True, PROXIWARE_BROWSER_ALLOW_MUTATION=True)
    with app.app_context():
        db = get_db()
        from app.services.proxiware_credentials import save_provider_credentials

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
            "INSERT INTO provider_sessions(provider,state,last_error_code,renew_next_attempt_at,updated_at) "
            "VALUES(?,?,?,?,datetime('now')) ON CONFLICT(provider) DO UPDATE SET state=excluded.state,"
            "last_error_code=excluded.last_error_code,renew_next_attempt_at=excluded.renew_next_attempt_at",
            (
                "proxiware",
                "manual_action_required",
                "captcha_timeout",
                (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            ),
        )
        db.commit()

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "manual_action_required", "error_code": "captcha_timeout"}


def test_configured_swap_runner_renews_when_runtime_gate_is_paused_but_intent_is_on(app, monkeypatch):
    app.config.update(
        PROXIWARE_BROWSER_ENABLED=True,
        PROXIWARE_BROWSER_ALLOW_MUTATION=True,
        PROXIWARE_HCAPTCHA_SITE_KEY="site-key",
    )
    calls = []
    with app.app_context():
        db = get_db()
        from app.services.proxiware_credentials import save_provider_credentials

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
            (
                "proxiware",
                "active",
                (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                datetime.now(UTC).isoformat(),
            ),
        )
        set_setting(db, "proxiware_auto_swap", "0")
        set_setting(db, "proxiware_auto_swap_intent", "1")

    class Adapter:
        allow_mutation = True

        def renew(self, **_kwargs):
            calls.append("renew")
            return {"cookies": [{"name": "session", "value": "fresh"}], "fingerprint_observed": True}

        def restore_session(self, _cookies):
            calls.append("restore")

        def close(self):
            calls.append("close")

    class Captcha:
        def solve_hcaptcha(self, **_kwargs):
            calls.append("captcha")
            return "token"

    monkeypatch.setattr("app.proxiware_swap_service.build_browser_adapter", lambda **_kwargs: Adapter())
    app.extensions["proxiware_captcha_adapter_factory"] = lambda _key: Captcha()

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "idle"}
    assert calls[:3] == ["captcha", "renew", "restore"]
    with app.app_context():
        assert get_setting(get_db(), "proxiware_auto_swap", "0") == "1"


def test_swap_runner_closes_configured_browser_adapter_after_attempt(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner
    from app.services.proxiware_credentials import store_provider_session

    _queue(app)
    with app.app_context():
        store_provider_session(
            get_db(), [{"name": "session", "value": "opaque"}], expires_at=datetime.now(UTC) + timedelta(hours=1)
        )
    app.config.update(PROXIWARE_BROWSER_ENABLED=True, PROXIWARE_BROWSER_ALLOW_MUTATION=True)
    closed = []

    class Adapter:
        allow_mutation = True

        def restore_session(self, _cookies):
            return None

        def swap(self, _job):
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

        def close(self):
            closed.append(True)

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "reconciliation_required"
    assert closed == [True]


def test_swap_runner_revalidates_assignment_before_calling_adapter(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    sub_id = _queue(app)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE provider_assignments SET qualification='allow' WHERE subscription_id=?",
            (sub_id,),
        )
        db.commit()

    calls = []

    class Adapter:
        def swap(self, job):
            calls.append(int(job["id"]))
            raise AssertionError("stale swap guard reached provider adapter")

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result == {"status": "rejected", "job_id": 1, "error_code": "not_risk"}
    assert calls == []
    with app.app_context():
        row = get_db().execute("SELECT state,reason,error_code FROM swap_jobs").fetchone()
    assert tuple(row) == ("blocked", "guard_failed", "not_risk")


def test_swap_runner_revalidates_provider_threshold_before_calling_adapter(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    sub_id = _queue(app)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE provider_subscriptions SET eligible_count=1000 WHERE id=?",
            (sub_id,),
        )
        db.commit()

    calls = []

    class Adapter:
        def swap(self, job):
            calls.append(int(job["id"]))
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "rejected"
    assert result["error_code"] == "provider_ineligible"
    assert calls == []


def test_swap_runner_revalidates_cooldown_before_calling_adapter(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    sub_id = _queue(app)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE provider_assignments SET replacement_ready_at=? WHERE subscription_id=?",
            ((datetime.now(UTC) + timedelta(minutes=5)).isoformat(), sub_id),
        )
        db.commit()

    calls = []

    class Adapter:
        def swap(self, job):
            calls.append(int(job["id"]))
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "rejected"
    assert result["error_code"] == "cooldown"
    assert calls == []
