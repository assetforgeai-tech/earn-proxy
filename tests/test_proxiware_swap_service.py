from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxiware_swap import ensure_proxiware_swap_schema, queue_eligible_swaps
from app.services.settings import set_setting


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
        assert queue_eligible_swaps(db) == 1
        return sub_id


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
    assert row["state"] == "provider_applied"
    assert mapping is None


def test_auto_swap_runner_queues_an_eligible_subscription_before_claiming(app):
    from app.proxiware_swap_service import ProxiwareSwapRunner

    with app.app_context():
        db = get_db()
        _seed(db)
        set_setting(db, "proxiware_auto_swap", "1")

    class Adapter:
        def swap(self, _job):
            return {"old_assignment_external_id": "old-worker", "new_assignment_external_id": "new-worker"}

    result = ProxiwareSwapRunner(app=app, adapter_factory=lambda: Adapter()).run_once()

    assert result["status"] == "reconciliation_required"
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("provider_applied", 1)


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
            "allow_mutation": True,
        }
    ]


def test_configured_swap_runner_requires_an_active_unexpired_session_before_claim(app):
    _queue(app)
    app.config.update(PROXIWARE_BROWSER_ENABLED=True, PROXIWARE_BROWSER_ALLOW_MUTATION=True)

    result = (
        __import__("app.proxiware_swap_service", fromlist=["ProxiwareSwapRunner"])
        .ProxiwareSwapRunner(app=app)
        .run_once()
    )

    assert result == {"status": "manual_action_required", "error_code": "session_expired"}
    with app.app_context():
        row = get_db().execute("SELECT state,attempts FROM swap_jobs").fetchone()
    assert tuple(row) == ("pending", 0)


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
