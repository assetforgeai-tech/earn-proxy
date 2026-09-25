from __future__ import annotations

from conftest import login_admin

from app.services.proxiware import claim_sync_run
from app.services.proxiware_swap import ensure_proxiware_swap_schema


def test_credentials_post_is_admin_only_and_persists_encrypted_values(client, db):
    response = client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key-before"},
    )
    assert response.status_code == 403

    login_admin(client)
    response = client.post(
        "/admin/providers/proxiware/credentials",
        data={
            "proxiware_email": "owner@example.com",
            "proxiware_password": "provider-password",
            "proxiware_api_key": "key-before",
            "twocaptcha_api_key": "captcha-key",
            "auto_swap_enabled": "",
            "ui": "1",
        },
    )
    assert response.status_code in {302, 303}
    row = db.execute("SELECT secret_encrypted FROM provider_credentials WHERE name='api_key'").fetchone()
    assert row is not None
    assert "key-before" not in row[0]


def test_credentials_save_does_not_disable_auto_swap_when_policy_field_is_absent(client, db):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/settings",
        data={
            "eligibility_threshold": "1000",
            "worker_concurrency": "1",
            "retry_limit": "2",
            "cooldown_seconds": "60",
            "auto_swap_enabled": "on",
            "ui": "1",
        },
    )
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "preserve-key", "ui": "1"},
    )
    assert db.execute("SELECT value FROM settings WHERE key='proxiware_auto_swap'").fetchone()["value"] == "1"


def test_settings_post_is_bounded_and_auto_swap_defaults_off(client, db):
    login_admin(client)
    response = client.post(
        "/admin/providers/proxiware/settings",
        data={
            "eligibility_threshold": "0",
            "worker_concurrency": "999",
            "retry_limit": "999",
            "cooldown_seconds": "1",
            "auto_swap_enabled": "on",
            "distribution_enabled": "on",
            "ui": "1",
        },
    )
    assert response.status_code in {302, 303}
    values = dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_%'").fetchall())
    assert values["proxiware_auto_swap"] == "1"
    assert values["proxiware_eligible_threshold"] == "1"
    assert values["proxiware_cooldown_seconds"] == "60"
    assert values["proxiware_worker_concurrency"] == "20"
    assert values["proxiware_retry_limit"] == "5"
    assert values["proxiware_distribution_enabled"] == "1"


def test_read_only_actions_fail_closed_without_provider_adapters(client):
    login_admin(client)
    for path in (
        "/admin/providers/proxiware/test-connection",
        "/admin/providers/proxiware/renew-session",
    ):
        response = client.post(path, data={"ui": "1"})
        assert response.status_code in {303, 400, 409, 503}
        assert b"secret" not in response.data.lower()


def test_sync_now_is_explicit_post_and_only_visible_when_configured(client):
    login_admin(client)
    response = client.get("/admin/providers/proxiware")
    assert response.status_code == 200
    assert b"Sync now" not in response.data
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key-for-ui", "ui": "1"},
    )
    response = client.get("/admin/providers/proxiware")
    assert b"Sync now" in response.data
    assert b'action="/admin/providers/proxiware/sync"' in response.data


def test_sync_route_enqueues_durable_run_without_contacting_provider(client, app):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key-for-sync", "ui": "1"},
    )
    calls = []
    app.extensions["proxiware_api_client_factory"] = lambda _key: calls.append("provider")

    response = client.post("/admin/providers/proxiware/sync")

    assert response.status_code == 202
    assert response.get_json()["status"] == "queued"
    assert calls == []
    run = app.extensions.get("last_proxiware_sync_run")
    assert run is None


def test_sync_route_rejects_duplicate_queued_run(client):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key-for-sync", "ui": "1"},
    )
    first = client.post("/admin/providers/proxiware/sync")
    second = client.post("/admin/providers/proxiware/sync")

    assert first.status_code == 202
    assert second.status_code == 409
    assert second.get_json()["error_code"] == "already_running"


def test_sync_route_without_key_fails_closed(client):
    login_admin(client)
    response = client.post("/admin/providers/proxiware/sync")
    assert response.status_code in {400, 503}
    assert b"api key" in response.data.lower() or b"configured" in response.data.lower()


def test_sync_route_returns_conflict_when_sync_is_already_running(client, db):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key-for-sync", "ui": "1"},
    )
    run = claim_sync_run(db)
    response = client.post("/admin/providers/proxiware/sync")
    assert response.status_code == 409
    assert response.get_json()["error_code"] == "already_running"
    assert run is not None


def test_admin_can_cancel_only_a_running_sync(client, db):
    login_admin(client)
    run = claim_sync_run(db)
    response = client.post(f"/admin/providers/proxiware/sync/{run['run_id']}/cancel")
    assert response.status_code == 200
    assert response.get_json()["status"] == "cancel_requested"
    response = client.post(f"/admin/providers/proxiware/sync/{run['run_id']}/cancel")
    assert response.status_code == 409


def test_provider_action_get_requests_do_not_mutate(client, db):
    login_admin(client)
    before = db.total_changes

    # `/sync` is the canonical read-only workspace route; only its POST
    # sibling starts a run. Mutation-only endpoints must reject GET.
    assert client.get("/admin/providers/proxiware/sync").status_code == 200
    for path in (
        "/admin/providers/proxiware/test-connection",
        "/admin/providers/proxiware/renew-session",
    ):
        response = client.get(path)
        assert response.status_code in {404, 405}

    assert db.total_changes == before


def test_test_connection_uses_injected_read_only_adapters(client, app, monkeypatch):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "key", "twocaptcha_api_key": "captcha-key", "ui": "1"},
    )
    seen = {}

    class FakeApi:
        def get_account(self):
            seen["api"] = True
            return {"id": 1}

    class FakeCaptcha:
        def get_balance(self):
            seen["captcha"] = True
            return 2.0

    app.extensions["proxiware_api_client_factory"] = lambda key: seen.update(api_key=key) or FakeApi()
    app.extensions["proxiware_captcha_adapter_factory"] = lambda key: seen.update(captcha_key=key) or FakeCaptcha()
    response = client.post("/admin/providers/proxiware/test-connection")
    assert response.status_code == 200
    assert seen == {"api_key": "key", "captcha_key": "captcha-key", "api": True, "captcha": True}
    assert response.get_json()["api_ok"] is True
    assert response.get_json()["captcha_balance"] == 2.0


def test_test_connection_missing_credentials_fails_closed(client):
    login_admin(client)
    response = client.post("/admin/providers/proxiware/test-connection")
    assert response.status_code in {400, 503}
    assert b"configured" in response.data.lower()


def test_renew_session_uses_injected_adapters(client, app):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={
            "proxiware_email": "owner@example.com",
            "proxiware_password": "provider-password",
            "twocaptcha_api_key": "captcha-key",
            "ui": "1",
        },
    )
    seen = {}

    class FakeBrowser:
        def renew(self, *, email, password, captcha_token):
            seen.update(email=email, password=password, captcha_token=captcha_token)
            return {
                "cookies": [{"name": "session", "value": "opaque"}],
                "expires_at": "2026-09-25T00:00:00+00:00",
                "fingerprint_observed": True,
            }

    class FakeCaptcha:
        def solve_hcaptcha(self, *, site_key, page_url):
            seen.update(site_key=site_key, page_url=page_url)
            return "captcha-token"

    app.config["PROXIWARE_HCAPTCHA_SITE_KEY"] = "site-key"
    app.config["PROXIWARE_LOGIN_URL"] = "https://app.proxiware.com/login"
    app.extensions["proxiware_browser_adapter_factory"] = lambda: FakeBrowser()
    app.extensions["proxiware_captcha_adapter_factory"] = lambda key: seen.update(captcha_key=key) or FakeCaptcha()

    response = client.post("/admin/providers/proxiware/renew-session")

    assert response.status_code == 200
    assert response.get_json()["state"] == "active"
    assert seen == {
        "captcha_key": "captcha-key",
        "site_key": "site-key",
        "page_url": "https://app.proxiware.com/login",
        "email": "owner@example.com",
        "password": "provider-password",
        "captcha_token": "captcha-token",
    }


def test_renew_session_without_browser_adapter_is_safe_503(client):
    login_admin(client)
    response = client.post("/admin/providers/proxiware/renew-session")
    assert response.status_code == 503
    assert b"adapter" in response.data.lower()


def _swap_job(db, state="blocked"):
    ensure_proxiware_swap_schema(db)
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,eligible_count,connections,created_at,updated_at) "
        "VALUES('proxiware','action-sub','active',10,1,datetime('now'),datetime('now'))"
    )
    subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,status,qualification,provider_eligible,live_status,"
        "dashboard_assignment_id,dashboard_eligible,dashboard_connections,dashboard_observed_at,dashboard_source,created_at,updated_at) "
        "VALUES(?,'proxiware','action-old','old.example',8080,'active','risk',1,'live',"
        "'dashboard-action',1,10,datetime('now'),'provider_dashboard',datetime('now'),datetime('now'))",
        (subscription_id,),
    )
    assignment_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO swap_jobs(provider,subscription_id,old_assignment_id,state,reason,error_code,created_at,updated_at) "
        "VALUES('proxiware',?,?,?,?,?,datetime('now'),datetime('now'))",
        (subscription_id, assignment_id, state, "test", "provider_timeout"),
    )
    db.commit()
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]


def test_swap_retry_and_cancel_routes_are_durable_and_admin_only(client, db):
    job_id = _swap_job(db)
    assert client.post(f"/admin/providers/proxiware/swaps/{job_id}/retry").status_code == 403
    login_admin(client)

    response = client.post(f"/admin/providers/proxiware/swaps/{job_id}/retry")
    assert response.status_code == 200
    assert response.get_json()["status"] == "pending"
    row = db.execute("SELECT state,reason,error_code FROM swap_jobs WHERE id=?", (job_id,)).fetchone()
    assert tuple(row) == ("pending", "manual_retry", "")

    response = client.post(f"/admin/providers/proxiware/swaps/{job_id}/cancel")
    assert response.status_code == 200
    assert response.get_json()["status"] == "canceled"
    assert db.execute("SELECT state FROM swap_jobs WHERE id=?", (job_id,)).fetchone()["state"] == "canceled"


def test_swap_worker_pause_resume_routes_are_explicit(client, db):
    login_admin(client)
    paused = client.post("/admin/providers/proxiware/swap-worker/pause")
    resumed = client.post("/admin/providers/proxiware/swap-worker/resume")
    assert paused.status_code == 200
    assert resumed.status_code == 200
    assert db.execute("SELECT value FROM settings WHERE key='proxiware_swap_worker_paused'").fetchone()["value"] == "0"


def test_proxiware_emergency_pause_is_provider_scoped_and_preserves_distribution(client, db):
    login_admin(client)
    db.execute(
        "INSERT INTO settings(key,value,updated_at) VALUES('proxiware_distribution_enabled','1',datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value='1'"
    )
    db.commit()

    paused = client.post("/admin/providers/proxiware/automation/pause")
    assert paused.status_code == 200
    assert paused.get_json()["status"] == "paused"
    assert db.execute("SELECT value FROM settings WHERE key='proxiware_automation_paused'").fetchone()["value"] == "1"
    assert (
        db.execute("SELECT value FROM settings WHERE key='proxiware_distribution_enabled'").fetchone()["value"] == "1"
    )

    resumed = client.post("/admin/providers/proxiware/automation/resume")
    assert resumed.status_code == 200
    assert resumed.get_json()["status"] == "running"
    assert db.execute("SELECT value FROM settings WHERE key='proxiware_automation_paused'").fetchone()["value"] == "0"


def test_manual_swap_route_fails_closed_without_adapter(client, db):
    job_id = _swap_job(db)
    login_admin(client)
    response = client.post(f"/admin/providers/proxiware/swaps/{job_id}/manual")
    assert response.status_code == 503
    assert response.get_json()["error_code"] == "adapter_missing"


def test_manual_swap_route_executes_only_selected_job_with_injected_adapter(client, app, db):
    job_id = _swap_job(db)
    login_admin(client)

    class Adapter:
        def swap(self, job):
            assert int(job["id"]) == job_id
            return {
                "old_assignment_external_id": "action-old",
                "new_assignment_address": "51.194.85.9",
            }

    app.extensions["proxiware_swap_adapter_factory"] = lambda _job: Adapter()
    response = client.post(f"/admin/providers/proxiware/swaps/{job_id}/manual")
    assert response.status_code == 202
    assert response.get_json()["status"] == "reconciliation_required"
    row = db.execute("SELECT state FROM swap_jobs WHERE id=?", (job_id,)).fetchone()
    assert row["state"] == "provider_applied"


def test_provider_action_rate_limit_blocks_repeated_sync_requests(client, app):
    login_admin(client)
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"proxiware_api_key": "rate-key", "ui": "1"},
    )
    app.config["PROXIWARE_ACTION_RATE_LIMIT"] = 1
    app.config["PROXIWARE_ACTION_RATE_WINDOW_SECONDS"] = 300
    app.extensions["proxiware_api_client_factory"] = lambda _key: type(
        "Client", (), {"get_account": lambda self: {"id": 1}}
    )()
    # Use the read-only connection route so no provider mutation is involved.
    client.post(
        "/admin/providers/proxiware/credentials",
        data={"twocaptcha_api_key": "captcha-key", "ui": "1"},
    )
    app.extensions["proxiware_captcha_adapter_factory"] = lambda _key: type(
        "Captcha", (), {"get_balance": lambda self: 1.0}
    )()
    assert client.post("/admin/providers/proxiware/test-connection").status_code == 200
    response = client.post("/admin/providers/proxiware/test-connection")
    assert response.status_code == 429
    assert response.get_json()["error_code"] == "rate_limited"


def test_provider_action_rate_limit_records_are_provider_scoped(client, db):
    login_admin(client)

    response = client.post("/admin/providers/proxiware/test-connection")

    assert response.status_code == 503
    columns = {row["name"] for row in db.execute('PRAGMA table_info("provider_action_attempts")').fetchall()}
    assert "provider" in columns
    rows = db.execute("SELECT DISTINCT provider FROM provider_action_attempts").fetchall()
    assert [row["provider"] for row in rows] == ["proxiware"]


def test_all_proxiware_admin_responses_are_no_store(client):
    login_admin(client)

    get_response = client.get("/admin/providers/proxiware")
    post_response = client.post(
        "/admin/providers/proxiware/settings",
        data={
            "eligibility_threshold": "1000",
            "worker_concurrency": "1",
            "retry_limit": "2",
            "cooldown_seconds": "60",
        },
    )

    assert get_response.headers["Cache-Control"] == "no-store"
    assert post_response.headers["Cache-Control"] == "no-store"


def test_provider_policy_mutations_are_rate_limited(client, app):
    login_admin(client)
    app.config["PROXIWARE_ACTION_RATE_LIMIT"] = 1
    app.config["PROXIWARE_ACTION_RATE_WINDOW_SECONDS"] = 300
    payload = {
        "eligibility_threshold": "1000",
        "worker_concurrency": "1",
        "retry_limit": "2",
        "cooldown_seconds": "60",
    }

    assert client.post("/admin/providers/proxiware/settings", data=payload).status_code == 200
    response = client.post("/admin/providers/proxiware/settings", data=payload)

    assert response.status_code == 429
    assert response.get_json()["error_code"] == "rate_limited"
