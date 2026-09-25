from pathlib import Path

from conftest import login_admin

from app.services.proxiware_swap import ensure_proxiware_swap_schema


def test_proxiware_workspace_is_admin_only_and_never_caches(client):
    assert client.get("/admin/providers/proxiware").status_code == 403

    login_admin(client)
    response = client.get("/admin/providers/proxiware")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert "Proxiware" in page
    assert "Credentials" in page
    assert "API key" in page
    assert "Sync now" not in page
    assert "Browser-backed swap adapter unavailable" in page
    assert "manual_action_required" in page


def test_proxiware_overview_marks_stale_worker_heartbeat(client, db):
    from app.services.settings import set_setting

    set_setting(db, "proxiware_sync_worker_status", "ok")
    set_setting(db, "proxiware_sync_worker_heartbeat_at", "2020-01-01T00:00:00+00:00")
    login_admin(client)
    page = client.get("/admin/providers/proxiware").get_data(as_text=True)

    assert "Worker heartbeat stale" in page


def test_intentional_automation_pause_is_not_reported_as_stale(client, db):
    from app.services.settings import set_setting

    set_setting(db, "proxiware_automation_paused", "1")
    set_setting(db, "proxiware_sync_worker_status", "ok")
    set_setting(db, "proxiware_sync_worker_heartbeat_at", "2020-01-01T00:00:00+00:00")
    login_admin(client)
    page = client.get("/admin/providers/proxiware").get_data(as_text=True)

    assert "Paused" in page
    assert "Worker heartbeat stale" not in page


def test_proxiware_overview_alerts_link_to_correct_workspaces(client, db):
    from app.services.proxiware_credentials import mark_manual_action_required
    from app.services.proxiware_swap import ensure_proxiware_swap_schema
    from app.services.settings import set_setting

    ensure_proxiware_swap_schema(db)
    set_setting(db, "proxiware_sync_worker_status", "ok")
    set_setting(db, "proxiware_sync_worker_heartbeat_at", "2020-01-01T00:00:00+00:00")
    mark_manual_action_required(db, "session_expired")
    login_admin(client)
    page = client.get("/admin/providers/proxiware").get_data(as_text=True)

    assert 'href="/admin/providers/proxiware/sync"' in page
    assert 'href="/admin/providers/proxiware/session"' in page


def test_proxiware_has_dedicated_provider_navigation_and_all_areas(client):
    login_admin(client)
    page = client.get("/admin/providers/proxiware/inventory").get_data(as_text=True)

    assert '<p class="nav-label">Providers</p>' in page
    assert 'data-nav="proxiware"' in page
    assert 'href="/admin/providers/proxiware"' in page
    for area in ("overview", "inventory", "eligibility", "swaps", "history", "credentials", "settings", "audit"):
        assert f'data-proxiware-area="{area}"' in page


def test_proxiware_area_urls_render_without_javascript(client):
    login_admin(client)
    for path, marker in (
        ("/admin/providers/proxiware/inventory", "Provider inventory"),
        ("/admin/providers/proxiware/eligibility", "Qualification"),
        ("/admin/providers/proxiware/swaps", "Swap queue"),
        ("/admin/providers/proxiware/sync-history", "Sync history"),
        ("/admin/providers/proxiware/credentials", "Credentials &amp; Session"),
        ("/admin/providers/proxiware/settings", "Provider settings"),
        ("/admin/providers/proxiware/audit", "Audit trail"),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.get_data(as_text=True)
        assert response.headers["Cache-Control"] == "no-store"


def test_proxiware_has_canonical_sync_history_swap_history_session_and_policy_routes(client):
    login_admin(client)
    for path, marker in (
        ("/admin/providers/proxiware/sync", "Sync"),
        ("/admin/providers/proxiware/swaps/history", "Swap history"),
        ("/admin/providers/proxiware/session", "Provider session"),
        ("/admin/providers/proxiware/policy", "Provider settings"),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert marker in response.get_data(as_text=True)


def test_all_proxiware_subroutes_keep_provider_sidebar_active(client):
    login_admin(client)
    for path in (
        "/admin/providers/proxiware",
        "/admin/providers/proxiware/inventory",
        "/admin/providers/proxiware/qualification",
        "/admin/providers/proxiware/sync",
        "/admin/providers/proxiware/swaps",
        "/admin/providers/proxiware/swaps/history",
        "/admin/providers/proxiware/session",
        "/admin/providers/proxiware/credentials",
        "/admin/providers/proxiware/policy",
        "/admin/providers/proxiware/audit",
    ):
        page = client.get(path).get_data(as_text=True)
        assert '<a class="nav-item" data-nav="proxiware" aria-current="page"' in page, path


def test_proxiware_swap_history_is_separate_from_actionable_queue(client, db):
    login_admin(client)
    ensure_proxiware_swap_schema(db)
    page = client.get("/admin/providers/proxiware/swaps/history").get_data(as_text=True)
    assert "Immutable swap history" in page
    assert "Retry" not in page


def test_proxiware_inventory_exposes_server_side_controls(client):
    login_admin(client)
    page = client.get(
        "/admin/providers/proxiware/inventory?q=isp&subscription=sub-1&live=online&qualification=allow&country=US&sort=country&direction=asc&per_page=50&page=2"
    ).get_data(as_text=True)

    assert 'name="q"' in page
    assert 'name="subscription"' in page
    assert 'name="live"' in page
    assert 'name="qualification"' in page
    assert 'name="country"' in page
    assert 'name="per_page"' in page
    assert 'name="sort"' in page
    assert 'name="provider_eligibility"' in page
    assert 'name="readiness"' in page
    assert "Page 1" in page
    assert "Showing" in page


def test_proxiware_secret_safe_placeholders_and_confirmations(client):
    login_admin(client)
    page = client.get("/admin/providers/proxiware/credentials").get_data(as_text=True)

    assert 'name="proxiware_email"' in page
    assert 'name="proxiware_password"' in page
    assert 'name="proxiware_api_key"' in page
    assert 'name="twocaptcha_api_key"' in page
    assert "write-only" in page.lower()
    assert 'type="password"' in page
    assert "data-confirm-dialog" in page
    assert "data-confirm-trigger" in page
    assert "secret" not in page.lower() or "secret values" in page.lower()
    for name in ("email", "password", "api-key", "captcha-key"):
        assert f"/admin/providers/proxiware/credentials/clear/{name}" in page


def test_proxiware_settings_exposes_distribution_and_swap_worker_controls(client):
    login_admin(client)
    page = client.get("/admin/providers/proxiware/settings").get_data(as_text=True)
    assert 'name="distribution_enabled"' in page
    assert 'name="auto_swap_enabled"' in page


def test_proxiware_overview_exposes_global_automation_pause_controls(client):
    from app.db import get_db
    from app.services.settings import set_setting

    login_admin(client)
    page = client.get("/admin/providers/proxiware").get_data(as_text=True)
    assert "/admin/providers/proxiware/automation/pause" in page
    assert "Pause Proxiware automation" in page
    with client.application.app_context():
        set_setting(get_db(), "proxiware_automation_paused", "1")
    paused_page = client.get("/admin/providers/proxiware").get_data(as_text=True)
    assert "/admin/providers/proxiware/automation/resume" in paused_page
    assert "Resume Proxiware automation" in paused_page


def test_proxiware_workspace_has_real_breadcrumb_for_each_area(client):
    login_admin(client)
    page = client.get("/admin/providers/proxiware/qualification").get_data(as_text=True)
    assert 'aria-label="Breadcrumb"' in page
    assert 'href="/admin/providers/proxiware">Proxiware</a>' in page
    assert "Qualification" in page


def test_proxiware_swap_actions_are_real_routes_not_placeholder_hash(client):
    login_admin(client)
    page = client.get("/admin/providers/proxiware/swaps").get_data(as_text=True)
    assert 'action="#"' not in page
    assert "Pause worker" in page


def test_proxiware_queued_sync_exposes_cancel_control(client, db):
    from app.services.proxiware import enqueue_sync_run

    queued = enqueue_sync_run(db)
    login_admin(client)

    page = client.get("/admin/providers/proxiware/sync").get_data(as_text=True)

    assert f"/admin/providers/proxiware/sync/{queued['run_id']}/cancel" in page
    assert "Cancel queued sync" in page


def test_proxiware_overview_counts_canonical_live_status(client, db):
    login_admin(client)
    ensure_proxiware_swap_schema(db)
    now = "2026-09-25T00:00:00+00:00"
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) VALUES('proxiware','count-sub','active',?,?)",
        (now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,live_status,qualification,created_at,updated_at) "
        "VALUES(?,?,?,'count.example',8080,'live','allow',?,?)",
        (sub_id, "proxiware", "count-assignment", now, now),
    )
    db.commit()
    page = client.get("/admin/providers/proxiware/inventory").get_data(as_text=True)
    # The canonical worker value is live, while the UI label is Online.
    assert ">Online</span>" in page


def test_proxiware_online_filter_matches_canonical_live_value(client, db):
    login_admin(client)
    ensure_proxiware_swap_schema(db)
    now = "2026-09-25T00:00:00+00:00"
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) VALUES('proxiware','filter-sub','active',?,?)",
        (now, now),
    )
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,live_status,qualification,created_at,updated_at) "
        "VALUES(?,?,?,'filter.example',8080,'live','allow',?,?)",
        (sub_id, "proxiware", "filter-assignment", now, now),
    )
    db.commit()
    page = client.get("/admin/providers/proxiware/inventory?live=online").get_data(as_text=True)
    assert "filter.example:8080" in page


def test_proxiware_template_avoids_credential_columns_and_supports_accessibility():
    root = Path(__file__).parents[1]
    template = (root / "app" / "templates" / "admin_proxiware.html").read_text()
    assert "password_encrypted" not in template
    assert "api_key_encrypted" not in template
    assert 'aria-label="Proxiware workspace"' in template
    assert 'aria-live="polite"' in template


def test_proxiware_workspace_fails_closed_when_provider_scope_column_is_missing(client, db, monkeypatch):
    from app.routes import admin as admin_routes

    ensure_proxiware_swap_schema(db)
    now = "2026-09-25T00:00:00+00:00"
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) "
        "VALUES('proxiware','scope-sub','active',?,?)",
        (now, now),
    )
    subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,created_at,updated_at) "
        "VALUES(?,'proxiware','scope-assignment','must-not-render.example',8080,?,?)",
        (subscription_id, now, now),
    )
    db.commit()
    original = admin_routes._proxiware_columns

    def without_scope_column(database, table):
        columns = original(database, table)
        return columns - {"provider"} if table == "provider_assignments" else columns

    monkeypatch.setattr(admin_routes, "_proxiware_columns", without_scope_column)
    login_admin(client)

    page = client.get("/admin/providers/proxiware/inventory").get_data(as_text=True)

    assert "must-not-render.example" not in page


def test_proxiware_duplicate_filter_ignores_other_provider_egress(client, db):
    login_admin(client)
    ensure_proxiware_swap_schema(db)
    now = "2026-09-25T00:00:00+00:00"
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) "
        "VALUES('proxiware','duplicate-scope-sub','active',?,?)",
        (now, now),
    )
    subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,exit_ip,created_at,updated_at) "
        "VALUES(?,'proxiware','duplicate-scope-assignment','proxiware.example',8080,'198.51.100.44',?,?)",
        (subscription_id, now, now),
    )
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) "
        "VALUES('other-provider','duplicate-scope-other-sub','active',?,?)",
        (now, now),
    )
    other_subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,exit_ip,created_at,updated_at) "
        "VALUES(?,'other-provider','duplicate-scope-other-assignment','other.example',8080,'198.51.100.44',?,?)",
        (other_subscription_id, now, now),
    )
    db.commit()

    page = client.get("/admin/providers/proxiware/inventory?duplicate=duplicate").get_data(as_text=True)

    assert "duplicate-scope-assignment" not in page
