from __future__ import annotations

import logging
import re
from pathlib import Path

from app.db import get_db
from app.proxiware_sync_service import ProxiwareSyncRunner, safe_error_code
from app.services.proxiware_credentials import save_provider_secret


class FakeClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def list_subscriptions(self, network="isp"):
        return [{"id": 11, "network": network, "status": "active"}]

    def list_subscription_proxies(self, subscription_id: int):
        return [{"id": 101, "host": "proxy.example", "port": 8080}]


def test_runner_stops_without_running_after_stop(app, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "app.proxiware_sync_service.sync_proxiware_inventory",
        lambda db, client, **kwargs: calls.append("sync") or {"added": 1},
    )
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "secret-key",
        interval_seconds=1,
    )
    runner.stop()
    assert runner.run_forever(max_cycles=1) == 0
    assert calls == []


def test_runner_runs_one_sync_without_logging_api_key(app, monkeypatch, caplog):
    result = {"added": 1, "updated": 0, "missing": 0, "errors": []}
    monkeypatch.setattr(
        "app.proxiware_sync_service.sync_proxiware_inventory",
        lambda db, client, **kwargs: result,
    )
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "super-secret-api-key",
    )
    with caplog.at_level(logging.INFO):
        outcome = runner.run_once()
    assert outcome["status"] == "ok"
    assert outcome["added"] == 1
    assert "super-secret-api-key" not in caplog.text


def test_runner_maps_failures_to_safe_code_and_does_not_retry_forever(app, monkeypatch):
    attempts = 0

    def fail(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        raise TimeoutError("provider token super-secret-api-key timed out")

    monkeypatch.setattr("app.proxiware_sync_service.sync_proxiware_inventory", fail)
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "super-secret-api-key",
        retry_limit=2,
        retry_backoff_seconds=0,
    )
    outcome = runner.run_once()
    assert outcome["status"] == "error"
    assert outcome["error_code"] == "provider_timeout"
    assert attempts == 2
    assert "super-secret-api-key" not in str(outcome)


def test_safe_error_code_has_no_secret_or_raw_exception():
    assert safe_error_code(TimeoutError("secret=abc")) == "provider_timeout"
    assert safe_error_code(PermissionError("denied")) == "permission_denied"
    assert safe_error_code(ValueError("bad response")) == "invalid_response"


def test_deployment_service_is_restartable_and_unprivileged():
    service = Path("deploy/earn-proxy-proxiware.service").read_text(encoding="utf-8")
    assert "Restart=always" in service
    assert "User=earnproxy" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    swap_service = Path("deploy/earn-proxy-proxiware-swap.service").read_text(encoding="utf-8")
    assert "Restart=always" in swap_service
    assert "User=earnproxy" in swap_service


def test_compose_has_healthchecks_for_provider_workers():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    for worker, command in (
        ("proxiware-sync", "sync_worker"),
        ("proxiware-swap", "swap_worker"),
        ("proxiware-qualification", "qualification_worker"),
    ):
        section = re.search(rf"(?ms)^  {re.escape(worker)}:\n(.*?)(?=^  \S|\Z)", compose).group(1)
        assert "healthcheck:" in section
        assert command in section


def test_runner_reads_encrypted_api_key_from_database_before_env(app, monkeypatch):
    with app.app_context():
        save_provider_secret(get_db(), "api_key", "db-api-key")
    app.config["PROXIWARE_API_KEY"] = ""
    app.config["PROXIWARE_API_KEY_FILE"] = ""
    seen = {}

    class Client(FakeClient):
        def __init__(self, api_key, **kwargs):
            seen["api_key"] = api_key
            super().__init__(api_key)

    monkeypatch.setattr("app.proxiware_sync_service.sync_proxiware_inventory", lambda *args, **kwargs: {"added": 0})
    outcome = ProxiwareSyncRunner(app=app, client_factory=Client).run_once()
    assert outcome["status"] == "ok"
    assert seen["api_key"] == "db-api-key"


def test_sync_runner_records_heartbeat_and_last_success(app, monkeypatch):
    monkeypatch.setattr(
        "app.proxiware_sync_service.sync_proxiware_inventory",
        lambda *_args, **_kwargs: {"run_id": 9, "added": 0},
    )
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "key",
    )

    assert runner.run_once()["status"] == "ok"

    with app.app_context():
        values = dict(
            get_db().execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_sync_worker_%'").fetchall()
        )
    assert values["proxiware_sync_worker_status"] == "ok"
    assert values["proxiware_sync_worker_heartbeat_at"]
    assert values["proxiware_sync_worker_last_success_at"]


def test_runner_consumes_queued_sync_immediately(app, monkeypatch):
    from app.services.proxiware import enqueue_sync_run

    with app.app_context():
        queued = enqueue_sync_run(get_db())
    seen = []

    def sync(db, client, **kwargs):
        seen.append(True)
        claim = db.execute("SELECT id FROM provider_sync_runs WHERE status='queued'").fetchone()
        db.execute(
            "UPDATE provider_sync_runs SET status='success',finished_at=datetime('now') WHERE id=?",
            (claim["id"],),
        )
        db.commit()
        return {"run_id": claim["id"], "added": 0}

    monkeypatch.setattr("app.proxiware_sync_service.sync_proxiware_inventory", sync)
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "key",
        interval_seconds=3600,
    )

    outcome = runner.run_once()

    assert outcome["status"] == "ok"
    assert outcome["run_id"] == queued["run_id"]
    assert seen == [True]


def test_global_proxiware_pause_stops_sync_without_consuming_queue(app, monkeypatch):
    from app.services.proxiware import enqueue_sync_run
    from app.services.settings import set_setting

    with app.app_context():
        db = get_db()
        queued = enqueue_sync_run(db)
        set_setting(db, "proxiware_automation_paused", "1")

    calls: list[str] = []
    monkeypatch.setattr(
        "app.proxiware_sync_service.sync_proxiware_inventory",
        lambda *_args, **_kwargs: calls.append("sync") or {"run_id": queued["run_id"]},
    )
    runner = ProxiwareSyncRunner(
        app=app,
        client_factory=FakeClient,
        api_key_provider=lambda _db: "key",
    )

    assert runner.run_once() == {"status": "paused"}
    assert calls == []
    with app.app_context():
        row = get_db().execute("SELECT status FROM provider_sync_runs WHERE id=?", (queued["run_id"],)).fetchone()
        setting = get_db().execute("SELECT value FROM settings WHERE key='proxiware_sync_worker_status'").fetchone()
    assert row["status"] == "queued"
    assert setting["value"] == "paused"
