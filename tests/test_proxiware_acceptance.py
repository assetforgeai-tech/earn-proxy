from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

from scripts.proxiware_preflight import run_preflight


def test_runtime_observation_reports_disabled_browser_without_stale_reason(tmp_path):
    from scripts.proxiware_preflight import _database_observation

    database = tmp_path / "runtime.db"
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
    connection.executemany(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
        [
            ("proxiware_browser_worker_status", "disabled", old),
            ("proxiware_browser_worker_heartbeat_at", old, old),
        ],
    )
    connection.commit()
    connection.close()

    observation = _database_observation(database, now=datetime.now(UTC))

    assert observation["heartbeats"]["browser_worker"]["status"] == "disabled"
    assert observation["heartbeats"]["browser_worker"]["reason"] == "disabled"


def test_runtime_observation_reports_recent_degraded_worker_as_degraded(tmp_path):
    from scripts.proxiware_preflight import _database_observation

    database = tmp_path / "runtime.db"
    now = datetime.now(UTC)
    current = now.isoformat()
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
    connection.executemany(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
        [
            ("proxiware_qualification_worker_status", "degraded", current),
            ("proxiware_qualification_worker_heartbeat_at", current, current),
        ],
    )
    connection.commit()
    connection.close()

    observation = _database_observation(database, now=now)

    assert observation["heartbeats"]["qualification_worker"]["reason"] == "degraded"


def test_runtime_observation_uses_disabled_adapter_over_old_browser_heartbeat(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    database = tmp_path / "runtime.db"
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)")
    connection.executemany(
        "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)",
        [
            ("proxiware_browser_worker_status", "sleeping", old),
            ("proxiware_browser_worker_heartbeat_at", old, old),
        ],
    )
    connection.commit()
    connection.close()
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_BROWSER_ENABLED", "0")

    observation = proxiware_preflight.collect_runtime_observation(
        database_path=database,
        backup_root=tmp_path / "backups",
        local_health_url="",
        public_health_url="",
    )

    assert observation["heartbeats"]["browser_worker"]["status"] == "disabled"
    assert observation["heartbeats"]["browser_worker"]["reason"] == "disabled"


def test_preflight_is_redacted_and_keeps_mutations_disabled(tmp_path):
    report = run_preflight(tmp_path / "preflight.db")

    assert report["ok"] is True
    assert report["checks"]["schema"] is True
    assert report["checks"]["auto_swap_default_off"] is True
    assert report["checks"]["distribution_default_off"] is True
    assert report["checks"]["automation_pause_default_off"] is True
    assert report["checks"]["dry_run_no_mutation"] is True
    assert report["checks"]["admin_route_protected"] is True
    serialized = json.dumps(report, sort_keys=True)
    assert "preflight-secret" not in serialized
    assert "api-key" not in serialized
    assert "captcha-token" not in serialized


def test_preflight_does_not_contact_provider_or_claim_jobs(tmp_path):
    report = run_preflight(tmp_path / "preflight.db")

    assert report["provider_calls"] == 0
    assert report["swap_calls"] == 0
    assert report["checks"]["no_provider_mutation"] is True
    assert report["checks"]["no_active_swap_claim"] is True


def test_preflight_reports_release_workers_health_and_session_without_secrets(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    monkeypatch.setattr(
        proxiware_preflight,
        "collect_runtime_observation",
        lambda **_kwargs: {
            "release": {
                "current_path": "/opt/earn-proxy-abc1234",
                "current_exists": True,
                "rollback_path": "/opt/earn-proxy-old1234",
                "rollback_exists": True,
            },
            "services": {
                "earn-proxy-web": {"enabled": True, "active": True},
                "earn-proxy-proxiware-browser": {"enabled": True, "active": True},
            },
            "heartbeats": {"browser_worker": {"reason": "ok", "age_seconds": 3.0, "status": "ok"}},
            "adapter": {"state": "disabled", "cdp_loopback": True},
            "session": {"state": "active", "expires_at": "2026-09-26T12:00:00+00:00"},
            "health": {
                "local": {"ok": True, "code": "http_200"},
                "public": {"ok": True, "code": "http_200"},
            },
            "backup": {"target": "/var/backups/earn-proxy/latest", "exists": True},
        },
    )

    report = run_preflight(tmp_path / "preflight.db", production=True)

    assert report["checks"]["runtime_observation"] is True
    assert report["release"]["current_path"].startswith("/opt/earn-proxy-")
    assert report["services"]["earn-proxy-web"]["active"] is True
    assert report["heartbeats"]["browser_worker"]["age_seconds"] == 3.0
    assert report["session"]["state"] == "active"
    serialized = __import__("json").dumps(report, sort_keys=True)
    assert "password" not in serialized.lower()
    assert "api-key" not in serialized.lower()


def test_preflight_counts_only_instrumented_provider_mutations(tmp_path):
    report = run_preflight(tmp_path / "preflight.db")

    assert report["provider_mutation_calls"] == 0
    assert report["checks"]["unavailable_adapter_fail_closed"] is True


def test_production_preflight_does_not_report_ready_when_runtime_evidence_is_missing(tmp_path):
    report = run_preflight(tmp_path / "missing.db", production=True, local_health_url="", public_health_url="")

    assert report["ok"] is False
    assert report["checks"]["database_readable"] is False
    assert report["checks"]["release_active"] is False
    assert report["checks"]["services_active"] is False
    assert report["checks"]["local_health_ok"] is False
    assert report["checks"]["public_health_ok"] is False


def test_runtime_observation_validates_enabled_chrome_binary_and_ephemeral_profile(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    binary = tmp_path / "google-chrome"
    binary.write_text("")
    profile_root = tmp_path / "runtime"
    profile_dir = profile_root / "profile"
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_CHROME_ENABLED", "1")
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_CHROME_BINARY", str(binary))
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT", str(profile_root))
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("EARN_PROXY_PROXIWARE_CDP_URL", "http://127.0.0.1:9222")
    monkeypatch.setattr(proxiware_preflight.os, "access", lambda _path, _mode: True)

    observation = proxiware_preflight._adapter_state()

    assert observation["chrome_enabled"] is True
    assert observation["binary_exists"] is True
    assert observation["binary_executable"] is True
    assert observation["profile_isolated"] is True


def test_runtime_observation_selects_backup_by_mtime_not_directory_name(tmp_path):
    backup_root = tmp_path / "backups"
    old = backup_root / "pre-f7b994f-20260905T030109Z"
    newest = backup_root / "20260926T012017Z-82d5959"
    old.mkdir(parents=True)
    newest.mkdir()
    old.touch()
    newest.touch()
    import os

    os.utime(old, (100, 100))
    os.utime(newest, (200, 200))

    from scripts.proxiware_preflight import collect_runtime_observation

    observation = collect_runtime_observation(
        database_path=tmp_path / "missing.db",
        backup_root=backup_root,
        local_health_url="",
        public_health_url="",
    )

    assert observation["backup"]["target"].endswith("20260926T012017Z-82d5959")


def test_production_preflight_rejects_enabled_chrome_with_invalid_runtime(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    monkeypatch.setattr(
        proxiware_preflight,
        "collect_runtime_observation",
        lambda **_kwargs: {
            "release": {"current_exists": True},
            "services": {name: {"enabled": True, "active": True} for name in proxiware_preflight.PROVIDER_SERVICES},
            "database": {"readable": True},
            "settings": {"auto_swap": "0", "distribution": "0"},
            "adapter": {
                "cdp_loopback": True,
                "mutation_allowed": False,
                "chrome_enabled": True,
                "binary_executable": False,
                "profile_isolated": False,
            },
            "health": {"local": {"ok": True}, "public": {"ok": True}},
        },
    )

    report = proxiware_preflight.run_preflight(tmp_path / "db", production=True)

    assert report["ok"] is False
    assert report["checks"]["chrome_binary_ready"] is False
    assert report["checks"]["chrome_profile_isolated"] is False


def test_production_preflight_rejects_stale_required_worker_heartbeat(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    monkeypatch.setattr(
        proxiware_preflight,
        "collect_runtime_observation",
        lambda **_kwargs: {
            "release": {"current_exists": True},
            "services": {name: {"enabled": True, "active": True} for name in proxiware_preflight.PROVIDER_SERVICES},
            "database": {"readable": True},
            "settings": {"auto_swap": "0", "distribution": "0"},
            "heartbeats": {
                "sync_worker": {"reason": "ok"},
                "qualification_worker": {"reason": "stale_or_missing"},
                "swap_worker": {"reason": "disabled"},
                "browser_worker": {"reason": "disabled"},
            },
            "adapter": {
                "cdp_loopback": True,
                "mutation_allowed": False,
                "chrome_enabled": False,
                "binary_executable": True,
                "profile_isolated": True,
            },
            "health": {"local": {"ok": True}, "public": {"ok": True}},
        },
    )

    report = proxiware_preflight.run_preflight(tmp_path / "db", production=True)

    assert report["ok"] is False
    assert report["checks"]["worker_heartbeats_ready"] is False


def test_production_preflight_rejects_missing_required_worker_heartbeat(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    monkeypatch.setattr(
        proxiware_preflight,
        "collect_runtime_observation",
        lambda **_kwargs: {
            "release": {"current_exists": True},
            "services": {name: {"enabled": True, "active": True} for name in proxiware_preflight.PROVIDER_SERVICES},
            "database": {"readable": True},
            "settings": {"auto_swap": "0", "distribution": "0"},
            "heartbeats": {"sync_worker": {"reason": "ok"}},
            "adapter": {
                "cdp_loopback": True,
                "mutation_allowed": False,
                "chrome_enabled": False,
                "binary_executable": True,
                "profile_isolated": True,
            },
            "health": {"local": {"ok": True}, "public": {"ok": True}},
        },
    )

    report = proxiware_preflight.run_preflight(tmp_path / "db", production=True)

    assert report["ok"] is False
    assert report["checks"]["worker_heartbeats_ready"] is False


def test_production_preflight_checks_every_production_unit(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    assert {
        "earn-proxy-web",
        "earn-proxy-checker",
        "earn-proxy-earnapp",
        "earn-proxy-maintenance",
        "earn-proxy-payout-verifier",
        "earn-proxy-proxiware",
        "earn-proxy-proxiware-qualification",
        "earn-proxy-proxiware-swap",
        "earn-proxy-proxiware-cdp-acl",
        "earn-proxy-proxiware-chrome",
        "earn-proxy-proxiware-browser",
    } == set(proxiware_preflight.PROVIDER_SERVICES)


def test_release_metadata_is_used_when_preflight_runs_from_archived_release(tmp_path, monkeypatch):
    from scripts import proxiware_preflight

    release = tmp_path / "earn-proxy-abc1234"
    release.mkdir()
    (release / ".release-metadata").write_text(
        "revision=abc1234\nbranch=main\norigin_main=abc1234\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(proxiware_preflight, "ROOT", tmp_path / "no-git-checkout")

    state = proxiware_preflight._git_state(release)

    assert state == {"branch": "main", "head": "abc1234", "origin_main": "abc1234"}
