"""Redacted, no-mutation preflight for the Proxiware provider workspace."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app import create_app
from app.db import get_db
from app.proxiware_swap_service import ProxiwareSwapRunner
from app.services.proxiware_browser import BrowserAdapterUnavailable, UnavailableProxiwareBrowser
from app.services.proxiware_swap import ensure_proxiware_swap_schema
from app.services.settings import get_setting

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_SERVICES = (
    "earn-proxy-web",
    "earn-proxy-proxiware",
    "earn-proxy-proxiware-qualification",
    "earn-proxy-proxiware-swap",
    "earn-proxy-proxiware-chrome",
    "earn-proxy-proxiware-browser",
)
WORKERS = ("sync_worker", "qualification_worker", "swap_worker", "browser_worker")


def _tables(db) -> set[str]:
    return {
        str(row["name"])
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'provider_%' OR name='swap_jobs')"
        ).fetchall()
    }


def _safe_command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_state() -> dict[str, str]:
    return {
        "branch": _safe_command(["git", "-C", str(ROOT), "branch", "--show-current"]),
        "head": _safe_command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "origin_main": _safe_command(["git", "-C", str(ROOT), "rev-parse", "origin/main"]),
    }


def _release_state(release_link: Path) -> dict[str, object]:
    current = ""
    try:
        if release_link.exists() or release_link.is_symlink():
            current = str(release_link.resolve(strict=True))
    except OSError:
        current = ""
    try:
        candidates = sorted(
            (
                path
                for path in release_link.parent.glob(f"{release_link.name}-*")
                if path.is_dir() and str(path.resolve()) != current
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        candidates = []
    rollback = str(candidates[0].resolve()) if candidates else ""
    return {
        "current_path": current,
        "current_exists": bool(current),
        "rollback_path": rollback,
        "rollback_exists": bool(rollback),
    }


def _service_state(name: str) -> dict[str, object]:
    if shutil.which("systemctl") is None:
        return {"enabled": False, "active": False, "code": "systemctl_unavailable"}
    enabled = _safe_command(["systemctl", "is-enabled", name])
    active = _safe_command(["systemctl", "is-active", name])
    return {
        "enabled": enabled == "enabled",
        "active": active == "active",
        "code": "ok" if enabled == "enabled" and active == "active" else "inactive",
    }


def _parse_timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or ""))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _database_observation(database: Path, *, now: datetime) -> dict[str, object]:
    empty = {
        "settings": {"auto_swap": "unknown", "distribution": "unknown", "automation_paused": "unknown"},
        "heartbeats": {},
        "session": {"state": "missing", "expires_at": "", "updated_at": ""},
        "database": {"readable": False, "code": "missing"},
    }
    if not database.is_file():
        return empty
    try:
        db = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
    except sqlite3.Error:
        empty["database"] = {"readable": False, "code": "open_failed"}
        return empty
    try:
        settings = dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'proxiware_%'").fetchall())
        heartbeats: dict[str, dict[str, object]] = {}
        for worker in WORKERS:
            status = str(settings.get(f"proxiware_{worker}_status", "unknown"))
            heartbeat_at = str(settings.get(f"proxiware_{worker}_heartbeat_at", ""))
            parsed = _parse_timestamp(heartbeat_at)
            age = round((now - parsed).total_seconds(), 3) if parsed else None
            heartbeats[worker] = {
                "status": status,
                "heartbeat_at": heartbeat_at,
                "age_seconds": age,
                "reason": "ok" if parsed and age is not None and -60 <= age <= 900 else "stale_or_missing",
            }
        session = {"state": "missing", "expires_at": "", "updated_at": ""}
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='provider_sessions'").fetchone():
            row = db.execute(
                "SELECT state,expires_at,updated_at FROM provider_sessions WHERE provider='proxiware'"
            ).fetchone()
            if row:
                session = {
                    "state": str(row["state"] or "unknown"),
                    "expires_at": str(row["expires_at"] or ""),
                    "updated_at": str(row["updated_at"] or ""),
                }
        return {
            "settings": {
                "auto_swap": str(settings.get("proxiware_auto_swap", "0")),
                "distribution": str(settings.get("proxiware_distribution_enabled", "0")),
                "automation_paused": str(settings.get("proxiware_automation_paused", "0")),
            },
            "heartbeats": heartbeats,
            "session": session,
            "database": {"readable": True, "code": "ok"},
        }
    except sqlite3.Error:
        empty["database"] = {"readable": False, "code": "query_failed"}
        return empty
    finally:
        db.close()


def _health_state(url: str) -> dict[str, object]:
    if not url:
        return {"ok": False, "code": "not_configured"}
    try:
        with urlopen(Request(url, method="GET"), timeout=5) as response:
            status = int(response.status)
        return {"ok": status == 200, "code": f"http_{status}"}
    except HTTPError as exc:
        return {"ok": False, "code": f"http_{int(exc.code)}"}
    except (URLError, OSError, ValueError):
        return {"ok": False, "code": "unreachable"}


def _adapter_state() -> dict[str, object]:
    endpoint = str(os.environ.get("EARN_PROXY_PROXIWARE_CDP_URL") or "http://127.0.0.1:9222").strip()
    parsed = urlparse(endpoint)
    loopback = parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    try:
        port = int(parsed.port or 0)
    except ValueError:
        port = 0
    loopback = loopback and 1 <= port <= 65535
    enabled = os.environ.get("EARN_PROXY_PROXIWARE_BROWSER_ENABLED", "0") == "1"
    dry_run = os.environ.get("EARN_PROXY_PROXIWARE_BROWSER_DRY_RUN", "0") == "1"
    mutation = os.environ.get("EARN_PROXY_PROXIWARE_BROWSER_ALLOW_MUTATION", "0") == "1"
    chrome_enabled = os.environ.get("EARN_PROXY_PROXIWARE_CHROME_ENABLED", "0") == "1"
    binary = Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_BINARY", "/usr/bin/google-chrome"))
    profile_root = Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT", "/run/earn-proxy-browser"))
    profile_dir = Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR", "/run/earn-proxy-browser/profile"))
    binary_exists = binary.is_file()
    binary_executable = binary_exists and os.access(binary, os.X_OK)
    try:
        profile_isolated = profile_root.is_absolute() and profile_dir.is_absolute()
        if profile_isolated:
            profile_dir.resolve().relative_to(profile_root.resolve())
    except (OSError, ValueError):
        profile_isolated = False
    return {
        "state": "dry_run" if dry_run else "enabled" if enabled else "disabled",
        "cdp_loopback": loopback,
        "mutation_allowed": mutation,
        "chrome_enabled": chrome_enabled,
        "binary_exists": binary_exists,
        "binary_executable": binary_executable,
        "profile_isolated": profile_isolated,
    }


def collect_runtime_observation(
    *,
    database_path: str | Path,
    release_link: str | Path = "/opt/earn-proxy",
    backup_root: str | Path = "/var/backups/earn-proxy",
    local_health_url: str = "http://127.0.0.1:8100/healthz",
    public_health_url: str = "",
    now: datetime | None = None,
) -> dict[str, object]:
    """Collect production state read-only; never contact the provider."""

    current = now or datetime.now(UTC)
    current = current.astimezone(UTC) if current.tzinfo else current.replace(tzinfo=UTC)
    database = _database_observation(Path(database_path), now=current)
    backups = Path(backup_root)
    try:
        candidates = sorted(
            (path for path in backups.iterdir() if path.is_dir()), key=lambda path: path.name, reverse=True
        )
        latest_backup = str(candidates[0].resolve()) if candidates else ""
    except OSError:
        latest_backup = ""
    domain = str(os.environ.get("EARN_PROXY_DOMAIN") or "").strip()
    public_url = public_health_url or (f"https://{domain}/healthz" if domain else "")
    return {
        "source": _git_state(),
        "release": _release_state(Path(release_link)),
        "services": {name: _service_state(name) for name in PROVIDER_SERVICES},
        "heartbeats": database["heartbeats"],
        "settings": database["settings"],
        "session": database["session"],
        "database": database["database"],
        "adapter": _adapter_state(),
        "health": {
            "local": _health_state(local_health_url),
            "public": _health_state(public_url),
        },
        "backup": {"target": latest_backup, "exists": bool(latest_backup)},
    }


def _run_disposable_checks(database: Path) -> dict[str, Any]:
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "preflight-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
            "CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
        }
    )
    provider_mutation_calls = 0

    class InstrumentedDryRunAdapter:
        def swap(self, _job):
            nonlocal provider_mutation_calls
            provider_mutation_calls += 1
            raise BrowserAdapterUnavailable("manual_action_required")

    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        required_tables = {
            "provider_subscriptions",
            "provider_assignments",
            "provider_sync_runs",
            "provider_credentials",
            "provider_sessions",
            "provider_audit_events",
            "provider_action_attempts",
            "swap_jobs",
        }
        checks: dict[str, bool] = {
            "schema": required_tables.issubset(_tables(db)),
            "auto_swap_default_off": get_setting(db, "proxiware_auto_swap", "0") == "0",
            "distribution_default_off": get_setting(db, "proxiware_distribution_enabled", "0") == "0",
            "automation_pause_default_off": get_setting(db, "proxiware_automation_paused", "0") == "0",
        }
        before_changes = db.total_changes
        with app.test_client() as client:
            response = client.get("/admin/providers/proxiware")
        checks["admin_route_protected"] = response.status_code in {302, 303, 401, 403}
        checks["get_side_effect_free"] = db.total_changes == before_changes
        runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: InstrumentedDryRunAdapter())
        runner_result = runner.run_once()
        checks["dry_run_no_mutation"] = runner_result == {"status": "disabled"}
        checks["no_active_swap_claim"] = (
            db.execute("SELECT COUNT(*) AS count FROM swap_jobs WHERE state='running'").fetchone()["count"] == 0
        )

    unavailable_fail_closed = False
    try:
        UnavailableProxiwareBrowser().swap({"id": 1})
    except BrowserAdapterUnavailable:
        unavailable_fail_closed = True
    checks["unavailable_adapter_fail_closed"] = unavailable_fail_closed
    checks["no_provider_mutation"] = provider_mutation_calls == 0
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "provider_mutation_calls": provider_mutation_calls,
        "provider_calls": 0,
        "swap_calls": provider_mutation_calls,
        "runner_status": "disabled",
    }


def run_preflight(database_path: str | Path, *, production: bool = False, **runtime_options) -> dict[str, Any]:
    """Run disposable checks or collect a strictly read-only production report."""

    database = Path(database_path)
    if not production:
        return _run_disposable_checks(database)
    observation = collect_runtime_observation(database_path=database, **runtime_options)
    settings = observation.get("settings", {})
    adapter = observation.get("adapter", {})
    services = observation.get("services", {})
    health = observation.get("health", {})
    database_state = observation.get("database", {})
    release = observation.get("release", {})
    checks = {
        "runtime_observation": bool(observation),
        "database_readable": database_state.get("readable") is True,
        "release_active": release.get("current_exists") is True,
        "services_active": bool(services)
        and all(value.get("enabled") is True and value.get("active") is True for value in services.values()),
        "local_health_ok": health.get("local", {}).get("ok") is True,
        "public_health_ok": health.get("public", {}).get("ok") is True,
        "auto_swap_off": settings.get("auto_swap", "0") == "0",
        "distribution_off": settings.get("distribution", "0") == "0",
        "cdp_loopback": adapter.get("cdp_loopback") is True,
        "browser_mutation_off": adapter.get("mutation_allowed") is not True,
        "chrome_binary_ready": adapter.get("chrome_enabled") is not True or adapter.get("binary_executable") is True,
        "chrome_profile_isolated": adapter.get("chrome_enabled") is not True or adapter.get("profile_isolated") is True,
        "no_provider_mutation": True,
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "provider_mutation_calls": 0,
        **observation,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a redacted Proxiware no-mutation preflight")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--public-health-url", default="")
    args = parser.parse_args()
    report = run_preflight(
        args.database,
        production=args.production,
        public_health_url=args.public_health_url,
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
