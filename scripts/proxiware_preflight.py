"""Redacted, no-mutation preflight for the Proxiware provider workspace."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app import create_app
from app.db import get_db
from app.proxiware_swap_service import ProxiwareSwapRunner
from app.services.proxiware_swap import ensure_proxiware_swap_schema
from app.services.settings import get_setting


def _tables(db) -> set[str]:
    return {
        str(row["name"])
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'provider_%' OR name='swap_jobs')"
        ).fetchall()
    }


def run_preflight(database_path: str | Path) -> dict[str, Any]:
    """Run disposable-db checks without contacting Proxiware or mutating a job."""

    database = Path(database_path)
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
    provider_calls = 0
    swap_calls = 0

    class DryRunAdapter:
        def swap(self, _job):
            nonlocal swap_calls
            swap_calls += 1
            raise RuntimeError("dry_run_no_mutation")

    app.extensions["proxiware_swap_adapter_factory"] = lambda: DryRunAdapter()
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

        runner = ProxiwareSwapRunner(app=app, adapter_factory=lambda: DryRunAdapter())
        runner_result = runner.run_once()
        checks["dry_run_no_mutation"] = runner_result == {"status": "disabled"}
        checks["no_active_swap_claim"] = (
            db.execute("SELECT COUNT(*) AS count FROM swap_jobs WHERE state='running'").fetchone()["count"] == 0
        )

    checks["no_provider_mutation"] = provider_calls == 0 and swap_calls == 0
    ok = all(checks.values())
    return {
        "ok": ok,
        "checks": checks,
        "provider_calls": provider_calls,
        "swap_calls": swap_calls,
        "runner_status": "disabled",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a redacted Proxiware no-mutation preflight")
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    report = run_preflight(args.database)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
