"""Read-only healthcheck for Proxiware worker heartbeat state."""

from __future__ import annotations

import argparse
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class WorkerHealth:
    ok: bool
    reason: str
    status: str = ""
    heartbeat_at: str = ""
    age_seconds: float | None = None


def check_worker_health(
    db,
    worker: str,
    *,
    max_age_seconds: int = 600,
    now: datetime | None = None,
    configured_enabled: bool | None = None,
) -> WorkerHealth:
    name = str(worker or "").strip().lower().replace("-", "_")
    if name not in {"sync_worker", "qualification_worker", "browser_worker", "swap_worker"}:
        return WorkerHealth(False, "invalid_worker")
    if name == "browser_worker" and configured_enabled is False:
        return WorkerHealth(False, "disabled", status="disabled")
    status_row = db.execute("SELECT value FROM settings WHERE key=?", (f"proxiware_{name}_status",)).fetchone()
    heartbeat_row = db.execute("SELECT value FROM settings WHERE key=?", (f"proxiware_{name}_heartbeat_at",)).fetchone()
    status = str(status_row["value"] if status_row else "unknown")
    heartbeat = str(heartbeat_row["value"] if heartbeat_row else "")
    if status == "disabled":
        return WorkerHealth(False, "disabled", status=status, heartbeat_at=heartbeat)
    if not heartbeat:
        return WorkerHealth(False, "missing", status=status)
    try:
        parsed = datetime.fromisoformat(heartbeat)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        age = (current.astimezone(UTC) - parsed.astimezone(UTC)).total_seconds()
    except ValueError:
        return WorkerHealth(False, "invalid_timestamp", status=status, heartbeat_at=heartbeat)
    if age > max(1, int(max_age_seconds)) or age < -60:
        return WorkerHealth(False, "stale", status=status, heartbeat_at=heartbeat, age_seconds=age)
    if status in {"error", "degraded", "stopped", "blocked", "manual_action_required", "disabled", "paused"}:
        return WorkerHealth(False, status, status=status, heartbeat_at=heartbeat, age_seconds=age)
    return WorkerHealth(True, "ok", status=status, heartbeat_at=heartbeat, age_seconds=age)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a Proxiware worker heartbeat")
    parser.add_argument("worker")
    parser.add_argument("--max-age-seconds", type=int, default=600)
    parser.add_argument("--database", type=Path, help="Read a SQLite database without loading application secrets")
    args = parser.parse_args()
    if args.database is not None:
        database = args.database.expanduser().resolve()
        uri = f"file:{database.as_posix()}?mode=ro"
        browser_enabled = None
        if (
            str(args.worker).strip().lower().replace("-", "_") == "browser_worker"
            and "EARN_PROXY_PROXIWARE_BROWSER_ENABLED" in os.environ
        ):
            browser_enabled = os.environ["EARN_PROXY_PROXIWARE_BROWSER_ENABLED"] == "1"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            result = check_worker_health(
                connection,
                args.worker,
                max_age_seconds=args.max_age_seconds,
                configured_enabled=browser_enabled,
            )
        finally:
            connection.close()
    else:
        from app import create_app
        from app.db import get_db

        app = create_app()
        with app.app_context():
            result = check_worker_health(
                get_db(),
                args.worker,
                max_age_seconds=args.max_age_seconds,
                configured_enabled=(
                    bool(app.config.get("PROXIWARE_BROWSER_ENABLED", False))
                    if str(args.worker).strip().lower().replace("-", "_") == "browser_worker"
                    else None
                ),
            )
    print(result.reason)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
