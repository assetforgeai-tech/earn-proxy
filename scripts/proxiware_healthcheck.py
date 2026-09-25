"""Read-only healthcheck for Proxiware worker heartbeat state."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class WorkerHealth:
    ok: bool
    reason: str
    status: str = ""
    heartbeat_at: str = ""
    age_seconds: float | None = None


def check_worker_health(db, worker: str, *, max_age_seconds: int = 600, now: datetime | None = None) -> WorkerHealth:
    name = str(worker or "").strip().lower().replace("-", "_")
    if name not in {"sync_worker", "qualification_worker", "browser_worker", "swap_worker"}:
        return WorkerHealth(False, "invalid_worker")
    status_row = db.execute("SELECT value FROM settings WHERE key=?", (f"proxiware_{name}_status",)).fetchone()
    heartbeat_row = db.execute("SELECT value FROM settings WHERE key=?", (f"proxiware_{name}_heartbeat_at",)).fetchone()
    status = str(status_row["value"] if status_row else "unknown")
    heartbeat = str(heartbeat_row["value"] if heartbeat_row else "")
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
    from app import create_app
    from app.db import get_db

    parser = argparse.ArgumentParser(description="Check a Proxiware worker heartbeat")
    parser.add_argument("worker")
    parser.add_argument("--max-age-seconds", type=int, default=600)
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        result = check_worker_health(get_db(), args.worker, max_age_seconds=args.max_age_seconds)
    print(result.reason)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
