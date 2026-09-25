"""Small durable health markers shared by provider workers and the admin UI."""

from __future__ import annotations

from datetime import UTC, datetime

AUTOMATION_PAUSE_KEY = "proxiware_automation_paused"


def _iso(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat()


def record_worker_heartbeat(
    db,
    worker: str,
    status: str,
    *,
    now: datetime | None = None,
    last_success: bool = False,
    error_code: str = "",
) -> None:
    """Persist only safe worker status metadata; never persist exception text."""

    name = str(worker or "worker").strip().lower().replace("-", "_")
    if not name or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789_" for ch in name):
        raise ValueError("Invalid worker name")
    timestamp = _iso(now)
    values = {
        f"proxiware_{name}_status": str(status or "unknown").strip().lower()[:32],
        f"proxiware_{name}_heartbeat_at": timestamp,
    }
    if error_code:
        values[f"proxiware_{name}_last_error_code"] = str(error_code).strip().lower()[:64]
    if last_success:
        values[f"proxiware_{name}_last_success_at"] = timestamp
    for key, value in values.items():
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value, timestamp),
        )
    db.commit()


def is_proxiware_automation_paused(db) -> bool:
    """Return the provider-scoped emergency pause state."""

    row = db.execute("SELECT value FROM settings WHERE key=?", (AUTOMATION_PAUSE_KEY,)).fetchone()
    return bool(row and str(row["value"] or "").strip() == "1")


__all__ = ["AUTOMATION_PAUSE_KEY", "is_proxiware_automation_paused", "record_worker_heartbeat"]
