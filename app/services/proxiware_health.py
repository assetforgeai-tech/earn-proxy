"""Small durable health markers shared by provider workers and the admin UI."""

from __future__ import annotations

from datetime import UTC, datetime

AUTOMATION_PAUSE_KEY = "proxiware_automation_paused"
RUNTIME_MUTATION_KEYS = ("proxiware_auto_swap", "proxiware_allow_mutation")


def _iso(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC).isoformat()


def set_proxiware_runtime_mutation(db, enabled: bool, *, now: datetime | None = None) -> None:
    """Keep auto-swap and its runtime mutation permission in sync."""

    timestamp = _iso(now)
    value = "1" if enabled else "0"
    for key in RUNTIME_MUTATION_KEYS:
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value, timestamp),
        )


def record_swap_mutation_readiness(
    db,
    ready: bool,
    *,
    error_code: str = "",
    now: datetime | None = None,
) -> None:
    """Persist safe readiness metadata reported by the configured swap worker."""

    timestamp = _iso(now)
    values = {
        "proxiware_swap_worker_mutation_ready": "1" if ready else "0",
        "proxiware_swap_worker_mutation_readiness_at": timestamp,
        "proxiware_swap_worker_mutation_error_code": str(error_code or "").strip().lower()[:64],
    }
    for key, value in values.items():
        db.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value, timestamp),
        )
    db.commit()


def record_worker_heartbeat(
    db,
    worker: str,
    status: str,
    *,
    now: datetime | None = None,
    last_success: bool = False,
    error_code: str = "",
    next_wake_at: datetime | str | None = None,
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
    if next_wake_at is not None:
        values[f"proxiware_{name}_next_wake_at"] = (
            _iso(next_wake_at) if isinstance(next_wake_at, datetime) else str(next_wake_at)[:64]
        )
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


__all__ = [
    "AUTOMATION_PAUSE_KEY",
    "is_proxiware_automation_paused",
    "record_swap_mutation_readiness",
    "record_worker_heartbeat",
    "set_proxiware_runtime_mutation",
]
