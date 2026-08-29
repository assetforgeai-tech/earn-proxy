from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class UptimeHours:
    online: float
    offline: float


def uptime_hours(row, *, now: datetime | None = None) -> UptimeHours:
    current = now or datetime.now(UTC)
    online = int(row["accumulated_online_seconds"] or 0)
    offline = int(row["accumulated_offline_seconds"] or 0)
    if row["status"] == "online" and row["online_since"]:
        online += max(0, int((current - _as_utc(row["online_since"])).total_seconds()))
    elif row["status"] == "offline" and row["offline_since"]:
        offline += max(0, int((current - _as_utc(row["offline_since"])).total_seconds()))
    return UptimeHours(round(online / 3600, 2), round(offline / 3600, 2))


def _as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
