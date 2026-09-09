from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class UptimeHours:
    online: float
    offline: float
    online_label: str
    offline_label: str


MONTH_SECONDS = 30 * 24 * 60 * 60


def _unit(value: int, singular: str, plural: str) -> str:
    return f"{value} {singular if value == 1 else plural}"


def format_duration(seconds: int) -> str:
    """Render elapsed time in calendar-like units without losing small intervals."""
    remaining = max(0, int(seconds))
    if remaining == 0:
        return "0 hours"

    months, remaining = divmod(remaining, MONTH_SECONDS)
    days, remaining = divmod(remaining, 24 * 60 * 60)
    hours, remaining = divmod(remaining, 60 * 60)
    minutes = remaining // 60
    parts = []
    if months:
        parts.append(_unit(months, "month", "months"))
    if days:
        parts.append(_unit(days, "day", "days"))
    if hours:
        parts.append(_unit(hours, "hour", "hours"))
    if minutes:
        parts.append(_unit(minutes, "minute", "minutes"))
    return " ".join(parts) or "less than 1 minute"


def uptime_hours(row, *, now: datetime | None = None) -> UptimeHours:
    current = now or datetime.now(UTC)
    online = int(row["accumulated_online_seconds"] or 0)
    offline = int(row["accumulated_offline_seconds"] or 0)
    if row["status"] == "online" and row["online_since"]:
        online += max(0, int((current - _as_utc(row["online_since"])).total_seconds()))
    elif row["status"] == "offline" and row["offline_since"]:
        offline += max(0, int((current - _as_utc(row["offline_since"])).total_seconds()))
    return UptimeHours(
        round(online / 3600, 2),
        round(offline / 3600, 2),
        format_duration(online),
        format_duration(offline),
    )


def _as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
