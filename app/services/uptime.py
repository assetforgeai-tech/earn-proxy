from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


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


def uptime_hours(
    row,
    *,
    now: datetime | None = None,
    earning_enabled: bool = True,
    health_stale_minutes: int | None = None,
    earning_online_seconds: int | None = None,
) -> UptimeHours:
    current = _as_utc(now or datetime.now(UTC))
    online = (
        max(0, int(earning_online_seconds))
        if earning_enabled and earning_online_seconds is not None
        else (max(0, int(row["accumulated_online_seconds"] or 0)) if earning_enabled else 0)
    )
    offline = max(0, int(row["accumulated_offline_seconds"] or 0))
    if earning_online_seconds is None and row["status"] in {"online", "suspect"} and row["online_since"]:
        observed_until = current
        if health_stale_minutes is not None and not row["last_success_at"]:
            observed_until = _as_utc(row["online_since"])
        elif health_stale_minutes is not None:
            observed_until = min(
                current,
                _as_utc(row["last_success_at"]) + timedelta(minutes=max(0, int(health_stale_minutes))),
            )
        if earning_enabled:
            online += max(0, int((observed_until - _as_utc(row["online_since"])).total_seconds()))
    elif row["status"] in {"offline", "blocked"} and row["offline_since"]:
        offline += max(0, int((current - _as_utc(row["offline_since"])).total_seconds()))
    return UptimeHours(
        round(online / 3600, 2),
        round(offline / 3600, 2),
        format_duration(online),
        format_duration(offline),
    )


def _as_utc(value: str | datetime) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
