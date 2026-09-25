"""Read-only, credential-safe observation of the Proxiware dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Protocol


class DashboardObservationError(ValueError):
    """Raised when a dashboard snapshot cannot be trusted."""


@dataclass(frozen=True)
class DashboardAssignment:
    assignment_id: str
    subscription_id: str
    address: str
    eligible: bool | None
    connections: int | None
    observed_at: datetime


class DashboardTransport(Protocol):
    def request_json(self, method: str, path: str, *, body: Any = None) -> Any: ...


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _required_text(value: object, label: str, *, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ord(ch) < 32 for ch in text):
        raise DashboardObservationError(f"invalid dashboard {label}")
    return text


def _optional_bool(value: object) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise DashboardObservationError("invalid dashboard eligibility")


def _optional_connections(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise DashboardObservationError("invalid dashboard connections") from None
    if result < 0 or result > 1_000_000:
        raise DashboardObservationError("invalid dashboard connections")
    return result


class ProxiwareDashboardObserver:
    """Parse one read-only dashboard response through an injected transport."""

    def __init__(self, transport: DashboardTransport, *, now: Callable[[], datetime] | None = None):
        self.transport = transport
        self.now = now or (lambda: datetime.now(UTC))

    def observe(self, *, subscription_id: str) -> list[DashboardAssignment]:
        requested_subscription = _required_text(subscription_id, "subscription id")
        payload = self.transport.request_json("GET", "/api/static/networks/isp/proxies", body=None)
        if not isinstance(payload, dict) or not isinstance(payload.get("proxies"), list):
            raise DashboardObservationError("invalid dashboard response")
        observed_at = _utc(self.now())
        rows: list[DashboardAssignment] = []
        for raw in payload["proxies"]:
            if not isinstance(raw, dict):
                raise DashboardObservationError("invalid dashboard assignment")
            current_subscription = _required_text(raw.get("subscription_id"), "subscription id")
            if current_subscription != requested_subscription:
                continue
            rows.append(
                DashboardAssignment(
                    assignment_id=_required_text(raw.get("assignment_id"), "assignment id"),
                    subscription_id=current_subscription,
                    address=_required_text(raw.get("addr"), "address"),
                    eligible=_optional_bool(raw.get("eligible")),
                    connections=_optional_connections(raw.get("connections")),
                    observed_at=observed_at,
                )
            )
        return rows


def _ensure_observation_columns(db) -> None:
    columns = {str(row["name"]) for row in db.execute('PRAGMA table_info("provider_assignments")').fetchall()}
    for name, definition in {
        "dashboard_assignment_id": "TEXT",
        "dashboard_eligible": "INTEGER",
        "dashboard_connections": "INTEGER",
        "dashboard_observed_at": "TEXT",
        "dashboard_source": "TEXT NOT NULL DEFAULT ''",
        "dashboard_error_code": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if name not in columns:
            db.execute(f'ALTER TABLE provider_assignments ADD COLUMN "{name}" {definition}')


def apply_dashboard_observation(
    db,
    snapshot: DashboardAssignment,
    *,
    now: datetime | None = None,
    max_age_seconds: int = 900,
) -> int:
    """Attach one trusted dashboard row to its normalized provider assignment."""

    from app.services.proxiware_swap import ensure_proxiware_swap_schema

    ensure_proxiware_swap_schema(db)
    _ensure_observation_columns(db)
    current = _utc(now or datetime.now(UTC))
    observed = _utc(snapshot.observed_at)
    age = (current - observed).total_seconds()
    if age < -60 or age > max(1, int(max_age_seconds)):
        raise DashboardObservationError("stale dashboard observation")
    row = db.execute(
        "SELECT pa.id FROM provider_assignments pa "
        "JOIN provider_subscriptions ps ON ps.id=pa.subscription_id "
        "WHERE pa.provider='proxiware' AND ps.provider='proxiware' AND ps.external_id=? "
        "AND pa.host=? AND pa.missing_at IS NULL ORDER BY pa.id DESC LIMIT 1",
        (snapshot.subscription_id, snapshot.address),
    ).fetchone()
    if row is None:
        raise DashboardObservationError("dashboard assignment not found")
    db.execute(
        "UPDATE provider_assignments SET dashboard_assignment_id=?, dashboard_eligible=?, "
        "dashboard_connections=?, dashboard_observed_at=?, dashboard_source='provider_dashboard', "
        "provider_eligible=CASE WHEN ? IS NULL THEN provider_eligible ELSE ? END, "
        "dashboard_error_code='', updated_at=? WHERE id=? AND provider='proxiware'",
        (
            snapshot.assignment_id,
            None if snapshot.eligible is None else int(snapshot.eligible),
            snapshot.connections,
            observed.isoformat(),
            snapshot.eligible,
            None if snapshot.eligible is None else int(snapshot.eligible),
            current.isoformat(),
            int(row["id"]),
        ),
    )
    db.commit()
    return int(row["id"])


__all__ = [
    "DashboardAssignment",
    "DashboardObservationError",
    "DashboardTransport",
    "ProxiwareDashboardObserver",
    "apply_dashboard_observation",
]
