"""Read-only, credential-safe observation of the Proxiware dashboard."""

from __future__ import annotations

import ipaddress
import re
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


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


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


def dashboard_address_endpoint(address: str) -> tuple[str, int | None]:
    value = _required_text(address, "address", limit=512)
    if value.startswith("["):
        close = value.find("]")
        if close < 2:
            raise DashboardObservationError("invalid dashboard address")
        host = value[1:close]
        suffix = value[close + 1 :]
        if not suffix:
            port = None
        else:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                raise DashboardObservationError("invalid dashboard address")
            port = int(suffix[1:])
            if not 1 <= port <= 65535:
                raise DashboardObservationError("invalid dashboard address")
    elif value.count(":") == 1:
        host, candidate = value.rsplit(":", 1)
        if candidate.isdigit():
            port = int(candidate)
            if not host or not 1 <= port <= 65535:
                raise DashboardObservationError("invalid dashboard address")
        else:
            host, port = value, None
    else:
        host, port = value, None

    host = host.strip().lower()
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        if len(host) > 253 or host.endswith(".") or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise DashboardObservationError("invalid dashboard address") from None
    return host, port


def normalize_dashboard_address(address: str) -> str:
    host, port = dashboard_address_endpoint(address)
    if port is None:
        return host
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


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
                    address=normalize_dashboard_address(raw.get("addr")),
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

    from app.services.proxiware_swap import ensure_proxiware_swap_schema, reconcile_provider_applied_swaps

    ensure_proxiware_swap_schema(db)
    _ensure_observation_columns(db)
    current = _utc(now or datetime.now(UTC))
    row, observed = _resolved_observation(db, snapshot, current=current, max_age_seconds=max_age_seconds)
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
    reconcile_provider_applied_swaps(db, now=current)
    return int(row["id"])


def _resolved_observation(db, snapshot: DashboardAssignment, *, current: datetime, max_age_seconds: int):
    observed = _utc(snapshot.observed_at)
    age = (current - observed).total_seconds()
    if age < -60 or age > max(1, int(max_age_seconds)):
        raise DashboardObservationError("stale dashboard observation")
    host, port = dashboard_address_endpoint(snapshot.address)
    query = (
        "SELECT pa.id,pa.dashboard_observed_at FROM provider_assignments pa "
        "JOIN provider_subscriptions ps ON ps.id=pa.subscription_id "
        "WHERE pa.provider='proxiware' AND ps.provider='proxiware' AND ps.external_id=? "
        "AND LOWER(pa.host)=? AND pa.missing_at IS NULL"
    )
    params: tuple[object, ...] = (snapshot.subscription_id, host)
    if port is not None:
        query += " AND pa.port=?"
        params += (port,)
    rows = db.execute(query + " ORDER BY pa.id", params).fetchall()
    if not rows:
        raise DashboardObservationError("dashboard assignment not found")
    if len(rows) != 1:
        raise DashboardObservationError("ambiguous dashboard assignment")
    row = rows[0]
    previous = str(row["dashboard_observed_at"] or "").strip()
    if previous:
        try:
            previous_observed = _utc(datetime.fromisoformat(previous))
        except ValueError:
            raise DashboardObservationError("invalid stored dashboard observation") from None
        if observed < previous_observed:
            raise DashboardObservationError("older dashboard observation")
    return row, observed


def apply_dashboard_snapshot(
    db,
    subscription_id: str,
    snapshots: list[DashboardAssignment],
    *,
    now: datetime | None = None,
    max_age_seconds: int = 900,
) -> list[int]:
    """Apply one complete subscription snapshot in a single transaction."""

    from app.services.proxiware_swap import ensure_proxiware_swap_schema

    ensure_proxiware_swap_schema(db)
    _ensure_observation_columns(db)
    current = _utc(now or datetime.now(UTC))
    requested = _required_text(subscription_id, "subscription id")
    if not snapshots:
        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id=NULL,dashboard_eligible=NULL,"
            "dashboard_connections=NULL,dashboard_observed_at=NULL,dashboard_source='',"
            "dashboard_error_code='empty_snapshot',distribution_enabled=0,updated_at=? "
            "WHERE provider='proxiware' AND subscription_id IN ("
            "SELECT id FROM provider_subscriptions WHERE provider='proxiware' AND external_id=?)",
            (current.isoformat(), requested),
        )
        db.commit()
        raise DashboardObservationError("empty dashboard snapshot")

    owns = not db.in_transaction
    if owns:
        db.execute("BEGIN IMMEDIATE")
    try:
        resolved = []
        seen_dashboard_ids: set[str] = set()
        seen_assignment_ids: set[int] = set()
        for snapshot in snapshots:
            if not isinstance(snapshot, DashboardAssignment) or str(snapshot.subscription_id) != requested:
                raise DashboardObservationError("dashboard subscription scope mismatch")
            if snapshot.assignment_id in seen_dashboard_ids:
                raise DashboardObservationError("duplicate dashboard assignment")
            seen_dashboard_ids.add(snapshot.assignment_id)
            row, observed = _resolved_observation(
                db,
                snapshot,
                current=current,
                max_age_seconds=max_age_seconds,
            )
            assignment_id = int(row["id"])
            if assignment_id in seen_assignment_ids:
                raise DashboardObservationError("ambiguous dashboard assignment")
            seen_assignment_ids.add(assignment_id)
            resolved.append((snapshot, assignment_id, observed))

        db.execute(
            "UPDATE provider_assignments SET dashboard_assignment_id=NULL,dashboard_eligible=NULL,"
            "dashboard_connections=NULL,dashboard_observed_at=NULL,dashboard_source='',"
            "dashboard_error_code='not_observed',distribution_enabled=0,updated_at=? "
            "WHERE provider='proxiware' AND subscription_id IN ("
            "SELECT id FROM provider_subscriptions WHERE provider='proxiware' AND external_id=?)",
            (current.isoformat(), requested),
        )
        for snapshot, assignment_id, observed in resolved:
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
                    assignment_id,
                ),
            )
        if owns:
            db.commit()
    except Exception:
        if owns and db.in_transaction:
            db.rollback()
        raise
    from app.services.proxiware_swap import reconcile_provider_applied_swaps

    reconcile_provider_applied_swaps(db, now=current)
    return [assignment_id for _snapshot, assignment_id, _observed in resolved]


__all__ = [
    "DashboardAssignment",
    "DashboardObservationError",
    "DashboardTransport",
    "ProxiwareDashboardObserver",
    "apply_dashboard_observation",
    "apply_dashboard_snapshot",
    "dashboard_address_endpoint",
    "normalize_dashboard_address",
]
