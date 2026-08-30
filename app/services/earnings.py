from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.services.settings import get_setting

US_MONTHLY_MICRO_USD = 1_000_000
NON_US_MONTHLY_MICRO_USD = 500_000
MONTH_HOURS = 720
PROBATION_HOURS = 168
DEFAULT_HEALTH_STALE_MINUTES = 120


@dataclass(frozen=True)
class Balances:
    pending_micro_usd: int
    available_micro_usd: int


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        # A legacy/corrupt timestamp must not take the maintenance worker down;
        # callers deliberately treat an invalid value as an unobserved interval.
        return None


def _health_stale_minutes(db) -> int:
    try:
        value = int(get_setting(db, "health_stale_minutes", str(DEFAULT_HEALTH_STALE_MINUTES)))
    except (TypeError, ValueError):
        value = DEFAULT_HEALTH_STALE_MINUTES
    return max(60, min(1440, value))


def expire_pending_cycle(db, proxy_id: int) -> None:
    """Prevent a broken probation cycle from unlocking after a later recovery."""
    db.execute(
        "UPDATE earnings_ledger SET bucket='expired' WHERE proxy_id=? AND bucket='pending'",
        (proxy_id,),
    )


def reset_probation(db, proxy_id: int, at: datetime) -> None:
    """Start a fresh continuous-eligibility clock for a proxy."""
    expire_pending_cycle(db, proxy_id)
    db.execute(
        "UPDATE proxies SET probation_started_at=?, accrual_cursor_at=? WHERE id=?",
        (at.isoformat(), at.isoformat(), proxy_id),
    )


def _add_ledger_entry(
    db,
    *,
    user_id: int,
    proxy_id: int,
    started_at: datetime,
    ended_at: datetime,
    monthly_rate: int,
    bucket: str,
    created_at: datetime,
) -> None:
    duration = max(0, int((ended_at - started_at).total_seconds()))
    if not duration:
        return
    amount = (monthly_rate * duration) // (MONTH_HOURS * 3600)
    db.execute(
        """
        INSERT OR IGNORE INTO earnings_ledger(
            user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            proxy_id,
            started_at.isoformat(),
            ended_at.isoformat(),
            amount,
            bucket,
            created_at.isoformat(),
        ),
    )


def _accrue_eligible_time_locked(
    db, *, current: datetime, proxy_id: int | None = None, include_suspect: bool = False
) -> None:
    statuses = ("online", "suspect") if include_suspect else ("online",)
    placeholders = ",".join("?" for _ in statuses)
    parameters: list[object] = [*statuses]
    proxy_filter = ""
    if proxy_id is not None:
        proxy_filter = " AND p.id=?"
        parameters.append(proxy_id)
    rows = db.execute(
        f"""
        SELECT p.*, u.earn_paused, u.status AS user_status
        FROM proxies p JOIN users u ON u.id=p.user_id
        WHERE p.archived_at IS NULL AND p.status IN ({placeholders}) AND p.eligibility='allow'
          AND p.duplicate_of IS NULL{proxy_filter}
        """,
        parameters,
    ).fetchall()
    stale_minutes = _health_stale_minutes(db)
    for row in rows:
        cursor = _parse(row["accrual_cursor_at"]) or current
        last_success = _parse(row["last_success_at"])
        # A status label alone is not proof that the proxy remained reachable.
        # Legacy/operator rows start accruing only after the new checker records
        # a successful health observation.
        if last_success is None:
            continue
        end = min(current, last_success + timedelta(minutes=stale_minutes))
        if end <= cursor:
            continue
        if row["user_status"] != "active" or row["earn_paused"]:
            db.execute(
                "UPDATE proxies SET accrual_cursor_at=? WHERE id=?",
                (end.isoformat(), row["id"]),
            )
            continue
        monthly_rate = US_MONTHLY_MICRO_USD if row["country_code"] == "US" else NON_US_MONTHLY_MICRO_USD
        seconds = max(0, int((end - cursor).total_seconds()))
        if not seconds:
            continue
        probation = _parse(row["probation_started_at"]) or cursor
        unlock_at = probation + timedelta(hours=PROBATION_HOURS)
        user_id = int(row["user_id"])
        proxy_id = int(row["id"])

        def add_entry(
            started_at: datetime,
            ended_at: datetime,
            bucket: str,
            *,
            entry_user_id: int = user_id,
            entry_proxy_id: int = proxy_id,
            entry_monthly_rate: int = monthly_rate,
        ) -> None:
            _add_ledger_entry(
                db,
                user_id=entry_user_id,
                proxy_id=entry_proxy_id,
                started_at=started_at,
                ended_at=ended_at,
                monthly_rate=entry_monthly_rate,
                bucket=bucket,
                created_at=current,
            )

        if end >= unlock_at:
            # Unlock only the pending entries belonging to this probation
            # cycle; an older cycle may have been invalidated by replacement.
            db.execute(
                "UPDATE earnings_ledger SET bucket='available' WHERE proxy_id=? AND bucket='pending' AND started_at>=?",
                (row["id"], probation.isoformat()),
            )
            if cursor < unlock_at:
                # The observation reaches beyond the probation boundary, so
                # the entire validated pre-boundary interval unlocks atomically.
                add_entry(cursor, unlock_at, "available")
                add_entry(unlock_at, end, "available")
            else:
                add_entry(cursor, end, "available")
        else:
            add_entry(cursor, end, "pending" if end <= unlock_at else "available")
        db.execute(
            "UPDATE proxies SET accrual_cursor_at=? WHERE id=?",
            (end.isoformat(), row["id"]),
        )


def accrue_eligible_time(db, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            # Serialize cursor reads and ledger writes across web/checker
            # processes so the same online interval cannot be paid twice.
            db.execute("BEGIN IMMEDIATE")
        _accrue_eligible_time_locked(db, current=current)
        if owns_transaction:
            db.commit()
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise


def accrue_proxy_time(db, proxy_id: int, *, now: datetime | None = None) -> None:
    """Accrue the last confirmed interval while a proxy transitions through suspect."""
    current = now or datetime.now(UTC)
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            db.execute("BEGIN IMMEDIATE")
        _accrue_eligible_time_locked(db, current=current, proxy_id=proxy_id, include_suspect=True)
        if owns_transaction:
            db.commit()
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise


def balances_for_user(db, user_id: int) -> Balances:
    rows = db.execute(
        "SELECT bucket, COALESCE(SUM(micro_usd), 0) AS amount FROM earnings_ledger WHERE user_id=? GROUP BY bucket",
        (user_id,),
    ).fetchall()
    values = {row["bucket"]: int(row["amount"]) for row in rows}
    return Balances(values.get("pending", 0), values.get("available", 0))
