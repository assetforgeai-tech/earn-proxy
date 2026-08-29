from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.earnapp_probe import classify_verdict
from app.services.earnings import accrue_eligible_time, reset_probation
from app.services.proxies import promote_duplicate_if_due, reconcile_exit_ip
from app.services.settings import get_setting

DEFAULT_HEALTH_INTERVAL_MINUTES = 60
DEFAULT_HEALTH_CONCURRENCY = 5
MAX_HEALTH_CONCURRENCY = 5


@dataclass(frozen=True)
class CheckerSettings:
    health_interval_minutes: int
    health_concurrency: int
    earnapp_refresh_hours: int


def checker_settings(db) -> CheckerSettings:
    def bounded_int(key: str, default: int, lower: int, upper: int) -> int:
        try:
            value = int(get_setting(db, key, str(default)))
        except (TypeError, ValueError):
            value = default
        return max(lower, min(upper, value))

    return CheckerSettings(
        health_interval_minutes=bounded_int("health_interval_minutes", DEFAULT_HEALTH_INTERVAL_MINUTES, 15, 1440),
        health_concurrency=bounded_int("health_concurrency", DEFAULT_HEALTH_CONCURRENCY, 1, MAX_HEALTH_CONCURRENCY),
        earnapp_refresh_hours=bounded_int("earnapp_refresh_hours", 168, 24, 720),
    )


def batch_spacing_seconds(db, *, due_count: int) -> float:
    """Spread bounded batches across the interval instead of checking the whole pool at once."""
    settings = checker_settings(db)
    batches = max(
        1,
        (max(0, int(due_count)) + settings.health_concurrency - 1) // settings.health_concurrency,
    )
    return max(0.25, min(30.0, settings.health_interval_minutes * 60 / batches))


def operational_stats(db) -> dict[str, int | float]:
    counts = {
        row["status"]: int(row["count"])
        for row in db.execute(
            "SELECT status, COUNT(*) AS count FROM proxies WHERE archived_at IS NULL GROUP BY status"
        ).fetchall()
    }
    eligibility = {
        row["eligibility"]: int(row["count"])
        for row in db.execute(
            "SELECT eligibility, COUNT(*) AS count FROM proxies WHERE archived_at IS NULL GROUP BY eligibility"
        ).fetchall()
    }
    now = datetime.now(UTC)
    due = db.execute(
        "SELECT COUNT(*) AS count, MIN(next_check_at) AS oldest FROM proxies WHERE archived_at IS NULL AND next_check_at <= ?",
        (now.isoformat(),),
    ).fetchone()
    lag_minutes = 0.0
    if due["oldest"]:
        oldest = datetime.fromisoformat(due["oldest"])
        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=UTC)
        lag_minutes = max(0.0, (now - oldest).total_seconds() / 60)
    return {
        "total": sum(counts.values()),
        "online": counts.get("online", 0),
        "offline": counts.get("offline", 0),
        "pending": counts.get("pending", 0),
        "allow": eligibility.get("allow", 0),
        "risk": eligibility.get("risk", 0),
        "due": int(due["count"]),
        "lag_minutes": round(lag_minutes, 1),
    }


def claim_due_proxies(db, *, now: datetime | None = None, limit: int | None = None):
    current = now or datetime.now(UTC)
    settings = checker_settings(db)
    batch_size = max(1, min(limit or settings.health_concurrency, settings.health_concurrency))
    try:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute(
            """
            SELECT * FROM proxies
            WHERE archived_at IS NULL
              AND ((next_check_at IS NULL OR next_check_at <= ?) OR (check_claimed_until IS NOT NULL AND check_claimed_until <= ?))
              AND (check_claimed_until IS NULL OR check_claimed_until <= ?)
            ORDER BY COALESCE(next_check_at, created_at), id
            LIMIT ?
            """,
            (current.isoformat(), current.isoformat(), current.isoformat(), batch_size),
        ).fetchall()
        if not rows:
            db.commit()
            return []
        next_check = current + timedelta(minutes=settings.health_interval_minutes)
        claimed_until = current + timedelta(minutes=10)
        claim_token = secrets.token_urlsafe(18)
        db.executemany(
            "UPDATE proxies SET next_check_at=?, check_claimed_until=?, check_claim_token=? WHERE id=?",
            [(next_check.isoformat(), claimed_until.isoformat(), claim_token, row["id"]) for row in rows],
        )
        db.commit()
        placeholders = ",".join("?" for _ in rows)
        return db.execute(
            f"SELECT * FROM proxies WHERE check_claim_token=? AND id IN ({placeholders}) ORDER BY id",
            [claim_token, *[row["id"] for row in rows]],
        ).fetchall()
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise


def claim_due_earnapp(db, *, now: datetime | None = None, limit: int = 5):
    current = now or datetime.now(UTC)
    try:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute(
            """
            SELECT * FROM proxies WHERE archived_at IS NULL AND status='online'
              AND (earnapp_next_check_at IS NULL OR earnapp_next_check_at <= ?)
              AND (earnapp_claimed_until IS NULL OR earnapp_claimed_until <= ?)
            ORDER BY COALESCE(earnapp_next_check_at, created_at), id LIMIT ?
            """,
            (
                current.isoformat(),
                current.isoformat(),
                max(1, min(MAX_HEALTH_CONCURRENCY, int(limit))),
            ),
        ).fetchall()
        if not rows:
            db.commit()
            return []
        claimed_until = current + timedelta(minutes=10)
        claim_token = secrets.token_urlsafe(18)
        db.executemany(
            "UPDATE proxies SET earnapp_claimed_until=?, earnapp_claim_token=? WHERE id=?",
            [(claimed_until.isoformat(), claim_token, row["id"]) for row in rows],
        )
        db.commit()
        placeholders = ",".join("?" for _ in rows)
        return db.execute(
            f"SELECT * FROM proxies WHERE earnapp_claim_token=? AND id IN ({placeholders}) ORDER BY id",
            [claim_token, *[row["id"] for row in rows]],
        ).fetchall()
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise


def apply_earnapp_result(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    verdict = str(result.get("verdict") or "UNKNOWN")
    reason = str(result.get("reason") or "")
    eligibility = classify_verdict(verdict, reason)
    refresh = checker_settings(db).earnapp_refresh_hours
    previous = db.execute(
        "SELECT eligibility, credential_generation, earnapp_claim_token, archived_at FROM proxies WHERE id=?",
        (proxy_id,),
    ).fetchone()
    if previous is None or previous["archived_at"] is not None:
        return
    expected_generation = result.get("_credential_generation")
    expected_claim = result.get("_earnapp_claim_token")
    if expected_generation is not None and int(previous["credential_generation"] or 1) != int(expected_generation):
        return
    if expected_claim is not None and str(previous["earnapp_claim_token"] or "") != str(expected_claim):
        return
    previous_eligibility = str(previous["eligibility"] if previous else "")
    changed = previous is not None and previous_eligibility != eligibility
    if changed and previous_eligibility == "allow":
        # Capture the last eligible interval before invalidating its cycle.
        accrue_eligible_time(db, now=current)
    reset = previous is not None and previous_eligibility != eligibility
    if reset:
        reset_probation(db, proxy_id, current)
    db.execute(
        """
        UPDATE proxies SET eligibility=?, earnapp_verdict=?, earnapp_reason=?, earnapp_checked_at=?,
            earnapp_next_check_at=?, earnapp_claimed_until=NULL, earnapp_claim_token=NULL,
            probation_started_at=CASE WHEN ? THEN ? ELSE probation_started_at END,
            accrual_cursor_at=CASE WHEN ? THEN ? ELSE accrual_cursor_at END, updated_at=? WHERE id=?
        """,
        (
            eligibility,
            verdict[:60],
            reason[:300],
            current.isoformat(),
            (current + timedelta(hours=refresh)).isoformat(),
            int(reset),
            current.isoformat(),
            int(reset),
            current.isoformat(),
            current.isoformat(),
            proxy_id,
        ),
    )
    db.commit()


def apply_health_result(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    status = str(result.get("status") or "inconclusive")
    row = db.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if row is None or row["archived_at"] is not None:
        return
    expected_generation = result.get("_credential_generation")
    expected_claim = result.get("_check_claim_token")
    if expected_generation is not None and int(row["credential_generation"] or 1) != int(expected_generation):
        return
    if expected_claim is not None and str(row["check_claim_token"] or "") != str(expected_claim):
        return

    if status in {"live", "live_unverified"}:
        online_since = row["online_since"] or current.isoformat()
        recovered_from_offline = row["status"] == "offline"
        accumulated_offline = int(row["accumulated_offline_seconds"] or 0)
        if row["status"] == "offline" and row["offline_since"]:
            accumulated_offline += max(
                0,
                int((current - datetime.fromisoformat(row["offline_since"])).total_seconds()),
            )
        previous_exit_ip = str(row["exit_ip"] or "")
        next_exit_ip = str(result.get("exit_ip") or previous_exit_ip)
        egress_changed = bool(previous_exit_ip and next_exit_ip and previous_exit_ip != next_exit_ip)
        if egress_changed:
            reset_probation(db, proxy_id, current)
        db.execute(
            """
            UPDATE proxies SET status='online', detected_protocol=?, consecutive_failures=0,
                online_since=?, offline_since=NULL, last_checked_at=?, check_claimed_until=NULL, check_claim_token=NULL,
                accumulated_offline_seconds=?, continuous_dead_since=NULL, egress_verified_at=?, eligibility=?, earnapp_next_check_at=?, probation_started_at=?,
                accrual_cursor_at=?, last_error=?, updated_at=? WHERE id=?
            """,
            (
                result.get("protocol") or row["detected_protocol"],
                online_since,
                current.isoformat(),
                accumulated_offline,
                (
                    current.isoformat()
                    if next_exit_ip and (not row["egress_verified_at"] or egress_changed)
                    else row["egress_verified_at"]
                ),
                "pending" if egress_changed else row["eligibility"],
                current.isoformat() if egress_changed else row["earnapp_next_check_at"],
                current.isoformat() if recovered_from_offline or egress_changed else row["probation_started_at"],
                current.isoformat() if recovered_from_offline or egress_changed else row["accrual_cursor_at"],
                str(result.get("error") or "")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        if result.get("exit_ip"):
            reconcile_exit_ip(db, proxy_id, str(result["exit_ip"]))
        return

    if status == "inconclusive":
        db.execute(
            "UPDATE proxies SET last_checked_at=?, check_claimed_until=NULL, check_claim_token=NULL, last_error=?, updated_at=? WHERE id=?",
            (
                current.isoformat(),
                str(result.get("error") or "")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        return

    if status == "blocked":
        if row["eligibility"] == "allow":
            accrue_eligible_time(db, now=current)
        reset_probation(db, proxy_id, current)
        db.execute(
            "UPDATE proxies SET status='blocked', eligibility='risk', consecutive_failures=0, last_checked_at=?, check_claimed_until=NULL, check_claim_token=NULL, last_error=?, updated_at=? WHERE id=?",
            (
                current.isoformat(),
                str(result.get("error") or "provider blocked")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        db.commit()
        return

    failures = int(row["consecutive_failures"] or 0) + 1
    offline = failures >= 3
    accumulated_online = int(row["accumulated_online_seconds"] or 0)
    if offline and row["eligibility"] == "allow" and row["status"] == "online":
        # Accrue the final confirmed online interval before changing the row
        # to offline; the ledger query intentionally only reads online rows.
        accrue_eligible_time(db, now=current)
    if offline and row["status"] == "online" and row["online_since"]:
        accumulated_online += max(
            0,
            int((current - datetime.fromisoformat(row["online_since"])).total_seconds()),
        )
    db.execute(
        """
        UPDATE proxies SET status=?, consecutive_failures=?, offline_since=?, online_since=?,
            accumulated_online_seconds=?, continuous_dead_since=?, last_checked_at=?, check_claimed_until=NULL, check_claim_token=NULL, last_error=?, updated_at=? WHERE id=?
        """,
        (
            "offline" if offline else row["status"],
            failures,
            (row["offline_since"] or current.isoformat()) if offline else row["offline_since"],
            None if offline else row["online_since"],
            accumulated_online,
            (row["continuous_dead_since"] or current.isoformat()) if offline else row["continuous_dead_since"],
            current.isoformat(),
            str(result.get("error") or "")[:500],
            current.isoformat(),
            proxy_id,
        ),
    )
    db.commit()
    if offline:
        reset_probation(db, proxy_id, current)
        db.commit()


def archive_due_dead_proxies(db, *, now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    cutoff = (current - timedelta(hours=24)).isoformat()
    candidates = db.execute(
        "SELECT id FROM proxies WHERE archived_at IS NULL AND status='offline' AND continuous_dead_since IS NOT NULL AND continuous_dead_since <= ?",
        (cutoff,),
    ).fetchall()
    for row in candidates:
        # Re-home an online duplicate before archiving its old canonical row.
        promote_duplicate_if_due(db, int(row["id"]), now=current)
    cursor = db.execute(
        "UPDATE proxies SET status='archived', archived_at=?, updated_at=? WHERE archived_at IS NULL AND status='offline' AND continuous_dead_since IS NOT NULL AND continuous_dead_since <= ?",
        (current.isoformat(), current.isoformat(), cutoff),
    )
    db.commit()
    return int(cursor.rowcount)
