from __future__ import annotations

import ipaddress
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.earnapp_probe import classify_verdict
from app.services.earnings import accrue_proxy_time, reset_probation
from app.services.proxies import promote_duplicate_if_due, reconcile_exit_ip
from app.services.settings import get_setting

DEFAULT_HEALTH_INTERVAL_MINUTES = 60
DEFAULT_HEALTH_CONCURRENCY = 5
MAX_HEALTH_CONCURRENCY = 20
DEFAULT_PER_HOST_CONCURRENCY = 2
MAX_PER_HOST_CONCURRENCY = 3


def _normalized_exit_ip(value: object) -> str:
    """Accept only literal IP evidence before it can affect identity state."""
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


@contextmanager
def _serialized_result_write(db):
    """Keep result validation and state mutation in one SQLite write lock."""
    owns_transaction = not db.in_transaction
    if owns_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise
    else:
        if owns_transaction and db.in_transaction:
            db.commit()


@dataclass(frozen=True)
class CheckerSettings:
    health_interval_minutes: int
    health_concurrency: int
    health_per_host_concurrency: int
    health_retry_first_minutes: int
    health_retry_second_minutes: int
    health_stale_minutes: int
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
        health_per_host_concurrency=bounded_int(
            "health_per_host_concurrency", DEFAULT_PER_HOST_CONCURRENCY, 1, MAX_PER_HOST_CONCURRENCY
        ),
        health_retry_first_minutes=bounded_int("health_retry_first_minutes", 5, 1, 30),
        health_retry_second_minutes=bounded_int("health_retry_second_minutes", 15, 2, 60),
        health_stale_minutes=bounded_int("health_stale_minutes", 120, 60, 1440),
        earnapp_refresh_hours=bounded_int("earnapp_refresh_hours", 168, 24, 720),
    )


def batch_spacing_seconds(db, *, due_count: int) -> float:
    """Do not add idle time while durable health work is already overdue."""
    checker_settings(db)
    return 0.0 if int(due_count) > 0 else 1.0


def operational_stats(db, *, now: datetime | None = None) -> dict[str, int | float]:
    settings = checker_settings(db)
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
    now = now or datetime.now(UTC)
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
    stale_cutoff = (now - timedelta(minutes=settings.health_stale_minutes)).isoformat()
    stale = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies WHERE archived_at IS NULL AND status='online' AND (last_success_at IS NULL OR last_success_at < ?)",
            (stale_cutoff,),
        ).fetchone()["count"]
    )
    latencies = [
        int(row["last_latency_ms"])
        for row in db.execute(
            "SELECT last_latency_ms FROM proxies WHERE archived_at IS NULL AND last_latency_ms IS NOT NULL"
        ).fetchall()
    ]
    checked_since = (now - timedelta(minutes=5)).isoformat()
    recent_checks = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies WHERE archived_at IS NULL AND last_checked_at >= ?",
            (checked_since,),
        ).fetchone()["count"]
    )
    return {
        "total": sum(counts.values()),
        "online": counts.get("online", 0),
        "offline": counts.get("offline", 0),
        "pending": counts.get("pending", 0),
        "allow": eligibility.get("allow", 0),
        "risk": eligibility.get("risk", 0),
        "healthy": counts.get("online", 0) - stale,
        "suspect": counts.get("suspect", 0),
        "stale": stale,
        "average_latency_ms": round(sum(latencies) / len(latencies)) if latencies else 0,
        "checks_per_minute": round(recent_checks / 5, 1),
        "due": int(due["count"]),
        "lag_minutes": round(lag_minutes, 1),
    }


def claim_due_proxies(db, *, now: datetime | None = None, limit: int | None = None, per_host_limit: int | None = None):
    current = now or datetime.now(UTC)
    settings = checker_settings(db)
    batch_size = max(1, min(limit or settings.health_concurrency, settings.health_concurrency))
    try:
        db.execute("BEGIN IMMEDIATE")
        due_args = (current.isoformat(), current.isoformat(), current.isoformat())
        if per_host_limit is None:
            rows = db.execute(
                """
                SELECT p.* FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND u.status='active'
                  AND ((p.next_check_at IS NULL OR p.next_check_at <= ?) OR (p.check_claimed_until IS NOT NULL AND p.check_claimed_until <= ?))
                  AND (p.check_claimed_until IS NULL OR p.check_claimed_until <= ?)
                ORDER BY COALESCE(p.next_check_at, p.created_at), p.id
                LIMIT ?
                """,
                (*due_args, batch_size),
            ).fetchall()
        else:
            # Interleave provider hosts for fairness while leaving simultaneous
            # per-host enforcement to the runtime semaphore. SQL must still
            # fill the complete global batch when one provider dominates.
            rows = db.execute(
                """
                WITH ranked AS (
                    SELECT p.*,
                           ROW_NUMBER() OVER (
                               PARTITION BY lower(trim(COALESCE(p.host, '')))
                               ORDER BY COALESCE(p.next_check_at, p.created_at), p.id
                           ) AS host_rank
                    FROM proxies AS p
                    JOIN users AS u ON u.id = p.user_id
                    WHERE p.archived_at IS NULL AND u.status='active'
                      AND ((p.next_check_at IS NULL OR p.next_check_at <= ?)
                           OR (p.check_claimed_until IS NOT NULL AND p.check_claimed_until <= ?))
                      AND (p.check_claimed_until IS NULL OR p.check_claimed_until <= ?)
                )
                SELECT * FROM ranked
                ORDER BY host_rank, COALESCE(next_check_at, created_at), id
                LIMIT ?
                """,
                (*due_args, batch_size),
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
            SELECT p.* FROM proxies AS p
            JOIN users AS u ON u.id = p.user_id
            WHERE p.archived_at IS NULL AND p.status='online' AND u.status='active'
              AND (p.earnapp_next_check_at IS NULL OR p.earnapp_next_check_at <= ?)
              AND (p.earnapp_claimed_until IS NULL OR p.earnapp_claimed_until <= ?)
            ORDER BY COALESCE(p.earnapp_next_check_at, p.created_at), p.id LIMIT ?
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


def release_health_claims(db, claims, *, now: datetime | None = None) -> int:
    """Make unprocessed rows immediately claimable without touching completed claims."""
    current = now or datetime.now(UTC)
    released = 0
    for proxy_id, claim_token in claims:
        cursor = db.execute(
            """
            UPDATE proxies SET next_check_at=?, check_claimed_until=NULL, check_claim_token=NULL
            WHERE id=? AND check_claim_token=?
            """,
            (current.isoformat(), int(proxy_id), str(claim_token or "")),
        )
        released += int(cursor.rowcount)
    db.commit()
    return released


def release_earnapp_claims(db, claims, *, now: datetime | None = None) -> int:
    """Make unprocessed EarnApp rows immediately claimable after shutdown."""
    current = now or datetime.now(UTC)
    released = 0
    for proxy_id, claim_token in claims:
        cursor = db.execute(
            """
            UPDATE proxies SET earnapp_next_check_at=?, earnapp_claimed_until=NULL, earnapp_claim_token=NULL
            WHERE id=? AND earnapp_claim_token=?
            """,
            (current.isoformat(), int(proxy_id), str(claim_token or "")),
        )
        released += int(cursor.rowcount)
    db.commit()
    return released


def apply_earnapp_result(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
    owns_transaction = not db.in_transaction
    if owns_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        _apply_earnapp_result_locked(db, proxy_id, result, now=now)
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise
    else:
        if owns_transaction and db.in_transaction:
            db.commit()


def _apply_earnapp_result_locked(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    verdict = str(result.get("verdict") or "UNKNOWN")
    reason = str(result.get("reason") or "")
    eligibility = classify_verdict(verdict, reason)
    refresh = checker_settings(db).earnapp_refresh_hours
    previous = db.execute(
        "SELECT eligibility, credential_generation, earnapp_claim_token, archived_at, exit_ip, "
        "egress_verified_at FROM proxies WHERE id=?",
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
    result_exit_ip = _normalized_exit_ip(result.get("exit_ip"))
    previous_exit_ip = _normalized_exit_ip(previous["exit_ip"])
    attestation = result.get("egress_trusted")
    # Older direct service callers do not provide an attestation field. Keep
    # their eligibility/country behavior, but only an explicit true from the
    # production probe may establish or reconcile canonical egress identity.
    legacy_result = attestation is None
    authenticated_exit_ip = result_exit_ip if attestation is True else ""
    egress_changed = bool(authenticated_exit_ip and previous_exit_ip and authenticated_exit_ip != previous_exit_ip)
    if verdict == "CID_SET" and not legacy_result and not authenticated_exit_ip:
        eligibility = "pending"
        reason = f"{reason}; missing authenticated egress IP".strip("; ")
    if egress_changed:
        eligibility = "pending"
        reason = f"{reason}; authenticated egress changed".strip("; ")
    country_code = str(result.get("country_code") or "").strip().upper()
    country_evidence_ip = authenticated_exit_ip or (result_exit_ip if legacy_result else "")
    verified_country_code = (
        country_code
        if len(country_code) == 2
        and country_code.isalpha()
        and country_evidence_ip
        and country_evidence_ip == previous_exit_ip
        else ""
    )
    if legacy_result and result_exit_ip and result_exit_ip != previous_exit_ip:
        # Compatibility callers may report a changed address, but that value
        # is not an attested source; retain prior country metadata.
        verified_country_code = ""
    changed = previous is not None and previous_eligibility != eligibility
    if changed and previous_eligibility == "allow":
        # Capture the last eligible interval before invalidating its cycle.
        accrue_proxy_time(db, proxy_id, now=current)
    reset = bool(changed or egress_changed)
    if reset:
        reset_probation(db, proxy_id, current)
    if authenticated_exit_ip:
        # EarnApp supplies ext_ip over its authenticated TLS channel, making it
        # authoritative for duplicate identity and egress changes.
        reconcile_exit_ip(
            db,
            proxy_id,
            authenticated_exit_ip,
            attestation_source="earnapp_tls",
            commit=False,
        )
    db.execute(
        """
        UPDATE proxies SET eligibility=?, earnapp_verdict=?, earnapp_reason=?, earnapp_checked_at=?,
            country_code=CASE WHEN ?<>'' THEN ? ELSE country_code END,
            earnapp_next_check_at=?, earnapp_claimed_until=NULL, earnapp_claim_token=NULL,
            probation_started_at=CASE WHEN ? THEN ? ELSE probation_started_at END,
            accrual_cursor_at=CASE WHEN ? THEN ? ELSE accrual_cursor_at END, updated_at=? WHERE id=?
        """,
        (
            eligibility,
            verdict[:60],
            reason[:300],
            current.isoformat(),
            verified_country_code,
            verified_country_code,
            (current.isoformat() if egress_changed else (current + timedelta(hours=refresh)).isoformat()),
            int(reset),
            current.isoformat(),
            int(reset),
            current.isoformat(),
            current.isoformat(),
            proxy_id,
        ),
    )


def apply_health_result(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
    owns_transaction = not db.in_transaction
    if owns_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        _apply_health_result_locked(db, proxy_id, result, now=now)
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise
    else:
        if owns_transaction and db.in_transaction:
            db.commit()


def _apply_health_result_locked(db, proxy_id: int, result: dict, *, now: datetime | None = None) -> None:
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
    settings = checker_settings(db)
    failure_kind = str(result.get("failure_kind") or "")[:60]
    probe_endpoint = str(result.get("probe_endpoint") or "")[:300]
    try:
        next_probe_index = max(0, int(result.get("next_probe_index", row["next_probe_index"] or 0)))
    except (TypeError, ValueError):
        next_probe_index = int(row["next_probe_index"] or 0)
    try:
        latency_ms = max(0, int(result["latency_ms"])) if result.get("latency_ms") is not None else None
    except (TypeError, ValueError):
        latency_ms = None

    if status in {"live", "live_unverified"}:
        # The checker explicitly marks plain HTTP/insecure evidence as
        # untrusted. Legacy injected hooks that omit the field retain their
        # historical behavior; production checker results always include it.
        egress_trusted = result.get("egress_trusted", True) is True
        recovered_from_offline = row["status"] == "offline"
        accumulated_offline = int(row["accumulated_offline_seconds"] or 0)
        if row["status"] == "offline" and row["offline_since"]:
            accumulated_offline += max(
                0,
                int((current - datetime.fromisoformat(row["offline_since"])).total_seconds()),
            )
        previous_exit_ip = _normalized_exit_ip(row["exit_ip"])
        observed_exit_ip = _normalized_exit_ip(result.get("exit_ip"))
        trusted_exit_ip = observed_exit_ip if egress_trusted else ""
        egress_changed = bool(previous_exit_ip and trusted_exit_ip and previous_exit_ip != trusted_exit_ip)
        untrusted_egress_mismatch = bool(
            not egress_trusted and previous_exit_ip and observed_exit_ip and observed_exit_ip != previous_exit_ip
        )
        missing_trusted_egress = not previous_exit_ip and not trusted_exit_ip
        previous_success = datetime.fromisoformat(row["last_success_at"]) if row["last_success_at"] else None
        stale_recovery = bool(
            row["status"] in {"online", "suspect"}
            and previous_success
            and current > previous_success + timedelta(minutes=settings.health_stale_minutes)
        )
        if (egress_changed or untrusted_egress_mismatch or stale_recovery) and row["eligibility"] == "allow":
            accrue_proxy_time(db, proxy_id, now=current)
        if egress_changed or untrusted_egress_mismatch or stale_recovery:
            reset_probation(db, proxy_id, current)
        online_since = current.isoformat() if stale_recovery else (row["online_since"] or current.isoformat())
        accumulated_online = int(row["accumulated_online_seconds"] or 0)
        if stale_recovery and row["online_since"] and previous_success:
            observed_until = min(
                current,
                previous_success + timedelta(minutes=settings.health_stale_minutes),
            )
            accumulated_online += max(
                0,
                int((observed_until - datetime.fromisoformat(row["online_since"])).total_seconds()),
            )
        continuity_reset = recovered_from_offline or egress_changed or untrusted_egress_mismatch or stale_recovery
        requires_strong = (
            not egress_trusted and (not previous_exit_ip or untrusted_egress_mismatch)
        ) or missing_trusted_egress
        db.execute(
            """
            UPDATE proxies SET status='online', detected_protocol=?, consecutive_failures=0, health_mode=?,
                online_since=?, offline_since=NULL, last_checked_at=?, check_claimed_until=NULL, check_claim_token=NULL,
                accumulated_online_seconds=?, accumulated_offline_seconds=?, continuous_dead_since=NULL, egress_verified_at=?, eligibility=?, earnapp_next_check_at=?, probation_started_at=?,
                earnapp_claimed_until=CASE WHEN ? THEN NULL ELSE earnapp_claimed_until END,
                earnapp_claim_token=CASE WHEN ? THEN NULL ELSE earnapp_claim_token END,
                accrual_cursor_at=?, last_success_at=?, next_check_at=?, next_probe_index=?, last_probe_endpoint=?,
                last_latency_ms=?, failure_kind='', last_error=?, updated_at=? WHERE id=?
            """,
            (
                result.get("protocol") or row["detected_protocol"],
                "strong" if requires_strong else "fast",
                online_since,
                current.isoformat(),
                accumulated_online,
                accumulated_offline,
                (
                    current.isoformat()
                    if trusted_exit_ip and (not row["egress_verified_at"] or egress_changed)
                    else row["egress_verified_at"]
                ),
                "pending"
                if (egress_changed or untrusted_egress_mismatch or missing_trusted_egress)
                else row["eligibility"],
                current.isoformat()
                if (egress_changed or untrusted_egress_mismatch or missing_trusted_egress)
                else row["earnapp_next_check_at"],
                current.isoformat() if continuity_reset else row["probation_started_at"],
                int(egress_changed or untrusted_egress_mismatch or stale_recovery),
                int(egress_changed or untrusted_egress_mismatch or stale_recovery),
                current.isoformat() if continuity_reset else row["accrual_cursor_at"],
                current.isoformat(),
                (current + timedelta(minutes=settings.health_interval_minutes)).isoformat(),
                next_probe_index,
                probe_endpoint,
                latency_ms,
                str(result.get("error") or "")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        if trusted_exit_ip:
            reconcile_exit_ip(
                db,
                proxy_id,
                trusted_exit_ip,
                attestation_source="https_quorum",
                commit=False,
            )
        return

    if status == "inconclusive" or (
        status == "needs_confirmation" and failure_kind in {"probe_endpoint", "proxy_dns", "transient", "tls", "worker"}
    ):
        db.execute(
            """
            UPDATE proxies SET last_checked_at=?, next_check_at=?, check_claimed_until=NULL, check_claim_token=NULL,
                next_probe_index=?, last_probe_endpoint=?, last_latency_ms=?, failure_kind=?, last_error=?, updated_at=?
            WHERE id=?
            """,
            (
                current.isoformat(),
                (current + timedelta(minutes=settings.health_retry_first_minutes)).isoformat(),
                next_probe_index,
                probe_endpoint,
                latency_ms,
                failure_kind or "probe_endpoint",
                str(result.get("error") or "")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        return

    if status == "needs_confirmation" and failure_kind == "egress_changed":
        db.execute(
            """
            UPDATE proxies SET health_mode='strong', next_check_at=?, check_claimed_until=NULL,
                check_claim_token=NULL, next_probe_index=?, last_probe_endpoint=?, last_latency_ms=?,
                failure_kind=?, last_error=?, updated_at=? WHERE id=?
            """,
            (
                current.isoformat(),
                next_probe_index,
                probe_endpoint,
                latency_ms,
                failure_kind,
                str(result.get("error") or "exit IP requires independent confirmation")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        return

    if status == "blocked":
        if row["eligibility"] == "allow":
            accrue_proxy_time(db, proxy_id, now=current)
        reset_probation(db, proxy_id, current)
        db.execute(
            "UPDATE proxies SET status='blocked', eligibility='risk', consecutive_failures=0, health_mode='strong', last_checked_at=?, next_check_at=?, check_claimed_until=NULL, check_claim_token=NULL, earnapp_claimed_until=NULL, earnapp_claim_token=NULL, earnapp_next_check_at=?, failure_kind=?, last_error=?, updated_at=? WHERE id=?",
            (
                current.isoformat(),
                (current + timedelta(minutes=settings.health_interval_minutes)).isoformat(),
                current.isoformat(),
                failure_kind or "provider_blocked",
                str(result.get("error") or "provider blocked")[:500],
                current.isoformat(),
                proxy_id,
            ),
        )
        return

    failures = int(row["consecutive_failures"] or 0) + 1
    offline = failures >= 3
    next_retry = settings.health_retry_first_minutes if failures == 1 else settings.health_retry_second_minutes
    accumulated_online = int(row["accumulated_online_seconds"] or 0)
    if offline and row["eligibility"] == "allow" and row["status"] in {"online", "suspect"}:
        # Accrue the final confirmed online interval before changing the row
        # to offline; the ledger query intentionally only reads online rows.
        accrue_proxy_time(db, proxy_id, now=current)
    if offline and row["status"] in {"online", "suspect"} and row["online_since"]:
        accumulated_online += max(
            0,
            int((current - datetime.fromisoformat(row["online_since"])).total_seconds()),
        )
    db.execute(
        """
        UPDATE proxies SET status=?, health_mode='strong', consecutive_failures=?, offline_since=?, online_since=?,
            accumulated_online_seconds=?, continuous_dead_since=?, last_checked_at=?, next_check_at=?,
            check_claimed_until=NULL, check_claim_token=NULL, earnapp_claimed_until=NULL, earnapp_claim_token=NULL,
            earnapp_next_check_at=?, next_probe_index=?, last_probe_endpoint=?,
            last_latency_ms=?, failure_kind=?, last_error=?, updated_at=? WHERE id=?
        """,
        (
            "offline" if offline else ("suspect" if failures >= 2 else row["status"]),
            failures,
            (row["offline_since"] or current.isoformat()) if offline else row["offline_since"],
            None if offline else row["online_since"],
            accumulated_online,
            (row["continuous_dead_since"] or current.isoformat()) if offline else row["continuous_dead_since"],
            current.isoformat(),
            (current + timedelta(minutes=next_retry)).isoformat(),
            current.isoformat(),
            next_probe_index,
            probe_endpoint,
            latency_ms,
            failure_kind or "proxy",
            str(result.get("error") or "")[:500],
            current.isoformat(),
            proxy_id,
        ),
    )
    if offline:
        reset_probation(db, proxy_id, current)


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
