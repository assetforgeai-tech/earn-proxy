"""Provider-assignment qualification bridge.

This module adapts the existing probe/checker contracts to provider inventory
without creating user earnings or mixing provider rows into user quota logic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

from app.crypto import decrypt_secret
from app.earnapp_probe import classify_verdict
from app.services.proxiware import (
    assignment_identity_fingerprint,
    assignment_identity_from_row,
)
from app.services.proxiware_swap import ensure_proxiware_swap_schema

_PRIVATE_EGRESS_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_TEST_EGRESS_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if getattr(address, "ipv4_mapped", None) is not None:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or any(address in network for network in _PRIVATE_EGRESS_NETWORKS if address.version == network.version)
    ):
        return ""
    if not address.is_global:
        try:
            from flask import current_app

            if current_app.testing and any(address in network for network in _TEST_EGRESS_NETWORKS):
                return str(address)
        except RuntimeError:
            pass
        return ""
    return str(address)


def _table_exists(db, table: str) -> bool:
    return (
        db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (str(table),),
        ).fetchone()
        is not None
    )


def _ensure_columns(db) -> None:
    ensure_proxiware_swap_schema(db)
    columns = {str(row["name"]) for row in db.execute('PRAGMA table_info("provider_assignments")').fetchall()}
    definitions = {
        "protocol": "TEXT NOT NULL DEFAULT 'unknown'",
        "last_checked_at": "TEXT",
        "egress_verified_at": "TEXT",
        "last_error_code": "TEXT NOT NULL DEFAULT ''",
        "duplicate_egress": "INTEGER NOT NULL DEFAULT 0",
        "distribution_enabled": "INTEGER NOT NULL DEFAULT 0",
        "qualification_next_check_at": "TEXT",
        "qualification_claimed_until": "TEXT",
        "qualification_claim_token": "TEXT",
        "qualification_attempts": "INTEGER NOT NULL DEFAULT 0",
        "identity_fingerprint": "TEXT NOT NULL DEFAULT ''",
        "identity_generation": "INTEGER NOT NULL DEFAULT 1",
    }
    for name, definition in definitions.items():
        if name not in columns:
            db.execute(f'ALTER TABLE provider_assignments ADD COLUMN "{name}" {definition}')
    db.commit()


@dataclass(frozen=True)
class QualificationResult:
    assignment_id: int
    live_status: str
    qualification: str
    reason: str
    exit_ip: str = ""
    protocol: str = "unknown"
    distribution_enabled: bool = False


def _proxy_from_row(row) -> dict[str, Any]:
    try:
        username = decrypt_secret(str(row["username_encrypted"] or "")) if row["username_encrypted"] else ""
        password = decrypt_secret(str(row["password_encrypted"] or "")) if row["password_encrypted"] else ""
    except ValueError as exc:
        raise ValueError("provider credential unavailable") from exc
    protocol = str(row["protocol"] or "auto").strip().lower()
    if protocol not in {"http", "socks5"}:
        protocol = "auto"
    return {
        "host": str(row["host"] or ""),
        "port": int(row["port"] or 0),
        "username": username,
        "password": password,
        "protocol": protocol,
    }


def _identity_is_current(db, assignment_id: int, generation: int, identity: tuple[str, int, str, str]) -> bool:
    row = db.execute(
        "SELECT * FROM provider_assignments WHERE id=? AND provider='proxiware' AND missing_at IS NULL",
        (int(assignment_id),),
    ).fetchone()
    return bool(
        row is not None
        and int(row["identity_generation"] or 1) == int(generation)
        and assignment_identity_from_row(row) == identity
    )


def _duplicate_egress(db, assignment_id: int, exit_ip: str) -> bool:
    if not exit_ip:
        return False
    if _table_exists(db, "proxies"):
        user_duplicate = db.execute(
            "SELECT 1 FROM proxies WHERE archived_at IS NULL AND exit_ip=? "
            "AND egress_attestation_source IN ('https_quorum','earnapp_tls') LIMIT 1",
            (exit_ip,),
        ).fetchone()
        if user_duplicate is not None:
            return True
    provider_duplicate = db.execute(
        "SELECT 1 FROM provider_assignments WHERE provider='proxiware' AND exit_ip=? "
        "AND id<>? AND missing_at IS NULL AND id<? LIMIT 1",
        (exit_ip, int(assignment_id), int(assignment_id)),
    ).fetchone()
    return provider_duplicate is not None


def reconcile_proxiware_duplicates(db, *, commit: bool = True) -> int:
    """Reconcile provider egress identity against user and provider inventory.

    The query is deliberately based on literal IPs already attested by the
    proxy checker. DNS names, resolver addresses, and untrusted probe output
    never participate in duplicate identity.
    """

    _ensure_columns(db)
    provider_rows = db.execute(
        "SELECT id, exit_ip, qualification, live_status, provider_eligible, missing_at "
        "FROM provider_assignments WHERE provider='proxiware' AND missing_at IS NULL"
    ).fetchall()
    user_ips: set[str] = set()
    if _table_exists(db, "proxies"):
        user_ips = {
            str(row["exit_ip"])
            for row in db.execute(
                "SELECT DISTINCT exit_ip FROM proxies WHERE archived_at IS NULL "
                "AND exit_ip IS NOT NULL AND trim(exit_ip)<>'' "
                "AND egress_attestation_source IN ('https_quorum','earnapp_tls')"
            ).fetchall()
            if _ip(row["exit_ip"])
        }
    groups: dict[str, list[int]] = {}
    for row in provider_rows:
        address = _ip(row["exit_ip"])
        if address:
            groups.setdefault(address, []).append(int(row["id"]))
    duplicate_ids: set[int] = set()
    for address, ids in groups.items():
        if address in user_ips:
            duplicate_ids.update(ids)
        else:
            duplicate_ids.update(ids[1:])
    changed = 0
    for row in provider_rows:
        assignment_id = int(row["id"])
        duplicate = int(assignment_id in duplicate_ids)
        distribution = int(
            not duplicate
            and str(row["live_status"] or "").lower() == "live"
            and str(row["qualification"] or "").lower() == "allow"
            and str(row["provider_eligible"] or "").strip().lower() in {"1", "true", "yes", "on"}
        )
        cursor = db.execute(
            "UPDATE provider_assignments SET duplicate_egress=?, distribution_enabled=? WHERE id=? "
            "AND (COALESCE(duplicate_egress,0)<>? OR COALESCE(distribution_enabled,0)<>?)",
            (duplicate, distribution, assignment_id, duplicate, distribution),
        )
        changed += int(cursor.rowcount)
    if changed and commit:
        db.commit()
    return changed


def qualify_proxiware_assignment(
    db,
    assignment_id: int,
    *,
    probe: Callable[[dict[str, Any]], dict[str, Any]],
    eligibility: Callable[[dict[str, Any]], dict[str, Any]],
    now: datetime | None = None,
    claim_token: str | None = None,
    check_interval_seconds: int = 3600,
) -> QualificationResult:
    """Probe and classify one provider assignment using injected adapters."""

    _ensure_columns(db)
    current = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    next_check = (datetime.fromisoformat(current) + timedelta(seconds=max(60, int(check_interval_seconds)))).isoformat()
    claim_clause = " AND qualification_claim_token=?" if claim_token else ""
    claim_params = (str(claim_token),) if claim_token else ()
    row = db.execute(
        "SELECT * FROM provider_assignments WHERE id=? AND provider='proxiware' AND missing_at IS NULL" + claim_clause,
        (int(assignment_id), *claim_params),
    ).fetchone()
    if row is None:
        raise LookupError("Provider assignment not found")
    identity_generation = int(row["identity_generation"] or 1)
    identity = assignment_identity_from_row(row)
    identity_fingerprint = assignment_identity_fingerprint(*identity)
    try:
        proxy = _proxy_from_row(row)
        probe_result = probe(proxy) or {}
    except Exception:  # noqa: BLE001 - one bad provider row must not kill a batch
        if not _identity_is_current(db, int(assignment_id), identity_generation, identity):
            raise LookupError("Provider assignment identity changed") from None
        cursor = db.execute(
            "UPDATE provider_assignments SET live_status='inconclusive', qualification='pending', "
            "distribution_enabled=0, last_error_code='probe_error', last_checked_at=?, "
            "qualification_next_check_at=?, qualification_claimed_until=NULL, qualification_claim_token=NULL, "
            "qualification_attempts=qualification_attempts+1, identity_fingerprint=?, updated_at=? "
            "WHERE id=? AND identity_generation=?" + claim_clause,
            (
                current,
                next_check,
                identity_fingerprint,
                current,
                int(assignment_id),
                identity_generation,
                *claim_params,
            ),
        )
        if cursor.rowcount != 1:
            db.rollback()
            raise LookupError("Provider assignment identity changed") from None
        db.commit()
        return QualificationResult(int(assignment_id), "inconclusive", "pending", "probe_error")

    status = str(probe_result.get("status") or "inconclusive").strip().lower()
    protocol = str(probe_result.get("protocol") or "unknown").strip().lower()
    exit_ip = _ip(probe_result.get("exit_ip"))
    trusted = probe_result.get("egress_trusted") is True
    if status in {"live", "online"} and exit_ip and trusted:
        live_status = "live"
    elif status in {"live", "online", "live_unverified"}:
        live_status = "live_unverified"
        exit_ip = exit_ip or ""
    elif status == "blocked":
        live_status = "blocked"
    elif status == "dead":
        live_status = "dead"
    else:
        live_status = "inconclusive"

    qualification = "pending"
    reason = str(probe_result.get("failure_kind") or "probe_pending").strip().lower() or "probe_pending"
    duplicate = False
    distribution = False
    if live_status == "live":
        try:
            verdict = eligibility(proxy) or {}
        except Exception:  # noqa: BLE001 - qualification service remains fail-closed
            verdict = {"verdict": "UNKNOWN", "reason": "eligibility_error"}
        qualification = classify_verdict(str(verdict.get("verdict") or "UNKNOWN"), str(verdict.get("reason") or ""))
        reason = str(verdict.get("reason") or qualification).strip().lower()
        duplicate = _duplicate_egress(db, int(assignment_id), exit_ip)
        if duplicate:
            reason = "duplicate_egress"
        distribution = (
            qualification == "allow"
            and not duplicate
            and str(row["provider_eligible"] or "").strip().lower() in {"1", "true", "yes", "on"}
        )
    elif live_status == "dead":
        qualification = "dead"
        reason = str(probe_result.get("failure_kind") or "dead").strip().lower() or "dead"
    elif live_status == "blocked":
        qualification = "risk"
        reason = "provider_blocked"

    if not _identity_is_current(db, int(assignment_id), identity_generation, identity):
        raise LookupError("Provider assignment identity changed")
    cursor = db.execute(
        "UPDATE provider_assignments SET protocol=?, live_status=?, qualification=?, exit_ip=?, "
        "egress_verified_at=?, duplicate_egress=?, distribution_enabled=?, last_checked_at=?, "
        "last_error_code=?, qualification_next_check_at=?, qualification_claimed_until=NULL, "
        "qualification_claim_token=NULL, qualification_attempts=qualification_attempts+1, identity_fingerprint=?, "
        "updated_at=? WHERE id=? AND identity_generation=?" + claim_clause,
        (
            protocol,
            live_status,
            qualification,
            exit_ip or None,
            current if live_status == "live" else None,
            int(duplicate),
            int(distribution),
            current,
            "" if live_status == "live" else reason,
            next_check,
            identity_fingerprint,
            current,
            int(assignment_id),
            identity_generation,
            *claim_params,
        ),
    )
    if cursor.rowcount != 1:
        db.rollback()
        raise LookupError("Provider assignment identity changed")
    db.commit()
    # Reconcile all provider rows after each successful observation so a late
    # user/provider arrival cannot leave a stale distributable flag behind.
    reconcile_proxiware_duplicates(db)
    return QualificationResult(
        int(assignment_id),
        live_status,
        qualification,
        reason,
        exit_ip,
        protocol,
        distribution,
    )


__all__ = ["QualificationResult", "qualify_proxiware_assignment", "reconcile_proxiware_duplicates"]
