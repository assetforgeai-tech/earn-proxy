from __future__ import annotations

import hashlib

from app.proxy_parser import ParsedProxy, parse_proxy
from app.services.proxiware_crypto import decrypt_assignment_secret
from app.services.proxiware_swap import ensure_proxiware_swap_schema


class TransferSlotError(ValueError):
    pass


def _slot_key(subscription_external_id: str, root_assignment_id: str) -> str:
    identity = f"proxiware\0{subscription_external_id}\0{root_assignment_id}"
    return "pw1_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def load_proxiware_slots(db) -> list[dict[str, object]]:
    """Return current raw assignments with a stable identity across confirmed swaps."""

    ensure_proxiware_swap_schema(db)
    pending_swap = db.execute(
        "SELECT 1 FROM swap_jobs WHERE provider='proxiware' "
        "AND state IN ('provider_applied','reconciliation_required') LIMIT 1"
    ).fetchone()
    if pending_swap:
        raise TransferSlotError("Proxiware swap reconciliation is incomplete")
    invalid_current = db.execute(
        "SELECT 1 FROM provider_assignments pa JOIN provider_subscriptions ps "
        "ON ps.id=pa.subscription_id AND ps.provider='proxiware' "
        "WHERE pa.provider='proxiware' AND pa.missing_at IS NULL "
        "AND LOWER(COALESCE(pa.status,'')) IN ('active','current') "
        "AND ps.missing_at IS NULL AND LOWER(COALESCE(ps.status,'')) IN ('active','ready') "
        "AND (trim(COALESCE(ps.external_id,''))='' OR trim(COALESCE(pa.external_id,''))='' "
        "OR trim(COALESCE(pa.host,''))='' "
        "OR pa.port NOT BETWEEN 1 AND 65535) LIMIT 1"
    ).fetchone()
    if invalid_current:
        raise TransferSlotError("Proxiware current inventory contains an incomplete assignment")
    assignments = db.execute(
        "SELECT pa.*,ps.external_id AS subscription_external_id FROM provider_assignments pa "
        "JOIN provider_subscriptions ps ON ps.id=pa.subscription_id AND ps.provider='proxiware' "
        "WHERE pa.provider='proxiware' AND pa.missing_at IS NULL "
        "AND LOWER(COALESCE(pa.status,'')) IN ('active','current') "
        "AND ps.missing_at IS NULL AND LOWER(COALESCE(ps.status,'')) IN ('active','ready') "
        "AND trim(COALESCE(pa.host,''))<>'' AND pa.port BETWEEN 1 AND 65535 "
        "ORDER BY pa.subscription_id,pa.id"
    ).fetchall()
    previous_assignment: dict[tuple[int, str], str] = {}
    for row in db.execute(
        "SELECT sj.subscription_id,sm.old_assignment_external_id,sm.new_assignment_external_id "
        "FROM swap_mappings sm JOIN swap_jobs sj ON sj.id=sm.swap_job_id "
        "WHERE sj.provider='proxiware' AND sj.state='success'"
    ).fetchall():
        key = (int(row["subscription_id"]), str(row["new_assignment_external_id"] or "").strip())
        old = str(row["old_assignment_external_id"] or "").strip()
        if not key[1] or not old or (key in previous_assignment and previous_assignment[key] != old):
            raise TransferSlotError("Swap history has conflicting provider slot lineage")
        previous_assignment[key] = old

    slots: list[dict[str, object]] = []
    seen: set[str] = set()
    for row in assignments:
        subscription_id = int(row["subscription_id"])
        external_id = str(row["external_id"] or "").strip()
        root_id = external_id
        visited: set[str] = set()
        while (subscription_id, root_id) in previous_assignment:
            if root_id in visited:
                raise TransferSlotError("Swap history contains a provider slot cycle")
            visited.add(root_id)
            root_id = previous_assignment[(subscription_id, root_id)]
        key = _slot_key(str(row["subscription_external_id"] or ""), root_id)
        if key in seen:
            raise TransferSlotError("Multiple current assignments resolve to one provider slot")
        seen.add(key)
        try:
            username = decrypt_assignment_secret(row, "username_encrypted")
            password = decrypt_assignment_secret(row, "password_encrypted")
        except ValueError as exc:
            raise TransferSlotError("A current Proxiware assignment credential is unavailable") from exc
        try:
            validated = parse_proxy(f"{row['host']}:{row['port']}:{username}:{password}")
        except ValueError as exc:
            raise TransferSlotError("A current Proxiware assignment endpoint is invalid") from exc
        proxy = ParsedProxy(str(row["protocol"] or "auto"), validated.host, validated.port, username, password)
        slots.append(
            {
                "slot_key": key,
                "subscription": str(row["subscription_external_id"] or ""),
                "external_id": external_id,
                "host": proxy.host,
                "port": proxy.port,
                "upstream": {
                    "host": proxy.host,
                    "port": proxy.port,
                    "username": username,
                    "password": password,
                },
                "raw": proxy.raw,
                "protocol": proxy.protocol,
                "qualification": str(row["qualification"] or "pending").lower(),
                "live_status": str(row["live_status"] or "pending").lower(),
                "provider_eligible": row["provider_eligible"],
                "exit_ip": str(row["exit_ip"] or ""),
                "country": str(row["country"] or ""),
            }
        )
    return slots
