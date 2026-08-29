from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from app.crypto import decrypt_secret, encrypt_secret
from app.proxy_parser import ParsedProxy, parse_proxy
from app.services.earnings import expire_pending_cycle


class DuplicateCredential(ValueError):
    pass


def credential_fingerprint(parsed: ParsedProxy) -> str:
    normalized = "\0".join([parsed.host.lower(), str(parsed.port), parsed.username, parsed.password])
    return hashlib.sha256(normalized.encode()).hexdigest()


def add_proxy(db, user_id: int, raw_proxy: str) -> int:
    parsed = parse_proxy(raw_proxy)
    now = datetime.now(UTC).isoformat()
    try:
        cursor = db.execute(
            """
            INSERT INTO proxies(
                user_id, host, port, protocol_hint, username_encrypted, password_encrypted,
                credential_fingerprint, next_check_at, probation_started_at, accrual_cursor_at,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                parsed.host,
                parsed.port,
                parsed.protocol,
                encrypt_secret(parsed.username),
                encrypt_secret(parsed.password),
                credential_fingerprint(parsed),
                now,
                now,
                now,
                now,
                now,
            ),
        )
        db.commit()
    except Exception as exc:
        if "credential_fingerprint" in str(exc) or "UNIQUE constraint failed: proxies.credential_fingerprint" in str(
            exc
        ):
            raise DuplicateCredential("This proxy credential already exists") from exc
        raise
    return int(cursor.lastrowid)


def replace_proxy(db, proxy_id: int, user_id: int, raw_proxy: str, *, now: datetime | None = None) -> None:
    parsed = parse_proxy(raw_proxy)
    current = now or datetime.now(UTC)
    existing = db.execute(
        "SELECT exit_ip FROM proxies WHERE id=? AND user_id=? AND archived_at IS NULL",
        (proxy_id, user_id),
    ).fetchone()
    if existing is None:
        raise LookupError("Proxy not found")
    previous_exit = str(existing["exit_ip"] or "")
    fingerprint = credential_fingerprint(parsed)
    duplicate = db.execute(
        "SELECT id FROM proxies WHERE credential_fingerprint=? AND id<>?",
        (fingerprint, proxy_id),
    ).fetchone()
    if duplicate:
        raise DuplicateCredential("This proxy credential already exists")
    if previous_exit:
        _canonicalize_exit_group(db, previous_exit, exclude_id=proxy_id)
    expire_pending_cycle(db, proxy_id)
    cursor = db.execute(
        """
        UPDATE proxies SET host=?, port=?, protocol_hint=?, username_encrypted=?, password_encrypted=?,
            credential_fingerprint=?, credential_generation=credential_generation+1,
            detected_protocol='unknown', status='pending', eligibility='pending',
            earnapp_verdict='', earnapp_reason='', earnapp_checked_at=NULL, earnapp_next_check_at=NULL,
            earnapp_claimed_until=NULL, earnapp_claim_token=NULL, egress_verified_at=NULL, exit_ip=NULL, country_code='',
            duplicate_of=NULL, consecutive_failures=0, online_since=NULL,
            offline_since=NULL, last_checked_at=NULL, next_check_at=?, check_claimed_until=NULL, check_claim_token=NULL,
            accrual_cursor_at=?, probation_started_at=?, last_error='', updated_at=?
        WHERE id=? AND user_id=? AND archived_at IS NULL
        """,
        (
            parsed.host,
            parsed.port,
            parsed.protocol,
            encrypt_secret(parsed.username),
            encrypt_secret(parsed.password),
            fingerprint,
            current.isoformat(),
            current.isoformat(),
            current.isoformat(),
            current.isoformat(),
            proxy_id,
            user_id,
        ),
    )
    if cursor.rowcount != 1:
        raise LookupError("Proxy not found")
    db.commit()


def archive_proxy(db, proxy_id: int, user_id: int, *, now: datetime | None = None) -> None:
    current = now or datetime.now(UTC)
    owned = db.execute(
        "SELECT id FROM proxies WHERE id=? AND user_id=? AND archived_at IS NULL",
        (proxy_id, user_id),
    ).fetchone()
    if owned is None:
        raise LookupError("Proxy not found")
    existing = db.execute("SELECT exit_ip FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    previous_exit = str(existing["exit_ip"] or "") if existing else ""
    if previous_exit:
        _canonicalize_exit_group(db, previous_exit, exclude_id=proxy_id)
    expire_pending_cycle(db, proxy_id)
    cursor = db.execute(
        "UPDATE proxies SET archived_at=?, status='archived', updated_at=? WHERE id=? AND user_id=? AND archived_at IS NULL",
        (current.isoformat(), current.isoformat(), proxy_id, user_id),
    )
    if cursor.rowcount != 1:
        raise LookupError("Proxy not found")
    db.commit()


def promote_duplicate_if_due(db, canonical_id: int, *, now: datetime | None = None) -> int | None:
    current = now or datetime.now(UTC)
    canonical = db.execute("SELECT * FROM proxies WHERE id=?", (canonical_id,)).fetchone()
    if canonical is None or canonical["status"] not in {"offline", "archived"} or not canonical["offline_since"]:
        return None
    offline_since = datetime.fromisoformat(canonical["offline_since"])
    if canonical["status"] != "archived" and current - offline_since < timedelta(hours=24):
        return None
    candidate = db.execute(
        "SELECT * FROM proxies WHERE duplicate_of=? AND status='online' AND archived_at IS NULL ORDER BY created_at,id LIMIT 1",
        (canonical_id,),
    ).fetchone()
    if candidate is None:
        return None
    promoted_id = int(candidate["id"])
    db.execute("UPDATE proxies SET duplicate_of=? WHERE id=?", (promoted_id, canonical_id))
    db.execute("UPDATE proxies SET duplicate_of=NULL WHERE id=?", (promoted_id,))
    db.execute(
        "UPDATE proxies SET duplicate_of=? WHERE duplicate_of=? AND id<>?",
        (promoted_id, canonical_id, promoted_id),
    )
    db.commit()
    return promoted_id


def reveal_proxy(row) -> ParsedProxy:
    return ParsedProxy(
        row["protocol_hint"],
        row["host"],
        int(row["port"]),
        decrypt_secret(row["username_encrypted"]),
        decrypt_secret(row["password_encrypted"]),
    )


def reconcile_exit_ip(db, proxy_id: int, exit_ip: str) -> None:
    normalized_exit = str(exit_ip or "").strip()
    if not normalized_exit:
        return
    now = datetime.now(UTC).isoformat()
    previous = db.execute(
        "SELECT exit_ip, egress_verified_at FROM proxies WHERE id=? AND archived_at IS NULL",
        (proxy_id,),
    ).fetchone()
    if previous is None:
        return
    previous_exit = str(previous["exit_ip"] or "")
    had_verified_timestamp = bool(previous["egress_verified_at"])
    db.execute(
        """
        UPDATE proxies
        SET exit_ip=?,
            egress_verified_at=CASE
                WHEN COALESCE(exit_ip,'')<>? AND COALESCE(exit_ip,'')<>''
                     AND egress_verified_at IS NOT NULL THEN ?
                ELSE COALESCE(egress_verified_at, ?)
            END,
            updated_at=?
        WHERE id=?
        """,
        (normalized_exit, normalized_exit, now, now, now, proxy_id),
    )
    _canonicalize_exit_group(db, normalized_exit, prefer_verified_order=had_verified_timestamp)
    if previous_exit and previous_exit != normalized_exit:
        _canonicalize_exit_group(db, previous_exit)
    db.commit()


def _canonicalize_exit_group(
    db,
    exit_ip: str,
    *,
    prefer_verified_order: bool = False,
    exclude_id: int | None = None,
) -> None:
    """Choose one stable distributor for an egress IP and rehome duplicates."""
    if exclude_id is None:
        rows = db.execute(
            "SELECT * FROM proxies WHERE exit_ip=? AND archived_at IS NULL",
            (exit_ip,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM proxies WHERE exit_ip=? AND archived_at IS NULL AND id<>?",
            (exit_ip, exclude_id),
        ).fetchall()
    if not rows:
        return
    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    candidates = [
        row
        for row in rows
        if not (row["status"] == "offline" and row["offline_since"] and row["offline_since"] <= cutoff)
    ]
    candidates = candidates or list(rows)
    # Before every member has a verified timestamp, creation order prevents
    # check completion order from flipping the canonical proxy.
    all_preverified = prefer_verified_order and all(row["egress_verified_at"] for row in rows)
    key = (
        (lambda row: (row["egress_verified_at"], row["created_at"], row["id"]))
        if all_preverified
        else (lambda row: (row["created_at"], row["id"]))
    )
    canonical = min(candidates, key=key)["id"]
    db.execute("UPDATE proxies SET duplicate_of=NULL WHERE id=?", (canonical,))
    db.execute(
        "UPDATE proxies SET duplicate_of=? WHERE exit_ip=? AND id<>? AND archived_at IS NULL"
        + (" AND id<>?" if exclude_id is not None else ""),
        (canonical, exit_ip, canonical, exclude_id) if exclude_id is not None else (canonical, exit_ip, canonical),
    )
