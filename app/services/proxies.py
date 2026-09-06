from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.crypto import decrypt_secret, encrypt_secret
from app.proxy_parser import ParsedProxy, ProxyParseError, parse_proxy
from app.services.earnings import expire_pending_cycle, reset_probation


class DuplicateCredential(ValueError):
    pass


class ProxyQuotaExceeded(ValueError):
    pass


class ProxyImportLimitExceeded(ValueError):
    pass


MAX_BULK_IMPORT_ISSUES = 100


@dataclass(frozen=True)
class BulkImportIssue:
    line: int
    category: str
    reason: str
    value: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "line": self.line,
            "category": self.category,
            "reason": self.reason,
            "value": self.value,
        }


@dataclass(frozen=True)
class BulkImportResult:
    submitted: int
    added: int
    duplicates: int
    invalid: int
    quota_skipped: int
    ignored_blank: int
    issues: tuple[BulkImportIssue, ...]
    issues_truncated: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "submitted": self.submitted,
            "added": self.added,
            "duplicates": self.duplicates,
            "invalid": self.invalid,
            "quota_skipped": self.quota_skipped,
            "ignored_blank": self.ignored_blank,
            "issues": [issue.as_dict() for issue in self.issues],
            "issues_truncated": self.issues_truncated,
        }


def credential_fingerprint(parsed: ParsedProxy) -> str:
    normalized = "\0".join([parsed.host.lower(), str(parsed.port), parsed.username, parsed.password])
    return hashlib.sha256(normalized.encode()).hexdigest()


def _safe_issue_value(parsed: ParsedProxy | None) -> str:
    """Return only the public endpoint; never echo credentials in feedback."""
    if parsed is None:
        return ""
    return f"{parsed.host}:{parsed.port}"


def bulk_add_proxies(
    db,
    user_id: int,
    raw_lines: Iterable[str],
    *,
    max_active_proxies: int | None = None,
    max_lines: int = 5_000,
) -> BulkImportResult:
    """Parse and insert a bounded batch while preserving global deduplication."""
    try:
        line_values = str(raw_lines).splitlines() if isinstance(raw_lines, str) else list(raw_lines)
    except TypeError as exc:
        raise ProxyImportLimitExceeded("Proxy import input is invalid") from exc
    if len(line_values) > max(1, int(max_lines)):
        raise ProxyImportLimitExceeded(f"A single import can contain at most {int(max_lines)} lines")

    quota = None
    if max_active_proxies is not None:
        quota = max(1, min(10_000, int(max_active_proxies)))

    parsed_rows: list[tuple[int, ParsedProxy, str]] = []
    issues: list[BulkImportIssue] = []
    issues_truncated = 0

    def record_issue(issue: BulkImportIssue) -> None:
        nonlocal issues_truncated
        if len(issues) < MAX_BULK_IMPORT_ISSUES:
            issues.append(issue)
        else:
            issues_truncated += 1

    submitted = 0
    ignored_blank = 0
    invalid = 0
    for line_number, raw_line in enumerate(line_values, 1):
        value = str(raw_line or "").strip()
        if not value:
            ignored_blank += 1
            continue
        submitted += 1
        try:
            parsed = parse_proxy(value)
        except ProxyParseError as exc:
            invalid += 1
            record_issue(BulkImportIssue(line_number, "invalid", str(exc), ""))
            continue
        parsed_rows.append((line_number, parsed, credential_fingerprint(parsed)))

    added = 0
    duplicates = 0
    quota_skipped = 0
    owns_transaction = not db.in_transaction
    if owns_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        active_count = 0
        if quota is not None:
            active_count = int(
                db.execute(
                    "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
                    (user_id,),
                ).fetchone()["count"]
            )
        seen_fingerprints: set[str] = set()
        now = datetime.now(UTC).isoformat()
        for line_number, parsed, fingerprint in parsed_rows:
            public_value = _safe_issue_value(parsed)
            if fingerprint in seen_fingerprints:
                duplicates += 1
                record_issue(
                    BulkImportIssue(
                        line_number, "duplicate", "Proxy credential already exists in this import", public_value
                    )
                )
                continue
            seen_fingerprints.add(fingerprint)
            exists = db.execute(
                "SELECT 1 FROM proxies WHERE credential_fingerprint=? LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if exists:
                duplicates += 1
                record_issue(BulkImportIssue(line_number, "duplicate", "Proxy credential already exists", public_value))
                continue
            if quota is not None and active_count >= quota:
                quota_skipped += 1
                record_issue(BulkImportIssue(line_number, "quota", "Account proxy limit reached", public_value))
                continue
            db.execute(
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
                    fingerprint,
                    now,
                    now,
                    now,
                    now,
                    now,
                ),
            )
            added += 1
            active_count += 1
        if owns_transaction:
            db.commit()
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise

    issues.sort(key=lambda issue: issue.line)
    return BulkImportResult(
        submitted=submitted,
        added=added,
        duplicates=duplicates,
        invalid=invalid,
        quota_skipped=quota_skipped,
        ignored_blank=ignored_blank,
        issues=tuple(issues),
        issues_truncated=issues_truncated,
    )


def add_proxy(db, user_id: int, raw_proxy: str, *, max_active_proxies: int | None = None) -> int:
    quota = None
    if max_active_proxies is not None:
        quota = max(1, min(10_000, int(max_active_proxies)))
        # Serialize the quota check with the insert so parallel requests cannot
        # both observe the same available slot.
        db.execute("BEGIN IMMEDIATE")
    try:
        if quota is not None:
            active_count = int(
                db.execute(
                    "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
                    (user_id,),
                ).fetchone()["count"]
            )
            if active_count >= quota:
                raise ProxyQuotaExceeded(f"This account has reached the maximum number of active proxies ({quota})")
        parsed = parse_proxy(raw_proxy)
        now = datetime.now(UTC).isoformat()
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
        db.rollback()
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
            earnapp_claimed_until=NULL, earnapp_claim_token=NULL, egress_verified_at=NULL,
            egress_attestation_source='', exit_ip=NULL, country_code='',
            duplicate_of=NULL, consecutive_failures=0, online_since=NULL,
            offline_since=NULL, last_checked_at=NULL, last_success_at=NULL, next_check_at=?,
            check_claimed_until=NULL, check_claim_token=NULL, health_mode='strong', next_probe_index=0,
            last_probe_endpoint='', last_latency_ms=NULL, failure_kind='',
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
    reset_probation(db, promoted_id, current)
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


def reconcile_exit_ip(
    db,
    proxy_id: int,
    exit_ip: str,
    *,
    attestation_source: str = "https_quorum",
    commit: bool = True,
) -> None:
    try:
        normalized_exit = str(ipaddress.ip_address(str(exit_ip or "").strip()))
    except ValueError:
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
    source = str(attestation_source or "").strip().lower()
    if source not in {"https_quorum", "earnapp_tls"}:
        return
    db.execute(
        """
        UPDATE proxies
        SET exit_ip=?,
            country_code=CASE
                WHEN COALESCE(exit_ip,'')<>'' AND COALESCE(exit_ip,'')<>? THEN ''
                ELSE country_code
            END,
            egress_verified_at=CASE
                WHEN COALESCE(exit_ip,'')<>? AND COALESCE(exit_ip,'')<>''
                     AND egress_verified_at IS NOT NULL THEN ?
                ELSE COALESCE(egress_verified_at, ?)
            END,
            egress_attestation_source=?,
            updated_at=?
        WHERE id=?
        """,
        (normalized_exit, normalized_exit, normalized_exit, now, now, source, now, proxy_id),
    )
    _canonicalize_exit_group(db, normalized_exit, prefer_verified_order=had_verified_timestamp)
    if previous_exit and previous_exit != normalized_exit:
        _canonicalize_exit_group(db, previous_exit)
    if commit:
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
            "SELECT * FROM proxies WHERE exit_ip=? AND archived_at IS NULL "
            "AND egress_attestation_source IN ('https_quorum','earnapp_tls')",
            (exit_ip,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM proxies WHERE exit_ip=? AND archived_at IS NULL AND id<>? "
            "AND egress_attestation_source IN ('https_quorum','earnapp_tls')",
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
        "UPDATE proxies SET duplicate_of=? WHERE exit_ip=? AND id<>? AND archived_at IS NULL "
        "AND egress_attestation_source IN ('https_quorum','earnapp_tls')"
        + (" AND id<>?" if exclude_id is not None else ""),
        (canonical, exit_ip, canonical, exclude_id) if exclude_id is not None else (canonical, exit_ip, canonical),
    )
