from __future__ import annotations

import ipaddress
import math
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from app.auth import admin_required
from app.db import get_db
from app.proxiware_swap_service import ProxiwareSwapRunner
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.api_keys import (
    consume_api_key_reveal,
    create_api_key,
    create_api_key_reveal,
    get_api_key_by_public_id,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
)
from app.services.checks import (
    MAX_HEALTH_CONCURRENCY,
    MAX_PER_HOST_CONCURRENCY,
    checker_settings,
    operational_stats,
)
from app.services.payouts import approve_payout, mark_payout_sent
from app.services.proxiware import (
    ProxiwareClient,
    enqueue_sync_run,
    request_sync_cancel,
)
from app.services.proxiware_credentials import (
    clear_provider_secret,
    get_provider_secret,
    get_provider_secret_metadata,
    record_provider_audit,
    renew_provider_session,
    save_provider_credentials,
    test_provider_connections,
)
from app.services.proxiware_health import AUTOMATION_PAUSE_KEY
from app.services.proxiware_swap import (
    cancel_swap,
    ensure_proxiware_swap_schema,
    request_manual_swap,
    retry_swap,
)
from app.services.relay_sso import create_relay_sso_token
from app.services.settings import get_setting, set_setting
from app.services.users import MAX_EMAIL_LENGTH, create_user

bp = Blueprint("admin", __name__, url_prefix="/admin")

EGRESS_DUPLICATE_PAGE_SIZES = (25, 50, 100)
ADMIN_PROXY_PAGE_SIZES = (25, 50, 100)
ADMIN_PROXY_STATUSES = ("pending", "online", "offline", "blocked", "suspect")
ADMIN_PROXY_PROTOCOLS = ("http", "socks5", "unknown")
ADMIN_PROXY_ELIGIBILITIES = ("allow", "risk", "pending")
ADMIN_PROXY_IDENTITIES = ("canonical", "duplicate", "awaiting")
ADMIN_PROXY_FRESHNESS = ("fresh", "due", "stale", "never")
ADMIN_PROXY_ARCHIVED = ("active", "archived", "all")
ADMIN_PROXY_SORT_COLUMNS = {
    "created": ("COALESCE(julianday(p.created_at), -1)", "p.id"),
    "endpoint": ("LOWER(p.host)", "p.port", "p.id"),
    "owner": ("LOWER(u.email)", "LOWER(p.host)", "p.port", "p.id"),
    "status": ("p.status", "LOWER(p.host)", "p.port", "p.id"),
    "protocol": ("p.detected_protocol", "LOWER(p.host)", "p.port", "p.id"),
    "eligibility": ("p.eligibility", "LOWER(p.host)", "p.port", "p.id"),
    "country": ("p.country_code", "LOWER(p.host)", "p.port", "p.id"),
    "latency": ("COALESCE(p.last_latency_ms, -1)", "p.id"),
    "failures": ("COALESCE(p.consecutive_failures, 0)", "p.id"),
    "checked": ("COALESCE(julianday(p.last_checked_at), -1)", "p.id"),
    "next_check": ("COALESCE(julianday(p.next_check_at), -1)", "p.id"),
}
ADMIN_PROXY_SELECT_COLUMNS = (
    "p.host",
    "p.port",
    "p.archived_at",
    "p.detected_protocol",
    "p.status",
    "p.failure_kind",
    "p.eligibility",
    "p.egress_attestation_source",
    "p.exit_ip",
    "p.duplicate_of",
    "p.country_code",
    "p.last_latency_ms",
    "p.consecutive_failures",
    "p.last_checked_at",
    "p.last_success_at",
    "p.next_check_at",
    "p.created_at",
)

PROXIWARE_AREAS = (
    ("overview", "Overview"),
    ("inventory", "Inventory"),
    ("eligibility", "Qualification"),
    ("history", "Sync"),
    ("swaps", "Swap queue"),
    ("swap-history", "Swap history"),
    ("credentials", "Credentials"),
    ("session", "Session"),
    ("settings", "Policy"),
    ("audit", "Audit"),
)
PROXIWARE_AREA_KEYS = {key for key, _label in PROXIWARE_AREAS} | {"qualification", "sync", "policy"}
PROXIWARE_AREA_ALIASES = {
    "eligibility": "qualification",
    "history": "sync",
    "sync-history": "sync",
    "settings": "policy",
}


def _canonical_proxiware_area(area: str | None) -> str:
    value = str(area or "overview").strip().lower() or "overview"
    return PROXIWARE_AREA_ALIASES.get(value, value)


PROXIWARE_PAGE_SIZES = (25, 50, 100)
PROXIWARE_SAFE_ERROR_CODES = frozenset(
    {
        "adapter_missing",
        "already_running",
        "canceled",
        "authentication_error",
        "bad_request",
        "conflict",
        "forbidden",
        "http_error",
        "invalid_configuration",
        "manual_action_required",
        "missing_api_key",
        "network_error",
        "not_configured",
        "not_found",
        "payload_error",
        "provider_error",
        "rate_limited",
        "timeout",
    }
)
PROXIWARE_RATE_LIMITED_ACTIONS = frozenset({"sync", "test_connection", "renew_session", "swap", "settings"})


def _proxiware_area_url(area: str) -> str:
    area = _canonical_proxiware_area(area)
    if area == "overview":
        return url_for("admin.proxiware_workspace")
    if area == "swap-history":
        return url_for("admin.proxiware_swap_history")
    return url_for("admin.proxiware_workspace", area=area)


def _proxiware_table_exists(db, table: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _proxiware_columns(db, table: str) -> set[str]:
    if not _proxiware_table_exists(db, table):
        return set()
    return {str(row["name"]) for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()}


def _proxiware_page_args(args) -> dict[str, object]:
    try:
        page = max(1, min(10_000_000, int(str(args.get("page") or "1"))))
    except (TypeError, ValueError):
        page = 1
    try:
        requested = int(str(args.get("per_page") or "25"))
    except (TypeError, ValueError):
        requested = 25
    per_page = requested if requested in PROXIWARE_PAGE_SIZES else 25
    values = {
        "q": str(args.get("q") or "").strip()[:100],
        "subscription": str(args.get("subscription") or "").strip()[:100],
        "live": str(args.get("live") or "").strip().lower()[:20],
        "qualification": str(args.get("qualification") or "").strip().lower()[:20],
        "provider_eligibility": str(args.get("provider_eligibility") or "").strip().lower()[:20],
        "readiness": str(args.get("readiness") or "").strip().lower()[:20],
        "country": str(args.get("country") or "").strip().upper()[:2],
        "duplicate": str(args.get("duplicate") or "").strip().lower()[:20],
        "sort": str(args.get("sort") or "updated").strip().lower(),
        "direction": str(args.get("direction") or "desc").strip().lower(),
    }
    if values["live"] not in {"", "online", "offline", "pending"}:
        values["live"] = ""
    if values["qualification"] not in {"", "allow", "risk", "pending", "dead"}:
        values["qualification"] = ""
    if values["provider_eligibility"] not in {"", "eligible", "ineligible", "unknown"}:
        values["provider_eligibility"] = ""
    if values["readiness"] not in {"", "ready", "cooldown", "blocked"}:
        values["readiness"] = ""
    if values["duplicate"] not in {"", "duplicate"}:
        values["duplicate"] = ""
    if values["direction"] not in {"asc", "desc"}:
        values["direction"] = "desc"
    if values["sort"] not in {"updated", "subscription", "country", "status"}:
        values["sort"] = "updated"
    if len(values["country"]) != 2 or not values["country"].isalpha():
        values["country"] = ""
    return {"page": page, "per_page": per_page, **values}


def _proxiware_snapshot(db, area: str, args) -> dict[str, object]:
    """Build a credential-safe, schema-tolerant read model for the provider UI."""
    area = _canonical_proxiware_area(area)
    query = _proxiware_page_args(args)
    areas = [
        {
            "key": key,
            "canonical": _canonical_proxiware_area(key),
            "label": label,
            "url": _proxiware_area_url(key),
        }
        for key, label in PROXIWARE_AREAS
    ]
    settings = {
        "eligibility_threshold": get_setting(db, "proxiware_eligible_threshold", "1000"),
        "worker_concurrency": get_setting(db, "proxiware_worker_concurrency", "1"),
        "retry_limit": get_setting(db, "proxiware_retry_limit", "2"),
        "cooldown_seconds": get_setting(db, "proxiware_cooldown_seconds", "60"),
    }
    auto_swap_enabled = get_setting(db, "proxiware_auto_swap", "0") == "1"
    distribution_enabled = get_setting(db, "proxiware_distribution_enabled", "0") == "1"
    session_status = get_setting(db, "proxiware_session_status", "not_configured")
    worker_status = get_setting(db, "proxiware_worker_status", "stopped")
    worker_paused = get_setting(db, "proxiware_swap_worker_paused", "0") == "1"
    automation_paused = get_setting(db, AUTOMATION_PAUSE_KEY, "0") == "1"
    last_error = get_setting(db, "proxiware_last_error_code", "")
    last_sync = get_setting(db, "proxiware_last_sync_at", "") or "Never"
    last_check = get_setting(db, "proxiware_last_check_at", "") or "Never"
    credentials = {
        "proxiware_email": False,
        "proxiware_api_key": False,
        "twocaptcha_api_key": False,
        "session_metadata": "No session metadata",
    }
    credential_columns = _proxiware_columns(db, "provider_credentials")
    if credential_columns and "name" in credential_columns:
        metadata = get_provider_secret_metadata(db)
        credentials["proxiware_email"] = bool(metadata.get("login_email", {}).get("configured"))
        credentials["proxiware_api_key"] = bool(metadata.get("api_key", {}).get("configured"))
        credentials["twocaptcha_api_key"] = bool(metadata.get("captcha_api_key", {}).get("configured"))
    session_columns = _proxiware_columns(db, "provider_sessions")
    if session_columns:
        session_fields = [name for name in ("state", "expires_at", "updated_at") if name in session_columns]
        if session_fields:
            session_row = db.execute(
                "SELECT " + ",".join(session_fields) + " FROM provider_sessions WHERE provider=? LIMIT 1",
                ("proxiware",),
            ).fetchone()
            if session_row:
                session_status = str(session_row["state"] or session_status)
                session_values = {name: session_row[name] for name in session_fields}
                credentials["session_metadata"] = str(
                    session_values.get("expires_at") or session_values.get("updated_at") or "Configured"
                )

    summary: dict[str, object] = {
        "subscriptions": 0,
        "assignments": 0,
        "live": 0,
        "dead": 0,
        "allow": 0,
        "risk": 0,
        "pending": 0,
        "duplicate": 0,
        "swaps_pending": 0,
        "swaps_blocked": 0,
        "eligible_count": 0,
        "connections": "—",
        "last_sync": last_sync,
        "last_check": last_check,
        "last_error": last_error or "None recorded",
        "sync_run_id": None,
        "sync_state": "idle",
        "sync_processed": 0,
        "sync_total": 0,
        "health_badge": "Healthy"
        if session_status in {"healthy", "active", "ready"} and not last_error
        else "Needs attention",
    }
    heartbeat_states: dict[str, str] = {}
    now_utc = datetime.now(UTC)
    for worker_name in ("sync_worker", "qualification_worker", "swap_worker"):
        status = get_setting(db, f"proxiware_{worker_name}_status", "unknown")
        heartbeat = get_setting(db, f"proxiware_{worker_name}_heartbeat_at", "")
        if automation_paused:
            heartbeat_states[worker_name] = "paused"
            continue
        stale = False
        if heartbeat:
            try:
                parsed = datetime.fromisoformat(heartbeat)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=UTC)
                stale = now_utc - parsed.astimezone(UTC) > timedelta(minutes=10)
            except ValueError:
                stale = True
        elif status not in {"unknown", "stopped"}:
            stale = True
        heartbeat_states[worker_name] = "stale" if stale else status
    if any(value == "stale" for value in heartbeat_states.values()):
        worker_status = "stale"
        summary["health_badge"] = "Needs attention"
        summary["worker_alert"] = "Worker heartbeat stale"
        summary["worker_alert_url"] = _proxiware_area_url("sync")
    else:
        summary["worker_alert"] = ""
        summary["worker_alert_url"] = ""
    summary["worker_heartbeats"] = heartbeat_states
    summary["session_alert_url"] = (
        _proxiware_area_url("session") if session_status not in {"healthy", "active", "ready"} else ""
    )
    if _proxiware_table_exists(db, "provider_subscriptions"):
        summary["subscriptions"] = int(
            db.execute(
                "SELECT COUNT(*) AS count FROM provider_subscriptions WHERE provider=?", ("proxiware",)
            ).fetchone()["count"]
        )
        sub_cols = _proxiware_columns(db, "provider_subscriptions")
        if "eligible_count" in sub_cols:
            summary["eligible_count"] = int(
                db.execute(
                    "SELECT COALESCE(SUM(eligible_count),0) AS count FROM provider_subscriptions WHERE provider=?",
                    ("proxiware",),
                ).fetchone()["count"]
            )
        if "connections" in sub_cols:
            summary["connections"] = int(
                db.execute(
                    "SELECT COALESCE(SUM(connections),0) AS count FROM provider_subscriptions WHERE provider=?",
                    ("proxiware",),
                ).fetchone()["count"]
            )

    assignment_table = "provider_assignments"
    if _proxiware_table_exists(db, assignment_table):
        assignment_columns = _proxiware_columns(db, assignment_table)
        provider_clause = "provider=?" if "provider" in assignment_columns else "0=1"
        provider_params = ("proxiware",) if provider_clause == "provider=?" else ()
        summary["assignments"] = int(
            db.execute(
                f"SELECT COUNT(*) AS count FROM {assignment_table} WHERE {provider_clause}", provider_params
            ).fetchone()["count"]
        )
        for state, key in (("live", "live"), ("online", "live"), ("offline", "dead")):
            if "live_status" in assignment_columns:
                summary[key] = int(
                    db.execute(
                        f"SELECT COUNT(*) AS count FROM {assignment_table} WHERE {provider_clause} AND LOWER(COALESCE(live_status,'')) IN (?,?)"
                        if state == "live"
                        else f"SELECT COUNT(*) AS count FROM {assignment_table} WHERE {provider_clause} AND LOWER(COALESCE(live_status,''))=?",
                        (*provider_params, "live", "online") if state == "live" else (*provider_params, state),
                    ).fetchone()["count"]
                )
        if "qualification" in assignment_columns:
            for state in ("allow", "risk", "pending"):
                summary[state] = int(
                    db.execute(
                        f"SELECT COUNT(*) AS count FROM {assignment_table} WHERE {provider_clause} AND LOWER(COALESCE(qualification,''))=?",
                        (*provider_params, state),
                    ).fetchone()["count"]
                )
        if "exit_ip" in assignment_columns:
            summary["duplicate"] = int(
                db.execute(
                    f"SELECT COUNT(*) AS count FROM {assignment_table} WHERE {provider_clause} AND exit_ip IS NOT NULL AND trim(exit_ip)<>'' AND exit_ip IN (SELECT exit_ip FROM {assignment_table} WHERE {provider_clause} AND exit_ip IS NOT NULL AND trim(exit_ip)<>'' GROUP BY exit_ip HAVING COUNT(*)>1)",
                    (*provider_params, *provider_params),
                ).fetchone()["count"]
            )

    if _proxiware_table_exists(db, "swap_jobs"):
        swap_columns = _proxiware_columns(db, "swap_jobs")
        provider_clause = "provider=?" if "provider" in swap_columns else "0=1"
        provider_params = ("proxiware",) if provider_clause == "provider=?" else ()
        summary["swaps_pending"] = int(
            db.execute(
                f"SELECT COUNT(*) AS count FROM swap_jobs WHERE {provider_clause} AND state IN ('pending','running')",
                provider_params,
            ).fetchone()["count"]
        )
        summary["swaps_blocked"] = int(
            db.execute(
                f"SELECT COUNT(*) AS count FROM swap_jobs WHERE {provider_clause} AND state='blocked'",
                provider_params,
            ).fetchone()["count"]
        )

    if _proxiware_table_exists(db, "provider_sync_runs"):
        latest_sync = db.execute(
            "SELECT id,finished_at,error_code,status,processed_count,total_count FROM provider_sync_runs "
            "WHERE provider=? ORDER BY id DESC LIMIT 1",
            ("proxiware",),
        ).fetchone()
        if latest_sync:
            summary["sync_run_id"] = int(latest_sync["id"])
            summary["sync_state"] = str(latest_sync["status"] or "idle")
            summary["sync_processed"] = int(latest_sync["processed_count"] or 0)
            summary["sync_total"] = int(latest_sync["total_count"] or 0)
            summary["last_sync"] = latest_sync["finished_at"] or "In progress"
            if latest_sync["error_code"]:
                summary["last_error"] = latest_sync["error_code"]

    rows: list[dict[str, object]] = []
    area_total = 0
    table = (
        "provider_assignments"
        if area in {"inventory", "qualification"}
        else {
            "swaps": "swap_jobs",
            "swap-history": "swap_jobs",
            "sync": "provider_sync_runs",
            "audit": "provider_audit_events",
        }.get(area)
    )
    if table and _proxiware_table_exists(db, table):
        columns = _proxiware_columns(db, table)
        if table == "provider_assignments":
            safe = (
                "id",
                "subscription_id",
                "external_id",
                "host",
                "port",
                "country",
                "status",
                "qualification",
                "provider_eligible",
                "live_status",
                "exit_ip",
                "replacement_ready_at",
                "created_at",
                "updated_at",
            )
            selected = [name for name in safe if name in columns]
            if selected:
                where = ["provider=?"] if "provider" in columns else ["0=1"]
                params: list[object] = ["proxiware"] if "provider" in columns else []
                if query["q"]:
                    searchable = [
                        name
                        for name in ("external_id", "host", "country", "status", "qualification")
                        if name in columns
                    ]
                    if searchable:
                        where.append(
                            "(" + " OR ".join(f"LOWER(CAST({name} AS TEXT)) LIKE ?" for name in searchable) + ")"
                        )
                        params.extend([f"%{query['q'].lower()}%"] * len(searchable))
                for key, column in (
                    ("live", "live_status"),
                    ("qualification", "qualification"),
                    ("country", "country"),
                ):
                    if query[key] and column in columns:
                        if key == "live" and query[key] == "online":
                            where.append(f"LOWER(COALESCE({column},'')) IN ('live','online')")
                        elif key == "live" and query[key] == "offline":
                            where.append(f"LOWER(COALESCE({column},'')) IN ('dead','offline')")
                        else:
                            where.append(f"LOWER(COALESCE({column},''))=?")
                            params.append(query[key].lower())
                if query["provider_eligibility"] and "provider_eligible" in columns:
                    if query["provider_eligibility"] == "eligible":
                        where.append("provider_eligible=1")
                    elif query["provider_eligibility"] == "ineligible":
                        where.append("provider_eligible=0")
                    else:
                        where.append("provider_eligible IS NULL")
                if query["readiness"] and "replacement_ready_at" in columns:
                    if query["readiness"] == "ready":
                        where.append("(replacement_ready_at IS NULL OR replacement_ready_at <= datetime('now'))")
                    elif query["readiness"] == "cooldown":
                        where.append("replacement_ready_at > datetime('now')")
                    elif query["readiness"] == "blocked" and "status" in columns:
                        where.append("LOWER(COALESCE(status,''))='blocked'")
                if query["duplicate"] == "duplicate" and "exit_ip" in columns:
                    where.append(
                        "exit_ip IS NOT NULL AND trim(exit_ip)<>'' AND exit_ip IN "
                        "(SELECT exit_ip FROM provider_assignments WHERE provider=? AND exit_ip IS NOT NULL "
                        "AND trim(exit_ip)<>'' GROUP BY exit_ip HAVING COUNT(*)>1)"
                    )
                    params.append("proxiware")
                if query["subscription"] and "subscription_id" in columns:
                    where.append("CAST(subscription_id AS TEXT) LIKE ?")
                    params.append(f"%{query['subscription']}%")
                area_total = int(
                    db.execute(
                        "SELECT COUNT(*) AS count FROM provider_assignments WHERE " + " AND ".join(where), params
                    ).fetchone()["count"]
                )
                effective_page = min(query["page"], max(1, math.ceil(area_total / query["per_page"])))
                sort_column = {
                    "updated": "updated_at",
                    "subscription": "subscription_id",
                    "country": "country",
                    "status": "status",
                }.get(query["sort"], "updated_at")
                if sort_column not in columns:
                    sort_column = "id" if "id" in columns else selected[0]
                order = "ASC" if query["direction"] == "asc" else "DESC"
                raw_rows = db.execute(
                    "SELECT "
                    + ",".join(selected)
                    + " FROM provider_assignments WHERE "
                    + " AND ".join(where)
                    + f" ORDER BY {sort_column} {order} LIMIT ? OFFSET ?",
                    [*params, query["per_page"], (effective_page - 1) * query["per_page"]],
                ).fetchall()
                for raw in raw_rows:
                    row = {name: raw[name] for name in selected}
                    rows.append(
                        {
                            "subscription": row.get("subscription_id", "—"),
                            "assignment": row.get("external_id", row.get("id", "—")),
                            "endpoint": f"{row.get('host')}:{row.get('port')}"
                            if row.get("host") and row.get("port")
                            else "—",
                            "country": row.get("country", "—"),
                            "live": "online"
                            if str(row.get("live_status", row.get("status", "pending"))).lower() in {"live", "online"}
                            else "offline"
                            if str(row.get("live_status", row.get("status", "pending"))).lower() in {"dead", "offline"}
                            else row.get("live_status", row.get("status", "pending")),
                            "qualification": row.get("qualification", "pending"),
                            "provider_status": row.get("provider_eligible", "—"),
                            "readiness": row.get("replacement_ready_at", "Ready"),
                            "reason": "",
                        }
                    )
                for state, key in (
                    ("online", "live"),
                    ("offline", "dead"),
                    ("allow", "allow"),
                    ("risk", "risk"),
                    ("pending", "pending"),
                ):
                    column = "live_status" if state in {"online", "offline"} else "qualification"
                    if column in columns:
                        values = (
                            ("live", "online")
                            if state == "online"
                            else ("dead", "offline")
                            if state == "offline"
                            else (state,)
                        )
                        summary[key] = int(
                            db.execute(
                                "SELECT COUNT(*) AS count FROM provider_assignments WHERE "
                                + " AND ".join(where[:1])
                                + (
                                    f" AND LOWER(COALESCE({column},'')) IN (?,?)"
                                    if len(values) == 2
                                    else f" AND LOWER(COALESCE({column},''))=?"
                                ),
                                [*params[:1], *values],
                            ).fetchone()["count"]
                        )
        else:
            safe_map = {
                "swaps": (
                    "id",
                    "subscription_id",
                    "old_assignment_id",
                    "new_assignment_id",
                    "state",
                    "attempts",
                    "error_code",
                    "created_at",
                    "updated_at",
                ),
                "swap-history": (
                    "id",
                    "subscription_id",
                    "old_assignment_id",
                    "new_assignment_id",
                    "state",
                    "attempts",
                    "error_code",
                    "created_at",
                    "updated_at",
                ),
                "sync": (
                    "id",
                    "started_at",
                    "finished_at",
                    "duration_ms",
                    "added_count",
                    "updated_count",
                    "missing_count",
                    "error_count",
                    "status",
                    "error_code",
                ),
                "audit": ("id", "actor_id", "action", "target_id", "result", "error_code", "created_at"),
            }
            selected = [name for name in safe_map[area] if name in columns]
            if selected:
                provider_clause = "provider=?" if "provider" in columns else "0=1"
                params = ["proxiware"] if "provider" in columns else []
                area_total = int(
                    db.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {provider_clause}", params).fetchone()[
                        "count"
                    ]
                )
                effective_page = min(query["page"], max(1, math.ceil(area_total / query["per_page"])))
                rows_raw = db.execute(
                    f"SELECT {','.join(selected)} FROM {table} WHERE {provider_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                    [*params, query["per_page"], (effective_page - 1) * query["per_page"]],
                ).fetchall()
                for raw in rows_raw:
                    value = {name: raw[name] for name in selected}
                    if area in {"swaps", "swap-history"}:
                        rows.append(
                            {
                                "job_id": value.get("id"),
                                "subscription": value.get("subscription_id", "—"),
                                "old_assignment": value.get("old_assignment_id", "—"),
                                "new_assignment": value.get("new_assignment_id", "—"),
                                "state": value.get("state", "pending"),
                                "attempts": value.get("attempts", 0),
                                "ready_at": value.get("updated_at", "—"),
                                "error_code": value.get("error_code", "—"),
                                "retryable": value.get("state") in {"failed", "blocked", "canceled"},
                                "cancelable": value.get("state") in {"pending", "running"},
                                "manual_available": value.get("state") in {"pending", "failed", "blocked", "canceled"},
                                "retry_url": url_for("admin.proxiware_swap_retry", job_id=int(value["id"]))
                                if value.get("id") is not None
                                else "#",
                                "cancel_url": url_for("admin.proxiware_swap_cancel", job_id=int(value["id"]))
                                if value.get("id") is not None
                                else "#",
                                "manual_url": url_for("admin.proxiware_swap_manual", job_id=int(value["id"]))
                                if value.get("id") is not None
                                else "#",
                            }
                        )
                    elif area == "sync":
                        rows.append(
                            {
                                "started": value.get("started_at", "—"),
                                "finished": value.get("finished_at", "—"),
                                "duration": value.get("duration_ms", "—"),
                                "added": value.get("added_count", 0),
                                "updated": value.get("updated_count", 0),
                                "missing": value.get("missing_count", 0),
                                "errors": value.get("error_count", 0),
                                "result": value.get("status", "—"),
                            }
                        )
                    else:
                        rows.append(
                            {
                                "created": value.get("created_at", "—"),
                                "actor": value.get("actor_id", "—"),
                                "action": value.get("action", "—"),
                                "target": value.get("target_id", "—"),
                                "result": value.get("result", "—"),
                            }
                        )
                if area in {"swaps", "swap-history"}:
                    summary["swaps_pending"] = int(
                        db.execute(
                            f"SELECT COUNT(*) AS count FROM {table} WHERE {provider_clause} AND state IN ('pending','running')",
                            params,
                        ).fetchone()["count"]
                    )
                    summary["swaps_blocked"] = int(
                        db.execute(
                            f"SELECT COUNT(*) AS count FROM {table} WHERE {provider_clause} AND state='blocked'", params
                        ).fetchone()["count"]
                    )
    total = (
        area_total
        if table and _proxiware_table_exists(db, table)
        else int(summary["assignments"] if area in {"inventory", "qualification"} else len(rows))
    )
    if area in {"swaps", "swap-history", "sync", "audit"} and table and _proxiware_table_exists(db, table):
        provider_clause = "provider=?" if "provider" in _proxiware_columns(db, table) else "0=1"
        total = int(
            db.execute(
                f"SELECT COUNT(*) AS count FROM {table} WHERE {provider_clause}",
                ("proxiware",) if provider_clause == "provider=?" else (),
            ).fetchone()["count"]
        )
    total_pages = max(1, math.ceil(total / query["per_page"]))
    page = min(query["page"], total_pages)

    def page_url(page_number: int) -> str:
        values = {key: value for key, value in query.items() if key not in {"page"} and value not in ("", None)}
        values["page"] = page_number
        path = _proxiware_area_url(area)
        return path + ("?" + urlencode(values) if values else "")

    links = (
        [{"number": number, "current": number == page, "url": page_url(number)} for number in range(1, total_pages + 1)]
        if total_pages <= 7
        else [
            {"number": 1, "current": page == 1, "url": page_url(1)},
            {"ellipsis": True},
            {"number": page, "current": True, "url": page_url(page)},
            {"ellipsis": True},
            {"number": total_pages, "current": page == total_pages, "url": page_url(total_pages)},
        ]
    )

    def quick_filter_url(key: str) -> str:
        values = {k: v for k, v in query.items() if k not in {"page", "per_page"} and v}
        values["page"] = 1
        if key == "all":
            for name in ("live", "qualification", "duplicate"):
                values.pop(name, None)
        elif key in {"live", "dead"}:
            values["live"] = "online" if key == "live" else "offline"
        elif key in {"allow", "risk", "pending"}:
            values["qualification"] = key
        elif key == "duplicate":
            values["duplicate"] = "duplicate"
        path = _proxiware_area_url(area)
        return path + ("?" + urlencode(values) if values else "")

    filter_urls = {
        key: quick_filter_url(key) for key in ("all", "live", "dead", "allow", "risk", "pending", "duplicate")
    }
    return {
        "area": area,
        "workspace_url": _proxiware_area_url(area),
        "areas": areas,
        "summary": summary,
        "rows": rows,
        "filters": query,
        "filter_urls": filter_urls,
        "pagination": {
            "page": page,
            "per_page": query["per_page"],
            "total": total,
            "total_pages": total_pages,
            "start": (page - 1) * query["per_page"] + 1 if total else 0,
            "end": min(page * query["per_page"], total),
            "links": links,
            "previous_url": page_url(max(1, page - 1)),
            "next_url": page_url(min(total_pages, page + 1)),
        },
        "session_status": session_status,
        "worker_status": worker_status,
        "worker_heartbeats": heartbeat_states,
        "worker_paused": worker_paused,
        "automation_paused": automation_paused,
        "auto_swap_enabled": auto_swap_enabled,
        "distribution_enabled": distribution_enabled,
        "sync_available": bool(credentials["proxiware_api_key"]),
        "swap_adapter_available": bool(
            current_app.extensions.get("proxiware_browser_adapter_factory")
            and current_app.extensions.get("proxiware_captcha_adapter_factory")
        ),
        "credentials": credentials,
        "settings": settings,
        "area_label": dict((key, label) for key, label in PROXIWARE_AREAS).get(area, area.title()),
        "error": "",
    }


@dataclass(frozen=True)
class AdminProxyQuery:
    page: int
    per_page: int
    search: str
    owner: str
    endpoint: str
    status: str
    protocol: str
    eligibility: str
    identity: str
    country: str
    freshness: str
    archived: str
    sort: str
    direction: str

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


def _bounded_int(value: object, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value or ""))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _admin_proxy_query(args) -> AdminProxyQuery:
    try:
        requested_size = int(str(args.get("per_page") or "25"))
    except (TypeError, ValueError):
        requested_size = 25

    def allowed(name: str, choices: tuple[str, ...], default: str = "") -> str:
        value = str(args.get(name) or default).strip().lower()
        return value if value in choices else default

    sort = str(args.get("sort") or "created").strip().lower()
    direction = str(args.get("direction") or "desc").strip().lower()
    country = str(args.get("country") or "").strip().upper()[:2]
    return AdminProxyQuery(
        page=_bounded_int(args.get("page"), default=1, minimum=1, maximum=10_000_000),
        per_page=requested_size if requested_size in ADMIN_PROXY_PAGE_SIZES else 25,
        search=str(args.get("q") or "").strip()[:100],
        owner=str(args.get("owner") or "").strip()[:100],
        endpoint=str(args.get("endpoint") or "").strip()[:100],
        status=allowed("status", ADMIN_PROXY_STATUSES),
        protocol=allowed("protocol", ADMIN_PROXY_PROTOCOLS),
        eligibility=allowed("eligibility", ADMIN_PROXY_ELIGIBILITIES),
        identity=allowed("identity", ADMIN_PROXY_IDENTITIES),
        country=country if len(country) == 2 and country.isalpha() else "",
        freshness=allowed("freshness", ADMIN_PROXY_FRESHNESS),
        archived=allowed("archived", ADMIN_PROXY_ARCHIVED, "active"),
        sort=sort if sort in ADMIN_PROXY_SORT_COLUMNS else "created",
        direction=direction if direction in {"asc", "desc"} else "desc",
    )


def _like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped.lower()}%"


def _parse_admin_timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or ""))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _admin_proxy_conditions(
    query: AdminProxyQuery, *, stale_cutoff: str, now_iso: str
) -> tuple[list[str], list[object]]:
    conditions: list[str] = []
    parameters: list[object] = []
    if query.archived == "archived":
        conditions.append("p.archived_at IS NOT NULL")
    elif query.archived == "active":
        conditions.append("p.archived_at IS NULL")
    if query.search:
        pattern = _like_pattern(query.search)
        conditions.append(
            "(LOWER(p.host) LIKE ? ESCAPE '\\' OR CAST(p.port AS TEXT) LIKE ? ESCAPE '\\' "
            "OR LOWER(u.email) LIKE ? ESCAPE '\\' OR "
            "(p.egress_attestation_source IN ('https_quorum','earnapp_tls') "
            "AND LOWER(COALESCE(p.exit_ip,'')) LIKE ? ESCAPE '\\'))"
        )
        parameters.extend((pattern, pattern, pattern, pattern))
    if query.owner:
        conditions.append("LOWER(u.email) LIKE ? ESCAPE '\\'")
        parameters.append(_like_pattern(query.owner))
    if query.endpoint:
        pattern = _like_pattern(query.endpoint)
        conditions.append("(LOWER(p.host) LIKE ? ESCAPE '\\' OR CAST(p.port AS TEXT) LIKE ? ESCAPE '\\')")
        parameters.extend((pattern, pattern))
    if query.status:
        conditions.append("p.status=?")
        parameters.append(query.status)
    if query.protocol:
        if query.protocol == "unknown":
            conditions.append("COALESCE(NULLIF(p.detected_protocol,''),'unknown') IN ('unknown','auto')")
        else:
            conditions.append("p.detected_protocol=?")
            parameters.append(query.protocol)
    if query.eligibility:
        conditions.append("p.eligibility=?")
        parameters.append(query.eligibility)
    trusted = "p.egress_attestation_source IN ('https_quorum','earnapp_tls')"
    if query.identity == "canonical":
        conditions.append(f"{trusted} AND p.exit_ip IS NOT NULL AND trim(p.exit_ip)<>'' AND p.duplicate_of IS NULL")
    elif query.identity == "duplicate":
        conditions.append(f"{trusted} AND p.exit_ip IS NOT NULL AND trim(p.exit_ip)<>'' AND p.duplicate_of IS NOT NULL")
    elif query.identity == "awaiting":
        conditions.append(f"NOT ({trusted} AND p.exit_ip IS NOT NULL AND trim(p.exit_ip)<>'')")
    if query.country:
        conditions.append("UPPER(p.country_code)=?")
        parameters.append(query.country)
    if query.freshness:
        freshness_sql, freshness_parameters = _admin_proxy_freshness_condition(
            query.freshness, stale_cutoff=stale_cutoff, now_iso=now_iso
        )
        conditions.append(freshness_sql)
        parameters.extend(freshness_parameters)
    return conditions or ["1=1"], parameters


def _admin_proxy_freshness_condition(state: str, *, stale_cutoff: str, now_iso: str) -> tuple[str, tuple[str, ...]]:
    """Use SQLite date functions so naive and timezone-aware stored values agree."""
    checked = "NULLIF(trim(COALESCE(p.last_checked_at,'')), '')"
    success = "NULLIF(trim(COALESCE(p.last_success_at,'')), '')"
    next_check = "NULLIF(trim(COALESCE(p.next_check_at,'')), '')"
    if state == "fresh":
        return (
            f"({checked} IS NOT NULL AND julianday({checked}) IS NOT NULL AND {success} IS NOT NULL "
            f"AND julianday({success}) IS NOT NULL AND julianday({success})>=julianday(?) AND "
            f"({next_check} IS NULL OR (julianday({next_check}) IS NOT NULL AND "
            f"julianday({next_check})>=julianday(?))) )",
            (stale_cutoff, now_iso),
        )
    if state == "due":
        return (
            f"({checked} IS NOT NULL AND julianday({checked}) IS NOT NULL AND {success} IS NOT NULL "
            f"AND julianday({success}) IS NOT NULL AND julianday({success})>=julianday(?) AND "
            f"{next_check} IS NOT NULL AND (julianday({next_check}) IS NULL OR "
            f"julianday({next_check})<julianday(?)))",
            (stale_cutoff, now_iso),
        )
    if state == "stale":
        return (
            f"({checked} IS NOT NULL AND (julianday({checked}) IS NULL OR {success} IS NULL OR "
            f"julianday({success}) IS NULL OR julianday({success})<julianday(?)))",
            (stale_cutoff,),
        )
    return (f"({checked} IS NULL)", ())


def _admin_proxy_url_args(query: AdminProxyQuery, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "q": query.search,
        "owner": query.owner,
        "endpoint": query.endpoint,
        "status": query.status,
        "protocol": query.protocol,
        "eligibility": query.eligibility,
        "identity": query.identity,
        "country": query.country,
        "freshness": query.freshness,
        "archived": query.archived,
        "sort": query.sort,
        "direction": query.direction,
        "per_page": query.per_page,
        "page": query.page,
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value not in ("", None)}


def _admin_proxy_url(query: AdminProxyQuery, **overrides: object) -> str:
    """Build inventory links without colliding with Flask's `endpoint` argument."""
    values = _admin_proxy_url_args(query, **overrides)
    path = url_for("admin.proxies")
    query_string = urlencode(values)
    return f"{path}?{query_string}" if query_string else path


def _admin_proxy_page(db, args) -> dict[str, object]:
    query = _admin_proxy_query(args)
    now = datetime.now(UTC)
    stale_at = now - timedelta(minutes=checker_settings(db).health_stale_minutes)
    stale_cutoff = stale_at.isoformat()
    now_iso = now.isoformat()
    conditions, parameters = _admin_proxy_conditions(query, stale_cutoff=stale_cutoff, now_iso=now_iso)
    where = " AND ".join(conditions)

    active_count = int(
        db.execute("SELECT COUNT(*) AS count FROM proxies WHERE archived_at IS NULL").fetchone()["count"]
    )
    archived_count = int(
        db.execute("SELECT COUNT(*) AS count FROM proxies WHERE archived_at IS NOT NULL").fetchone()["count"]
    )
    scope_condition = {
        "active": "p.archived_at IS NULL",
        "archived": "p.archived_at IS NOT NULL",
        "all": "1=1",
    }[query.archived]
    total_count = int(
        db.execute("SELECT COUNT(*) AS count FROM proxies p WHERE " + scope_condition).fetchone()["count"]
    )
    filtered_count = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies p JOIN users u ON u.id=p.user_id WHERE " + where,
            parameters,
        ).fetchone()["count"]
    )
    total_pages = max(1, math.ceil(filtered_count / query.per_page))
    query = replace(query, page=min(query.page, total_pages))
    order_direction = "ASC" if query.direction == "asc" else "DESC"
    order = ", ".join(f"{column} {order_direction}" for column in ADMIN_PROXY_SORT_COLUMNS[query.sort])
    rows = db.execute(
        "SELECT "
        + ", ".join(ADMIN_PROXY_SELECT_COLUMNS)
        + ", u.email AS owner_email FROM proxies p JOIN users u ON u.id=p.user_id WHERE "
        + where
        + f" ORDER BY {order} LIMIT ? OFFSET ?",
        [*parameters, query.per_page, query.offset],
    ).fetchall()

    def grouped_count(expression: str) -> dict[str, int]:
        grouped = db.execute(
            f"SELECT {expression} AS value, COUNT(*) AS count FROM proxies p "
            "WHERE " + scope_condition + " GROUP BY value"
        ).fetchall()
        return {str(row["value"]): int(row["count"]) for row in grouped}

    status_counts = grouped_count("COALESCE(NULLIF(p.status,''),'unknown')")
    protocol_counts_raw = grouped_count("COALESCE(NULLIF(p.detected_protocol,''),'unknown')")
    protocol_counts = {
        "http": protocol_counts_raw.get("http", 0),
        "socks5": protocol_counts_raw.get("socks5", 0),
        "unknown": sum(count for value, count in protocol_counts_raw.items() if value not in {"http", "socks5"}),
    }
    eligibility_counts = grouped_count("COALESCE(NULLIF(p.eligibility,''),'pending')")
    trusted = "p.egress_attestation_source IN ('https_quorum','earnapp_tls') AND p.exit_ip IS NOT NULL AND trim(p.exit_ip)<>''"

    def scalar_count(extra: str, values: tuple[object, ...] = ()) -> int:
        return int(
            db.execute(
                "SELECT COUNT(*) AS count FROM proxies p WHERE " + scope_condition + " AND " + extra,
                values,
            ).fetchone()["count"]
        )

    identity_counts = {
        "canonical": scalar_count(f"{trusted} AND p.duplicate_of IS NULL"),
        "duplicate": scalar_count(f"{trusted} AND p.duplicate_of IS NOT NULL"),
        "awaiting": scalar_count(f"NOT ({trusted})"),
    }
    freshness_counts = {
        "fresh": scalar_count(
            *_admin_proxy_freshness_condition("fresh", stale_cutoff=stale_cutoff, now_iso=now_iso),
        ),
        "due": scalar_count(
            *_admin_proxy_freshness_condition("due", stale_cutoff=stale_cutoff, now_iso=now_iso),
        ),
        "stale": scalar_count(
            *_admin_proxy_freshness_condition("stale", stale_cutoff=stale_cutoff, now_iso=now_iso),
        ),
        "never": scalar_count(*_admin_proxy_freshness_condition("never", stale_cutoff=stale_cutoff, now_iso=now_iso)),
    }
    countries = db.execute(
        "SELECT UPPER(p.country_code) AS code, COUNT(*) AS count FROM proxies p "
        "WHERE "
        + scope_condition
        + " AND length(trim(country_code))=2 GROUP BY UPPER(country_code) ORDER BY count DESC, code LIMIT 250"
    ).fetchall()

    def route_url(**overrides: object) -> str:
        return _admin_proxy_url(query, **overrides)

    def filter_url(**overrides: object) -> str:
        toggled = dict(overrides)
        for key, value in overrides.items():
            if value and getattr(query, key, None) == value:
                toggled[key] = ""
        return route_url(page=1, **toggled)

    sort_urls = {
        key: route_url(
            page=1,
            sort=key,
            direction="desc" if query.sort == key and query.direction == "asc" else "asc",
        )
        for key in ADMIN_PROXY_SORT_COLUMNS
    }
    page_links: list[dict[str, object]] = []
    visible_pages = {1, total_pages, query.page, query.page - 1, query.page + 1}
    previous_number = 0
    for page_number in sorted(number for number in visible_pages if 1 <= number <= total_pages):
        if previous_number and page_number > previous_number + 1:
            page_links.append({"ellipsis": True})
        page_links.append(
            {"number": page_number, "current": page_number == query.page, "url": route_url(page=page_number)}
        )
        previous_number = page_number

    def freshness_view(row) -> dict[str, str]:
        raw_checked_at = str(row["last_checked_at"] or "").strip()
        raw_next_check_at = str(row["next_check_at"] or "").strip()
        checked_at = _parse_admin_timestamp(row["last_checked_at"])
        success_at = _parse_admin_timestamp(row["last_success_at"])
        next_check_at = _parse_admin_timestamp(row["next_check_at"])
        if not raw_checked_at:
            return {"state": "never", "label": "Never checked"}
        if checked_at is None or success_at is None or success_at < stale_at:
            return {"state": "stale", "label": "Stale"}
        if raw_next_check_at and (next_check_at is None or next_check_at < now):
            return {"state": "due", "label": "Check due"}
        return {"state": "fresh", "label": "Fresh"}

    def timestamp_view(value: object, *, empty_label: str) -> dict[str, str]:
        parsed = _parse_admin_timestamp(value)
        if parsed is None:
            return {"iso": "", "label": empty_label}
        return {"iso": parsed.isoformat(), "label": parsed.strftime("%b %d, %Y %H:%M UTC")}

    def identity_view(row) -> dict[str, str]:
        is_trusted = str(row["egress_attestation_source"] or "") in {"https_quorum", "earnapp_tls"} and bool(
            str(row["exit_ip"] or "").strip()
        )
        if is_trusted and row["duplicate_of"] is not None:
            return {"state": "duplicate", "label": "Duplicate"}
        if is_trusted:
            return {"state": "canonical", "label": "Canonical"}
        return {"state": "awaiting", "label": "Awaiting probe"}

    views = [
        {
            "row": row,
            "freshness": freshness_view(row),
            "identity": identity_view(row),
            "last_checked": timestamp_view(row["last_checked_at"], empty_label="Never"),
            "next_check": timestamp_view(row["next_check_at"], empty_label="Not scheduled"),
        }
        for row in rows
    ]
    return {
        "query": query,
        "views": views,
        "total_count": total_count,
        "active_count": active_count,
        "archived_count": archived_count,
        "filtered_count": filtered_count,
        "total_pages": total_pages,
        "start_index": query.offset + 1 if filtered_count else 0,
        "end_index": min(query.offset + len(rows), filtered_count),
        "status_counts": status_counts,
        "protocol_counts": protocol_counts,
        "eligibility_counts": eligibility_counts,
        "identity_counts": identity_counts,
        "freshness_counts": freshness_counts,
        "countries": countries,
        "filter_url": filter_url,
        "sort_urls": sort_urls,
        "page_links": page_links,
        "previous_url": route_url(page=max(1, query.page - 1)),
        "next_url": route_url(page=min(total_pages, query.page + 1)),
        "reset_url": url_for("admin.proxies"),
        "duplicate_groups_url": url_for("admin.egress_duplicates"),
    }


def _egress_duplicate_query(args) -> tuple[int, int, str]:
    try:
        page = max(1, min(10_000_000, int(str(args.get("page") or "1"))))
    except (TypeError, ValueError):
        page = 1
    try:
        requested = int(str(args.get("per_page") or "25"))
    except (TypeError, ValueError):
        requested = 25
    per_page = requested if requested in EGRESS_DUPLICATE_PAGE_SIZES else 25
    search = str(args.get("q") or "").strip()[:100]
    return page, per_page, search


def _egress_duplicate_page(db, args) -> dict[str, object]:
    page, per_page, search = _egress_duplicate_query(args)
    conditions = [
        "p.archived_at IS NULL",
        "p.exit_ip IS NOT NULL",
        "trim(p.exit_ip)<>''",
        "p.egress_attestation_source IN ('https_quorum','earnapp_tls')",
    ]
    parameters: list[object] = []
    if search:
        conditions.append("p.exit_ip LIKE ? ESCAPE '\\'")
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        parameters.append(f"%{escaped}%")
    where = " AND ".join(conditions)
    total = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM (SELECT p.exit_ip FROM proxies p WHERE "
            + where
            + " GROUP BY p.exit_ip HAVING COUNT(*)>1)",
            parameters,
        ).fetchone()["count"]
    )
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    rows = db.execute(
        """
        SELECT p.exit_ip,
               COUNT(*) AS proxy_count,
               SUM(CASE WHEN p.duplicate_of IS NOT NULL THEN 1 ELSE 0 END) AS duplicate_count,
               COUNT(DISTINCT p.user_id) AS account_count,
               MIN(CASE WHEN p.duplicate_of IS NULL THEN p.host END) AS canonical_host,
               MIN(CASE WHEN p.duplicate_of IS NULL THEN p.port END) AS canonical_port
        FROM proxies p
        WHERE """
        + where
        + " GROUP BY p.exit_ip HAVING COUNT(*)>1 ORDER BY proxy_count DESC, p.exit_ip LIMIT ? OFFSET ?",
        [*parameters, per_page, (page - 1) * per_page],
    ).fetchall()

    def page_url(**overrides: object) -> str:
        values = {"q": search, "per_page": per_page, "page": page}
        values.update(overrides)
        return url_for(
            "admin.egress_duplicates",
            **{key: value for key, value in values.items() if value not in ("", None)},
        )

    return {
        "groups": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "start_index": (page - 1) * per_page + 1 if total else 0,
        "end_index": min(page * per_page, total),
        "search": search,
        "previous_url": page_url(page=max(1, page - 1)),
        "next_url": page_url(page=min(total_pages, page + 1)),
        "reset_url": url_for("admin.egress_duplicates"),
    }


def _egress_duplicate_members_page(db, exit_ip: str, args) -> dict[str, object]:
    try:
        normalized_exit = str(ipaddress.ip_address(exit_ip))
    except ValueError:
        abort(404)
    page, per_page, _ = _egress_duplicate_query(args)
    trusted_members = (
        "p.archived_at IS NULL AND p.exit_ip=? AND p.egress_attestation_source IN ('https_quorum','earnapp_tls')"
    )
    total = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies p WHERE " + trusted_members,
            (normalized_exit,),
        ).fetchone()["count"]
    )
    if total < 2:
        abort(404)
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    members = db.execute(
        "SELECT p.host,p.port,p.status,p.duplicate_of,u.email FROM proxies p JOIN users u ON u.id=p.user_id "
        "WHERE " + trusted_members + " ORDER BY p.duplicate_of IS NOT NULL, p.created_at, p.id LIMIT ? OFFSET ?",
        (normalized_exit, per_page, (page - 1) * per_page),
    ).fetchall()

    def page_url(**overrides: object) -> str:
        values = {"per_page": per_page, "page": page}
        values.update(overrides)
        return url_for(
            "admin.egress_duplicate_members",
            exit_ip=normalized_exit,
            **values,
        )

    return {
        "exit_ip": normalized_exit,
        "members": members,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "start_index": (page - 1) * per_page + 1,
        "end_index": min(page * per_page, total),
        "previous_url": page_url(page=max(1, page - 1)),
        "next_url": page_url(page=min(total_pages, page + 1)),
        "list_url": url_for("admin.egress_duplicates"),
    }


@bp.get("")
@admin_required
def dashboard():
    return render_template(
        "admin_dashboard.html",
        stats=operational_stats(get_db()),
        admin_section="overview",
    )


@bp.get("/providers/proxiware")
@bp.get("/providers/proxiware/<area>")
@admin_required
def proxiware_workspace(area: str = "overview"):
    area = _canonical_proxiware_area(area)
    if area == "swap-history":
        return proxiware_swap_history()
    if area not in PROXIWARE_AREA_KEYS:
        abort(404)
    response = current_app.make_response(
        render_template(
            "admin_proxiware.html",
            **_proxiware_snapshot(get_db(), area, request.args),
            admin_section="proxiware",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/providers/proxiware/swaps/history")
@admin_required
def proxiware_swap_history():
    response = current_app.make_response(
        render_template(
            "admin_proxiware.html",
            **_proxiware_snapshot(get_db(), "swap-history", request.args),
            admin_section="proxiware",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/providers/proxiware/credentials")
@admin_required
def proxiware_credentials():
    db = get_db()
    ensure_proxiware_swap_schema(db)
    try:
        save_provider_credentials(
            db,
            {
                "login_email": request.form.get("proxiware_email", ""),
                "login_password": request.form.get("proxiware_password", ""),
                "api_key": request.form.get("proxiware_api_key", ""),
                "captcha_api_key": request.form.get("twocaptcha_api_key", ""),
            },
        )
        if "auto_swap_enabled" in request.form:
            set_setting(db, "proxiware_auto_swap", "1" if request.form.get("auto_swap_enabled") else "0")
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="save_credentials",
            result="success",
        )
    except ValueError as exc:
        return form_error(str(exc), 400, "admin.proxiware_workspace", area="credentials")
    return _no_store_response(
        form_success(
            {"status": "saved"},
            endpoint="admin.proxiware_workspace",
            area="credentials",
            message="Provider credentials saved.",
        )
    )


@bp.post("/providers/proxiware/credentials/clear/<name>")
@admin_required
def proxiware_clear_credential(name: str):
    aliases = {
        "email": "login_email",
        "password": "login_password",
        "api-key": "api_key",
        "captcha-key": "captcha_api_key",
    }
    secret_name = aliases.get(str(name).strip().lower())
    if secret_name is None:
        abort(404)
    db = get_db()
    clear_provider_secret(db, secret_name)
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="clear_credential",
        target_id=name,
        result="success",
    )
    return _no_store_response(
        form_success(
            {"status": "cleared", "name": name},
            endpoint="admin.proxiware_workspace",
            area="credentials",
            message="Provider credential cleared.",
        )
    )


@bp.post("/providers/proxiware/settings")
@admin_required
def proxiware_settings():
    db = get_db()
    if not _provider_action_allowed(db, "settings"):
        return _proxiware_action_error("Provider policy rate limit reached.", 429, code="rate_limited")
    try:
        threshold = max(1, min(100_000, int(request.form.get("eligibility_threshold", "1000"))))
        concurrency = max(1, min(20, int(request.form.get("worker_concurrency", "1"))))
        retry_limit = max(0, min(5, int(request.form.get("retry_limit", "2"))))
        cooldown = max(60, min(86_400, int(request.form.get("cooldown_seconds", "60"))))
    except ValueError:
        return form_error("Provider settings must be numbers", 400, "admin.proxiware_workspace", area="settings")
    set_setting(db, "proxiware_eligible_threshold", str(threshold))
    set_setting(db, "proxiware_worker_concurrency", str(concurrency))
    set_setting(db, "proxiware_retry_limit", str(retry_limit))
    set_setting(db, "proxiware_cooldown_seconds", str(cooldown))
    set_setting(db, "proxiware_auto_swap", "1" if request.form.get("auto_swap_enabled") else "0")
    set_setting(db, "proxiware_distribution_enabled", "1" if request.form.get("distribution_enabled") else "0")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="save_settings",
        result="success",
    )
    return _no_store_response(
        form_success(
            {"status": "saved"},
            endpoint="admin.proxiware_workspace",
            area="settings",
            message="Provider settings saved.",
        )
    )


def _proxiware_action_response(payload: dict[str, object], *, status: int = 200, message: str = ""):
    """Return a credential-safe JSON response or an explicit UI redirect."""
    if is_browser_form():
        response = form_success(
            payload,
            endpoint="admin.proxiware_workspace",
            area="overview",
            message=message or "Provider action completed.",
            status=status,
        )
    else:
        response = jsonify(payload)
        response.status_code = status
    return _no_store_response(response)


def _proxiware_action_error(message: str, status: int, *, code: str = "provider_error"):
    """Return only a safe operator message and allowlisted error code."""
    code = code if code in PROXIWARE_SAFE_ERROR_CODES else "provider_error"
    if is_browser_form():
        response = form_error(message, status, "admin.proxiware_workspace", area="overview")
    else:
        response = jsonify(error=message, error_code=code)
        response.status_code = status
    return _no_store_response(response)


def _provider_action_allowed(db, action: str) -> bool:
    """Apply a small DB-backed per-admin limit to expensive provider actions."""

    action = str(action or "").strip().lower()
    if action not in PROXIWARE_RATE_LIMITED_ACTIONS:
        return True
    ensure_proxiware_swap_schema(db)
    try:
        limit = max(1, min(100, int(current_app.config.get("PROXIWARE_ACTION_RATE_LIMIT", 10))))
        window = max(1, min(86_400, int(current_app.config.get("PROXIWARE_ACTION_RATE_WINDOW_SECONDS", 60))))
    except (TypeError, ValueError):
        limit, window = 10, 60
    now = datetime.now(UTC)
    cutoff = (now - timedelta(seconds=window)).isoformat()
    db.execute(
        "DELETE FROM provider_action_attempts WHERE provider=? AND attempted_at<?",
        ("proxiware", cutoff),
    )
    count = db.execute(
        "SELECT COUNT(*) AS count FROM provider_action_attempts "
        "WHERE provider=? AND actor_id=? AND action=? AND attempted_at>=?",
        ("proxiware", int(g.user["id"]), action, cutoff),
    ).fetchone()["count"]
    if int(count) >= limit:
        db.commit()
        return False
    db.execute(
        "INSERT INTO provider_action_attempts(provider,actor_id,action,attempted_at) VALUES(?,?,?,?)",
        ("proxiware", int(g.user["id"]), action, now.isoformat()),
    )
    db.commit()
    return True


def _no_store_response(response):
    """Apply a no-store header to Flask responses and `(response, status)` tuples."""
    flask_response = current_app.make_response(response) if isinstance(response, tuple) else response
    flask_response.headers["Cache-Control"] = "no-store"
    return flask_response


@bp.after_request
def _protect_proxiware_responses(response):
    if request.path.startswith("/admin/providers/proxiware"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _proxiware_api_client(api_key: str):
    factory = current_app.extensions.get("proxiware_api_client_factory")
    if factory is not None:
        return factory(api_key)
    base_url = str(current_app.config.get("PROXIWARE_API_BASE_URL") or "").strip()
    default_url = "https://api.proxiware.com/v1"
    return (
        ProxiwareClient(api_key, base_url=base_url)
        if base_url and base_url != default_url
        else ProxiwareClient(api_key)
    )


@bp.post("/providers/proxiware/sync")
@admin_required
def proxiware_sync():
    db = get_db()
    if not _provider_action_allowed(db, "sync"):
        return _proxiware_action_error("Provider sync rate limit reached.", 429, code="rate_limited")
    ensure_proxiware_swap_schema(db)
    api_key = get_provider_secret(db, "api_key")
    if not api_key:
        return _proxiware_action_error("Proxiware API key is not configured.", 503, code="missing_api_key")
    try:
        queued = enqueue_sync_run(db)
    except (ValueError, TypeError):
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="sync_inventory",
            result="failed",
            error_code="invalid_configuration",
        )
        return _proxiware_action_error("Provider configuration is invalid.", 400, code="invalid_configuration")
    except Exception:  # noqa: BLE001 - queue boundary must not expose database details
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="sync_inventory",
            result="failed",
            error_code="provider_error",
        )
        return _proxiware_action_error("Provider sync could not be queued.", 500)
    if queued is None:
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="sync_inventory",
            result="already_running",
            error_code="already_running",
        )
        return _proxiware_action_error("A Proxiware sync is already running.", 409, code="already_running")
    payload = {
        "status": "queued",
        "run_id": int(queued["run_id"]),
    }
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="sync_inventory",
        target_id=str(queued["run_id"]),
        result="queued",
    )
    return _proxiware_action_response(payload, status=202, message="Provider sync queued.")


@bp.post("/providers/proxiware/sync/<int:run_id>/cancel")
@admin_required
def proxiware_sync_cancel(run_id: int):
    db = get_db()
    if not request_sync_cancel(db, run_id):
        return _proxiware_action_error("Sync is not running or has already finished.", 409, code="conflict")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="cancel_sync",
        target_id=str(run_id),
        result="cancel_requested",
    )
    return _proxiware_action_response(
        {"status": "cancel_requested", "run_id": int(run_id)},
        message="Sync cancellation requested.",
    )


@bp.post("/providers/proxiware/test-connection")
@admin_required
def proxiware_test_connection():
    db = get_db()
    if not _provider_action_allowed(db, "test_connection"):
        return _proxiware_action_error("Provider connection test rate limit reached.", 429, code="rate_limited")
    ensure_proxiware_swap_schema(db)
    api_key = get_provider_secret(db, "api_key")
    captcha_key = get_provider_secret(db, "captcha_api_key")
    if not api_key or not captcha_key:
        return _proxiware_action_error(
            "Provider API and CAPTCHA credentials must be configured.", 503, code="not_configured"
        )
    api_factory = current_app.extensions.get("proxiware_api_client_factory")
    captcha_factory = current_app.extensions.get("proxiware_captcha_adapter_factory")
    if api_factory is None or captcha_factory is None:
        return _proxiware_action_error("Provider connection adapter is not configured.", 503, code="adapter_missing")
    try:
        api_client = _proxiware_api_client(api_key)
        captcha_adapter = captcha_factory(captcha_key)
        result = test_provider_connections(db, api_client, captcha_adapter)
    except Exception:  # noqa: BLE001 - read-only dependency boundary
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="test_connection",
            result="failed",
            error_code="provider_error",
        )
        return _proxiware_action_error("Provider connection test failed.", 502)
    payload = {
        "status": "ok" if result.api_ok and result.captcha_ok else "degraded",
        "api_ok": bool(result.api_ok),
        "captcha_ok": bool(result.captcha_ok),
        "captcha_balance": result.captcha_balance,
        "error_code": str(result.error_code or ""),
    }
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="test_connection",
        result=payload["status"],
        error_code=payload["error_code"],
    )
    return _proxiware_action_response(payload, message="Provider connection checked.")


@bp.post("/providers/proxiware/renew-session")
@admin_required
def proxiware_renew_session():
    db = get_db()
    if not _provider_action_allowed(db, "renew_session"):
        return _proxiware_action_error("Provider session renewal rate limit reached.", 429, code="rate_limited")
    ensure_proxiware_swap_schema(db)
    browser_factory = current_app.extensions.get("proxiware_browser_adapter_factory")
    captcha_factory = current_app.extensions.get("proxiware_captcha_adapter_factory")
    site_key = str(current_app.config.get("PROXIWARE_HCAPTCHA_SITE_KEY") or "").strip()
    page_url = str(current_app.config.get("PROXIWARE_LOGIN_URL") or "https://app.proxiware.com/login").strip()
    captcha_key = get_provider_secret(db, "captcha_api_key")
    if browser_factory is None or captcha_factory is None:
        return _proxiware_action_error("Provider browser adapter is not configured.", 503, code="adapter_missing")
    if not site_key or not captcha_key:
        return _proxiware_action_error("Provider session prerequisites are not configured.", 503, code="not_configured")
    try:
        browser_adapter = browser_factory()
        captcha_adapter = captcha_factory(captcha_key)
        result = renew_provider_session(
            db,
            browser_adapter,
            captcha_adapter,
            site_key=site_key,
            page_url=page_url,
        )
    except Exception:  # noqa: BLE001 - renewal boundary must fail closed
        return _proxiware_action_error("Provider session renewal failed.", 502, code="manual_action_required")
    payload = {
        "state": str(result.state),
        "error_code": str(result.error_code or ""),
        "expires_at": result.expires_at,
    }
    status = 200 if result.state == "active" else 503
    return _proxiware_action_response(payload, status=status, message="Provider session renewed.")


@bp.post("/providers/proxiware/swaps/<int:job_id>/retry")
@admin_required
def proxiware_swap_retry(job_id: int):
    db = get_db()
    if not _provider_action_allowed(db, "swap"):
        return _proxiware_action_error("Swap action rate limit reached.", 429, code="rate_limited")
    try:
        retry_swap(db, job_id)
    except LookupError:
        return _proxiware_action_error("Swap job was not found.", 404, code="not_found")
    except ValueError:
        return _proxiware_action_error("Swap job cannot be retried from its current state.", 409, code="conflict")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="retry_swap",
        target_id=str(job_id),
        result="pending",
    )
    return _proxiware_action_response(
        {"status": "pending", "job_id": int(job_id)},
        message="Swap queued for retry.",
    )


@bp.post("/providers/proxiware/swaps/<int:job_id>/cancel")
@admin_required
def proxiware_swap_cancel(job_id: int):
    db = get_db()
    if not _provider_action_allowed(db, "swap"):
        return _proxiware_action_error("Swap action rate limit reached.", 429, code="rate_limited")
    try:
        cancel_swap(db, job_id)
    except LookupError:
        return _proxiware_action_error("Swap job is not active.", 409, code="conflict")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="cancel_swap",
        target_id=str(job_id),
        result="canceled",
    )
    return _proxiware_action_response(
        {"status": "canceled", "job_id": int(job_id)},
        message="Swap canceled.",
    )


@bp.post("/providers/proxiware/swaps/<int:job_id>/manual")
@admin_required
def proxiware_swap_manual(job_id: int):
    db = get_db()
    if not _provider_action_allowed(db, "swap"):
        return _proxiware_action_error("Swap action rate limit reached.", 429, code="rate_limited")
    adapter_factory = current_app.extensions.get("proxiware_swap_adapter_factory")
    if adapter_factory is None:
        return _proxiware_action_error(
            "Provider swap adapter is not configured.",
            503,
            code="adapter_missing",
        )
    try:
        request_manual_swap(db, job_id)
    except LookupError:
        return _proxiware_action_error("Swap job was not found.", 404, code="not_found")
    except ValueError:
        return _proxiware_action_error("Swap job cannot be requested from its current state.", 409, code="conflict")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action="manual_swap",
        target_id=str(job_id),
        result="pending",
    )
    runner = ProxiwareSwapRunner(
        app=current_app._get_current_object(),
        adapter_factory=adapter_factory,
        interval_seconds=5,
    )
    result = runner.run_job(job_id)
    state = str(result.get("status") or "error")
    if state == "success":
        record_provider_audit(
            db,
            actor_id=int(g.user["id"]),
            action="manual_swap",
            target_id=str(job_id),
            result="success",
        )
        return _proxiware_action_response(result, message="Manual swap completed.")
    if state == "reconciliation_required":
        return _proxiware_action_response(
            result,
            status=202,
            message="Provider swap confirmed; waiting for read-only reconciliation.",
        )
    if state in {"blocked", "paused"}:
        return _proxiware_action_error(
            "Manual swap did not run; resolve the provider action state first.",
            503,
            code=str(result.get("error_code") or "manual_action_required"),
        )
    if state in {"idle", "stopped"}:
        return _proxiware_action_error("Manual swap was not claimed.", 409, code="conflict")
    return _proxiware_action_error("Manual swap failed.", 502, code="provider_error")


@bp.post("/providers/proxiware/swap-worker/<state>")
@admin_required
def proxiware_swap_worker_state(state: str):
    value = str(state or "").strip().lower()
    if value not in {"pause", "resume"}:
        abort(404)
    db = get_db()
    paused = value == "pause"
    set_setting(db, "proxiware_swap_worker_paused", "1" if paused else "0")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action=f"{value}_swap_worker",
        result="paused" if paused else "running",
    )
    return _proxiware_action_response(
        {"status": "paused" if paused else "running"},
        message="Swap worker paused." if paused else "Swap worker resumed.",
    )


@bp.post("/providers/proxiware/automation/<state>")
@admin_required
def proxiware_automation_state(state: str):
    value = str(state or "").strip().lower()
    if value not in {"pause", "resume"}:
        abort(404)
    db = get_db()
    paused = value == "pause"
    set_setting(db, AUTOMATION_PAUSE_KEY, "1" if paused else "0")
    record_provider_audit(
        db,
        actor_id=int(g.user["id"]),
        action=f"{value}_automation",
        result="paused" if paused else "running",
    )
    return _proxiware_action_response(
        {"status": "paused" if paused else "running"},
        message="Proxiware automation paused." if paused else "Proxiware automation resumed.",
    )


@bp.get("/proxies")
@admin_required
def proxies():
    response = current_app.make_response(
        render_template(
            "admin_proxies.html",
            inventory=_admin_proxy_page(get_db(), request.args),
            admin_section="proxies",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/checker")
@admin_required
def checker():
    db = get_db()
    return render_template(
        "admin_dashboard.html",
        checker=checker_settings(db),
        api_include_allow=get_setting(db, "api_include_allow", "1") == "1",
        api_include_risk=get_setting(db, "api_include_risk", "1") == "1",
        admin_section="checker",
    )


@bp.get("/egress-duplicates")
@admin_required
def egress_duplicates():
    response = current_app.make_response(
        render_template(
            "admin_egress_duplicates.html",
            inventory=_egress_duplicate_page(get_db(), request.args),
            admin_section="egress_duplicates",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/egress-duplicates/<path:exit_ip>")
@admin_required
def egress_duplicate_members(exit_ip: str):
    response = current_app.make_response(
        render_template(
            "admin_egress_duplicates.html",
            member_inventory=_egress_duplicate_members_page(get_db(), exit_ip, request.args),
            admin_section="egress_duplicates",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/users")
@admin_required
def users():
    return render_template(
        "admin_dashboard.html",
        users=get_db().execute("SELECT * FROM users WHERE role='user' ORDER BY created_at DESC").fetchall(),
        admin_section="users",
    )


@bp.get("/payouts")
@admin_required
def payouts():
    return render_template(
        "admin_dashboard.html",
        payouts=get_db()
        .execute(
            """
            SELECT p.*, u.email FROM payouts p JOIN users u ON u.id=p.user_id
            ORDER BY p.created_at DESC LIMIT 100
            """
        )
        .fetchall(),
        now_iso=datetime.now(UTC).isoformat(),
        admin_section="payouts",
    )


@bp.get("/integrations")
@admin_required
def integrations():
    db = get_db()
    settings = checker_settings(db)
    primary_domain = str(current_app.config.get("EARN_PROXY_DOMAIN") or "proxy.acacondos.com").strip()
    legacy_domain = str(current_app.config.get("LEGACY_EARN_PROXY_DOMAIN") or "earn.proxy.acacondos.com").strip()
    return render_template(
        "admin_integrations.html",
        canonical_endpoint=f"https://{primary_domain}/api/v1/proxy-raw",
        raw_endpoint=f"https://{primary_domain}/api/v1/proxy-raw",
        transfer_endpoint=f"https://{primary_domain}/api/v1/proxy-transfer",
        legacy_endpoint=f"https://{legacy_domain}/api/v1/proxies",
        api_key_configured=bool(str(current_app.config.get("INTERNAL_API_KEY") or "")),
        api_include_allow=get_setting(db, "api_include_allow", "1") == "1",
        api_include_risk=get_setting(db, "api_include_risk", "1") == "1",
        health_stale_minutes=settings.health_stale_minutes,
        admin_section="integrations",
    )


@bp.get("/transfer-proxy")
@admin_required
def transfer_proxy():
    secret = str(current_app.config.get("RELAY_SSO_SECRET") or "")
    if not secret:
        response = current_app.make_response(
            (
                render_template(
                    "admin_transfer_proxy.html",
                    relay_url="",
                    relay_token="",
                    relay_configured=False,
                    admin_section="transfer_proxy",
                ),
                503,
            )
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    relay_public_url = str(current_app.config.get("RELAY_PUBLIC_URL") or "").strip().rstrip("/")
    relay_url = f"{relay_public_url}/sso" if relay_public_url else "/admin/transfer-proxy/sso"
    response = current_app.make_response(
        render_template(
            "admin_transfer_proxy.html",
            relay_url=relay_url,
            relay_token=create_relay_sso_token(secret),
            relay_configured=True,
            admin_section="transfer_proxy",
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _api_key_page(*, new_token: str | None = None, message: str | None = None, status: int = 200):
    response = render_template(
        "admin_api_keys.html",
        api_keys=list_api_keys(get_db()),
        new_token=new_token,
        new_token_message=message,
        admin_section="api_keys",
    )
    response = current_app.make_response((response, status))
    # A one-time token may be present in this response; never let a browser or
    # intermediary persist it in a cache or history-backed revalidation.
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/integrations/api-keys")
@admin_required
def api_keys_workspace():
    reveal_id = str(request.args.get("reveal") or "")
    pending = consume_api_key_reveal(get_db(), reveal_id) if reveal_id else None
    if pending is not None:
        return _api_key_page(new_token=pending[0], message=pending[1])
    return _api_key_page()


@bp.post("/integrations/api-keys")
@admin_required
def create_api_key_route():
    try:
        key_id, token = create_api_key(
            get_db(),
            request.form.get("name", ""),
            created_by_user_id=int(g.user["id"]),
        )
    except ValueError as exc:
        return form_error(str(exc), 400, "admin.api_keys_workspace", field="name", focus="api-key-name")
    if is_browser_form():
        reveal_id = create_api_key_reveal(get_db(), token, "Copy this token now. Secret material is never shown again.")
        response = redirect(url_for("admin.api_keys_workspace", reveal=reveal_id), code=303)
        response.headers["Cache-Control"] = "no-store"
        return response
    public_id = get_db().execute("SELECT public_id FROM api_keys WHERE id=?", (key_id,)).fetchone()["public_id"]
    response = jsonify({"id": public_id, "public_id": public_id, "token": token})
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/integrations/api-keys/<public_id>/revoke")
@admin_required
def revoke_api_key_route(public_id: str):
    row = get_api_key_by_public_id(get_db(), public_id)
    if row is None:
        return form_error("API key not found", 404, "admin.api_keys_workspace")
    try:
        revoke_api_key(get_db(), int(row["id"]))
    except LookupError as exc:
        return form_error(str(exc), 404, "admin.api_keys_workspace")
    return form_success(
        {"id": public_id, "public_id": public_id, "status": "revoked"},
        endpoint="admin.api_keys_workspace",
        message="API key revoked.",
    )


@bp.post("/integrations/api-keys/<public_id>/rotate")
@admin_required
def rotate_api_key_route(public_id: str):
    row = get_api_key_by_public_id(get_db(), public_id)
    if row is None:
        return form_error("API key not found", 404, "admin.api_keys_workspace")
    try:
        new_id, token = rotate_api_key(
            get_db(),
            int(row["id"]),
            created_by_user_id=int(g.user["id"]),
        )
    except LookupError as exc:
        return form_error(str(exc), 404, "admin.api_keys_workspace")
    if is_browser_form():
        reveal_id = create_api_key_reveal(
            get_db(), token, "Copy this rotated token now. The previous token has been revoked."
        )
        response = redirect(url_for("admin.api_keys_workspace", reveal=reveal_id), code=303)
        response.headers["Cache-Control"] = "no-store"
        return response
    new_public_id = get_db().execute("SELECT public_id FROM api_keys WHERE id=?", (new_id,)).fetchone()["public_id"]
    response = jsonify({"id": new_public_id, "public_id": new_public_id, "token": token, "status": "rotated"})
    response.status_code = 201
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.post("/settings")
@admin_required
def update_settings():
    try:
        interval = max(15, min(1440, int(request.form.get("health_interval_minutes", "60"))))
        concurrency = max(
            1,
            min(MAX_HEALTH_CONCURRENCY, int(request.form.get("health_concurrency", "5"))),
        )
        per_host = max(
            1,
            min(MAX_PER_HOST_CONCURRENCY, int(request.form.get("health_per_host_concurrency", "2"))),
        )
        retry_first = max(1, min(30, int(request.form.get("health_retry_first_minutes", "5"))))
        retry_second = max(
            retry_first + 1,
            min(60, int(request.form.get("health_retry_second_minutes", "15"))),
        )
        stale = max(60, min(1440, int(request.form.get("health_stale_minutes", "120"))))
    except ValueError:
        return form_error(
            "Checker settings must be numbers",
            400,
            "admin.checker",
            field="health_interval_minutes",
            focus="health_interval_minutes",
        )
    db = get_db()
    set_setting(db, "health_interval_minutes", str(interval))
    set_setting(db, "health_concurrency", str(concurrency))
    set_setting(db, "health_per_host_concurrency", str(per_host))
    set_setting(db, "health_retry_first_minutes", str(retry_first))
    set_setting(db, "health_retry_second_minutes", str(retry_second))
    set_setting(db, "health_stale_minutes", str(stale))
    set_setting(db, "api_include_allow", "1" if request.form.get("api_include_allow") else "0")
    set_setting(db, "api_include_risk", "1" if request.form.get("api_include_risk") else "0")
    return form_success(
        {"status": "saved"},
        endpoint="admin.checker",
        message="Checker policy saved.",
    )


def _change_user(
    user_id: int,
    *,
    status: str | None = None,
    earn_paused: int | None = None,
    message: str,
):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
    if row is None:
        return form_error("User not found", 404, "admin.users")
    new_status = status if status is not None else row["status"]
    new_paused = earn_paused if earn_paused is not None else row["earn_paused"]
    bump = 1 if new_status == "blocked" else 0
    db.execute(
        "UPDATE users SET status=?, earn_paused=?, session_version=session_version+? WHERE id=?",
        (new_status, new_paused, bump, user_id),
    )
    db.commit()
    return form_success(
        {"id": user_id, "status": new_status, "earn_paused": bool(new_paused)},
        endpoint="admin.users",
        message=message,
    )


@bp.post("/users/<int:user_id>/approve")
@admin_required
def approve_user(user_id: int):
    return _change_user(user_id, status="active", message="User approved.")


@bp.post("/users/<int:user_id>/pause-earn")
@admin_required
def pause_earn(user_id: int):
    return _change_user(user_id, earn_paused=1, message="Earnings paused for this user.")


@bp.post("/users/<int:user_id>/resume-earn")
@admin_required
def resume_earn(user_id: int):
    return _change_user(user_id, earn_paused=0, message="Earnings resumed for this user.")


@bp.post("/users/<int:user_id>/block")
@admin_required
def block_user(user_id: int):
    return _change_user(user_id, status="blocked", message="User blocked and sessions revoked.")


@bp.post("/users")
@admin_required
def create_admin_user():
    email = str(request.form.get("email") or "").strip().lower()
    password = str(request.form.get("password") or "")
    if "@" not in email or len(email) > MAX_EMAIL_LENGTH or len(password) < 8:
        return form_error(
            "A valid email and password of at least 8 characters are required",
            400,
            "admin.users",
            field="email" if "@" not in email or len(email) > MAX_EMAIL_LENGTH else "password",
            focus="new-user-email" if "@" not in email or len(email) > MAX_EMAIL_LENGTH else "new-user-password",
        )
    try:
        user_id = create_user(get_db(), email, password, status="active")
    except sqlite3.IntegrityError:
        return form_error(
            "Email is already registered",
            409,
            "admin.users",
            field="email",
            focus="new-user-email",
        )
    return form_success(
        {"id": user_id, "status": "active"},
        status=201,
        endpoint="admin.users",
        message="User created and activated.",
    )


@bp.post("/users/<int:user_id>/delete")
@admin_required
def delete_user(user_id: int):
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
    if row is None:
        return form_error("User not found", 404, "admin.users")
    db.execute(
        "UPDATE users SET status='deleted', session_version=session_version+1, earn_paused=1 WHERE id=?",
        (user_id,),
    )
    db.commit()
    return form_success(
        {"id": user_id, "status": "deleted"},
        endpoint="admin.users",
        message="User deleted. Historical records are retained.",
    )


@bp.post("/payouts/<int:payout_id>/approve")
@admin_required
def approve_payout_route(payout_id: int):
    try:
        approve_payout(get_db(), payout_id)
    except LookupError as exc:
        return form_error(str(exc), 400, "admin.payouts")
    return form_success(
        {"id": payout_id, "status": "approved"},
        endpoint="admin.payouts",
        message="Payout approved.",
    )


@bp.post("/payouts/<int:payout_id>/transaction")
@admin_required
def payout_transaction(payout_id: int):
    try:
        mark_payout_sent(get_db(), payout_id, request.form.get("tx_hash", ""))
    except (ValueError, LookupError) as exc:
        return form_error(
            str(exc),
            400,
            "admin.payouts",
            field="tx_hash",
            focus=f"tx-{payout_id}",
        )
    return form_success(
        {"id": payout_id, "status": "verifying"},
        endpoint="admin.payouts",
        message="Transaction submitted for automatic verification.",
    )


@bp.post("/payouts/<int:payout_id>/sent")
@admin_required
def payout_sent_compat(payout_id: int):
    """Keep the old endpoint working for existing admin tooling."""
    return payout_transaction(payout_id=payout_id)
