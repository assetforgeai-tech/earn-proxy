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
from app.services.relay_sso import create_relay_sso_token
from app.services.settings import get_setting, set_setting
from app.services.users import create_user

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
    if "@" not in email or len(password) < 8:
        return form_error(
            "A valid email and password of at least 8 characters are required",
            400,
            "admin.users",
            field="email" if "@" not in email else "password",
            focus="new-user-email" if "@" not in email else "new-user-password",
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
