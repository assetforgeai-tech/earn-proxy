from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, g, redirect, render_template, request, url_for

from app.auth import login_required
from app.db import get_db
from app.services.checks import checker_settings
from app.services.earnings import balances_for_user
from app.services.uptime import uptime_hours

bp = Blueprint("dashboard", __name__)

INVENTORY_PAGE_SIZES = (10, 25, 50, 100)
INVENTORY_STATUSES = ("pending", "online", "offline", "blocked", "suspect")
INVENTORY_PROTOCOLS = ("http", "socks5", "unknown")
INVENTORY_ELIGIBILITIES = ("allow", "risk", "pending")
INVENTORY_SORT_COLUMNS = {
    "endpoint": ("LOWER(p.host)", "p.port", "p.id"),
    "status": ("p.status", "LOWER(p.host)", "p.port", "p.id"),
    "protocol": ("p.detected_protocol", "LOWER(p.host)", "p.port", "p.id"),
    "eligibility": ("p.eligibility", "LOWER(p.host)", "p.port", "p.id"),
    "online": ("COALESCE(p.accumulated_online_seconds, 0)", "p.id"),
    "offline": ("COALESCE(p.accumulated_offline_seconds, 0)", "p.id"),
    "created": ("p.created_at", "p.id"),
    "checked": ("COALESCE(p.last_checked_at, '')", "p.id"),
}


@dataclass(frozen=True)
class InventoryQuery:
    page: int
    per_page: int
    search: str
    status: str
    protocol: str
    eligibility: str
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


def _inventory_query(args) -> InventoryQuery:
    page = _bounded_int(args.get("page"), default=1, minimum=1, maximum=10_000_000)
    try:
        requested_size = int(str(args.get("per_page") or "25"))
    except (TypeError, ValueError):
        requested_size = 25
    per_page = requested_size if requested_size in INVENTORY_PAGE_SIZES else 25
    search = str(args.get("q") or "").strip()[:100]
    status = str(args.get("status") or "").strip().lower()
    protocol = str(args.get("protocol") or "").strip().lower()
    eligibility = str(args.get("eligibility") or "").strip().lower()
    sort = str(args.get("sort") or "created").strip().lower()
    direction = str(args.get("direction") or "desc").strip().lower()
    return InventoryQuery(
        page=page,
        per_page=per_page,
        search=search,
        status=status if status in INVENTORY_STATUSES else "",
        protocol=protocol if protocol in INVENTORY_PROTOCOLS else "",
        eligibility=eligibility if eligibility in INVENTORY_ELIGIBILITIES else "",
        sort=sort if sort in INVENTORY_SORT_COLUMNS else "created",
        direction=direction if direction in {"asc", "desc"} else "desc",
    )


def _like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped.lower()}%"


def _inventory_conditions(user_id: int, query: InventoryQuery) -> tuple[list[str], list[object]]:
    conditions = ["p.user_id=?", "p.archived_at IS NULL"]
    parameters: list[object] = [user_id]
    if query.search:
        conditions.append("(LOWER(p.host) LIKE ? ESCAPE '\\' OR CAST(p.port AS TEXT) LIKE ? ESCAPE '\\')")
        pattern = _like_pattern(query.search)
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
    return conditions, parameters


def _inventory_url_args(query: InventoryQuery, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "q": query.search,
        "status": query.status,
        "protocol": query.protocol,
        "eligibility": query.eligibility,
        "sort": query.sort,
        "direction": query.direction,
        "per_page": query.per_page,
        "page": query.page,
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value not in ("", None)}


def _inventory_page(db, user_id: int, query: InventoryQuery) -> dict[str, object]:
    base_conditions = ["p.user_id=?", "p.archived_at IS NULL"]
    base_parameters: list[object] = [user_id]
    filtered_conditions, filtered_parameters = _inventory_conditions(user_id, query)

    total_row = db.execute(
        "SELECT COUNT(*) AS count FROM proxies p WHERE " + " AND ".join(base_conditions),
        base_parameters,
    ).fetchone()
    filtered_row = db.execute(
        "SELECT COUNT(*) AS count FROM proxies p WHERE " + " AND ".join(filtered_conditions),
        filtered_parameters,
    ).fetchone()

    def grouped_count(column: str) -> dict[str, int]:
        rows = db.execute(
            f"SELECT COALESCE(NULLIF(p.{column},''),'unknown') AS value, COUNT(*) AS count "
            "FROM proxies p WHERE " + " AND ".join(base_conditions) + f" GROUP BY p.{column}",
            base_parameters,
        ).fetchall()
        counts: dict[str, int] = {}
        for row in rows:
            value = str(row["value"])
            if column == "detected_protocol" and value not in {"http", "socks5"}:
                value = "unknown"
            counts[value] = counts.get(value, 0) + int(row["count"])
        return counts

    total_count = int(total_row["count"])
    filtered_count = int(filtered_row["count"])
    total_pages = max(1, math.ceil(filtered_count / query.per_page))
    effective_page = min(query.page, total_pages)
    if effective_page != query.page:
        query = InventoryQuery(
            page=effective_page,
            per_page=query.per_page,
            search=query.search,
            status=query.status,
            protocol=query.protocol,
            eligibility=query.eligibility,
            sort=query.sort,
            direction=query.direction,
        )
        filtered_conditions, filtered_parameters = _inventory_conditions(user_id, query)

    order_direction = "ASC" if query.direction == "asc" else "DESC"
    order = ", ".join(f"{column} {order_direction}" for column in INVENTORY_SORT_COLUMNS[query.sort])
    rows = db.execute(
        "SELECT p.* FROM proxies p WHERE " + " AND ".join(filtered_conditions) + f" ORDER BY {order} LIMIT ? OFFSET ?",
        [*filtered_parameters, query.per_page, query.offset],
    ).fetchall()

    page_links: list[dict[str, object]] = []
    visible_pages = {1, total_pages, query.page, query.page - 1, query.page + 1}
    last_added = 0
    for page_number in sorted(number for number in visible_pages if 1 <= number <= total_pages):
        if last_added and page_number > last_added + 1:
            page_links.append({"ellipsis": True})
        page_links.append(
            {
                "number": page_number,
                "current": page_number == query.page,
                "url": url_for("dashboard.proxies", **_inventory_url_args(query, page=page_number)),
            }
        )
        last_added = page_number

    def filter_url(**overrides: object) -> str:
        return url_for("dashboard.proxies", **_inventory_url_args(query, page=1, **overrides))

    sort_urls = {}
    for key in INVENTORY_SORT_COLUMNS:
        next_direction = "desc" if query.sort == key and query.direction == "asc" else "asc"
        sort_urls[key] = url_for(
            "dashboard.proxies",
            **_inventory_url_args(query, page=1, sort=key, direction=next_direction),
        )

    start_index = (query.offset + 1) if filtered_count else 0
    end_index = min(query.offset + len(rows), filtered_count)
    return {
        "query": query,
        "rows": rows,
        "total_count": total_count,
        "filtered_count": filtered_count,
        "total_pages": total_pages,
        "start_index": start_index,
        "end_index": end_index,
        "status_counts": grouped_count("status"),
        "protocol_counts": grouped_count("detected_protocol"),
        "eligibility_counts": grouped_count("eligibility"),
        "filter_url": filter_url,
        "sort_urls": sort_urls,
        "page_links": page_links,
        "previous_url": url_for("dashboard.proxies", **_inventory_url_args(query, page=max(1, query.page - 1))),
        "next_url": url_for("dashboard.proxies", **_inventory_url_args(query, page=min(total_pages, query.page + 1))),
        "reset_url": url_for("dashboard.proxies"),
    }


def _timestamp_view(value: str | None, *, empty_label: str) -> dict[str, str]:
    if not value:
        return {"iso": "", "label": empty_label}
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return {
        "iso": parsed.isoformat(),
        "label": parsed.strftime("%b %d, %Y %H:%M UTC"),
    }


def _freshness_view(proxy, *, now: datetime, stale_minutes: int) -> dict[str, object]:
    last_checked = datetime.fromisoformat(proxy["last_checked_at"]) if proxy["last_checked_at"] else None
    if last_checked and last_checked.tzinfo is None:
        last_checked = last_checked.replace(tzinfo=UTC)
    last_success = datetime.fromisoformat(proxy["last_success_at"]) if proxy["last_success_at"] else None
    if last_success and last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=UTC)
    next_check = datetime.fromisoformat(proxy["next_check_at"]) if proxy["next_check_at"] else None
    if next_check and next_check.tzinfo is None:
        next_check = next_check.replace(tzinfo=UTC)
    stale = last_success is None or last_success < now - timedelta(minutes=stale_minutes)
    overdue = next_check is not None and next_check < now
    if last_checked is None and last_success is None:
        label = "Awaiting first check"
    elif stale:
        label = "Stale result"
    elif overdue:
        label = "Check due"
    else:
        label = "Fresh"
    return {
        "state": "stale" if stale or overdue else "fresh",
        "label": label,
        "last": _timestamp_view(proxy["last_checked_at"], empty_label="Never"),
        "next": _timestamp_view(proxy["next_check_at"], empty_label="Pending schedule"),
    }


@bp.get("/")
def index():
    if g.user is None:
        return redirect(url_for("auth.login"))
    if g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    return redirect(url_for("dashboard.dashboard"))


@bp.get("/dashboard")
@login_required
def dashboard():
    return _render_dashboard("overview")


@bp.get("/dashboard/proxies")
@login_required
def proxies():
    return _render_dashboard("proxies")


@bp.get("/dashboard/earnings")
@login_required
def earnings():
    return _render_dashboard("earnings")


@bp.get("/dashboard/wallet")
@login_required
def wallet():
    return _render_dashboard("wallet")


def _render_dashboard(section: str):
    db = get_db()
    if g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    if section == "proxies":
        inventory = _inventory_page(db, int(g.user["id"]), _inventory_query(request.args))
    else:
        total = db.execute(
            "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
            (g.user["id"],),
        ).fetchone()["count"]
        inventory = {"total_count": int(total)}
    proxies = inventory.get("rows", [])
    settings = checker_settings(db)
    now = datetime.now(UTC)
    proxy_views = [
        {
            "row": proxy,
            "uptime": uptime_hours(proxy, now=now),
            "freshness": _freshness_view(
                proxy,
                now=now,
                stale_minutes=settings.health_stale_minutes,
            ),
        }
        for proxy in proxies
    ]
    wallet = db.execute("SELECT * FROM wallets WHERE user_id=?", (g.user["id"],)).fetchone()
    payouts = db.execute(
        "SELECT * FROM payouts WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (g.user["id"],),
    ).fetchall()
    wallet_masked = f"{wallet['address'][:6]}…{wallet['address'][-4:]}" if wallet else ""
    return render_template(
        "user_dashboard.html",
        proxies=proxies,
        proxy_views=proxy_views,
        balances=balances_for_user(db, g.user["id"]),
        wallet=wallet,
        wallet_masked=wallet_masked,
        payouts=payouts,
        inventory=inventory,
        health_interval_minutes=settings.health_interval_minutes,
        whitelist_host=current_app.config.get("WHITELIST_HOST", "whitelist.proxy.acacondos.com"),
        whitelist_ip=current_app.config.get("WHITELIST_IP", ""),
        dashboard_section=section,
    )
