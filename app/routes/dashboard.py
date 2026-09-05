from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, g, redirect, render_template, url_for

from app.auth import login_required
from app.db import get_db
from app.services.checks import checker_settings
from app.services.earnings import balances_for_user
from app.services.uptime import uptime_hours

bp = Blueprint("dashboard", __name__)


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
    db = get_db()
    if g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    proxies = db.execute(
        "SELECT * FROM proxies WHERE user_id=? AND archived_at IS NULL ORDER BY created_at DESC",
        (g.user["id"],),
    ).fetchall()
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
        health_interval_minutes=settings.health_interval_minutes,
        whitelist_host=current_app.config.get("WHITELIST_HOST", "whitelist.proxy.acacondos.com"),
        whitelist_ip=current_app.config.get("WHITELIST_IP", ""),
    )
