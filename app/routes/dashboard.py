from __future__ import annotations

from flask import Blueprint, g, redirect, render_template, url_for

from app.auth import login_required
from app.db import get_db
from app.services.earnings import balances_for_user
from app.services.uptime import uptime_hours

bp = Blueprint("dashboard", __name__)


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
    proxy_views = [{"row": proxy, "uptime": uptime_hours(proxy)} for proxy in proxies]
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
    )
