from __future__ import annotations

import sqlite3

from flask import Blueprint, render_template, request

from app.auth import admin_required
from app.db import get_db
from app.routes.forms import form_error, form_success
from app.services.checks import (
    MAX_HEALTH_CONCURRENCY,
    checker_settings,
    operational_stats,
)
from app.services.payouts import approve_payout, mark_payout_sent
from app.services.settings import get_setting, set_setting
from app.services.users import create_user

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.get("")
@admin_required
def dashboard():
    db = get_db()
    settings = checker_settings(db)
    return render_template(
        "admin_dashboard.html",
        users=db.execute("SELECT * FROM users WHERE role='user' ORDER BY created_at DESC").fetchall(),
        proxies=db.execute("SELECT * FROM proxies ORDER BY created_at DESC LIMIT 100").fetchall(),
        payouts=db.execute(
            """
            SELECT p.*, u.email FROM payouts p JOIN users u ON u.id=p.user_id
            ORDER BY p.created_at DESC LIMIT 100
            """
        ).fetchall(),
        checker=settings,
        stats=operational_stats(db),
        api_include_allow=get_setting(db, "api_include_allow", "1") == "1",
        api_include_risk=get_setting(db, "api_include_risk", "1") == "1",
    )


@bp.post("/settings")
@admin_required
def update_settings():
    try:
        interval = max(15, min(1440, int(request.form.get("health_interval_minutes", "60"))))
        concurrency = max(
            1,
            min(MAX_HEALTH_CONCURRENCY, int(request.form.get("health_concurrency", "5"))),
        )
    except ValueError:
        return form_error("Checker settings must be numbers", 400, "admin.dashboard")
    db = get_db()
    set_setting(db, "health_interval_minutes", str(interval))
    set_setting(db, "health_concurrency", str(concurrency))
    set_setting(db, "api_include_allow", "1" if request.form.get("api_include_allow") else "0")
    set_setting(db, "api_include_risk", "1" if request.form.get("api_include_risk") else "0")
    return form_success(
        {"status": "saved"},
        endpoint="admin.dashboard",
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
        return form_error("User not found", 404, "admin.dashboard")
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
        endpoint="admin.dashboard",
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
            "admin.dashboard",
        )
    try:
        user_id = create_user(get_db(), email, password, status="active")
    except sqlite3.IntegrityError:
        return form_error("Email is already registered", 409, "admin.dashboard")
    return form_success(
        {"id": user_id, "status": "active"},
        status=201,
        endpoint="admin.dashboard",
        message="User created and activated.",
    )


@bp.post("/users/<int:user_id>/delete")
@admin_required
def delete_user(user_id: int):
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
    if row is None:
        return form_error("User not found", 404, "admin.dashboard")
    db.execute(
        "UPDATE users SET status='deleted', session_version=session_version+1, earn_paused=1 WHERE id=?",
        (user_id,),
    )
    db.commit()
    return form_success(
        {"id": user_id, "status": "deleted"},
        endpoint="admin.dashboard",
        message="User deleted. Historical records are retained.",
    )


@bp.post("/payouts/<int:payout_id>/approve")
@admin_required
def approve_payout_route(payout_id: int):
    try:
        approve_payout(get_db(), payout_id)
    except LookupError as exc:
        return form_error(str(exc), 400, "admin.dashboard")
    return form_success(
        {"id": payout_id, "status": "approved"},
        endpoint="admin.dashboard",
        message="Payout approved.",
    )


@bp.post("/payouts/<int:payout_id>/sent")
@admin_required
def payout_sent(payout_id: int):
    try:
        mark_payout_sent(get_db(), payout_id, request.form.get("tx_hash", ""))
    except (ValueError, LookupError) as exc:
        return form_error(str(exc), 400, "admin.dashboard")
    return form_success(
        {"id": payout_id, "status": "sent"},
        endpoint="admin.dashboard",
        message="Payout marked as sent.",
    )
