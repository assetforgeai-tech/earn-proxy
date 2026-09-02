from __future__ import annotations

from flask import Blueprint, current_app, flash, g, redirect, request, url_for

from app.auth import login_required
from app.db import get_db
from app.proxy_parser import ProxyParseError
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.proxies import (
    DuplicateCredential,
    ProxyQuotaExceeded,
    add_proxy,
    archive_proxy,
    replace_proxy,
)

bp = Blueprint("proxies", __name__, url_prefix="/proxies")


@bp.post("")
@login_required
def create_proxy():
    if g.user["role"] != "user":
        return form_error("Only user accounts can add proxies", 403, "dashboard.dashboard")
    db = get_db()
    try:
        quota = max(1, min(10_000, int(current_app.config.get("MAX_ACTIVE_PROXIES_PER_USER", 100))))
    except (TypeError, ValueError):
        quota = 100
    # Fast rejection keeps malformed input out of the service when the quota
    # is already exhausted; add_proxy repeats this check under a write lock.
    active_count = int(
        db.execute(
            "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
            (g.user["id"],),
        ).fetchone()["count"]
    )
    if active_count >= quota:
        return form_error(
            f"This account has reached the maximum number of active proxies ({quota})",
            429,
            "dashboard.dashboard",
            field="raw_proxy",
            focus="raw_proxy",
        )
    try:
        proxy_id = add_proxy(
            db,
            g.user["id"],
            request.form.get("raw_proxy", ""),
            max_active_proxies=quota,
        )
    except ProxyParseError as exc:
        return form_error(str(exc), 400, "dashboard.dashboard", field="raw_proxy", focus="raw_proxy")
    except DuplicateCredential as exc:
        return form_error(str(exc), 409, "dashboard.dashboard", field="raw_proxy", focus="raw_proxy")
    except ProxyQuotaExceeded as exc:
        return form_error(str(exc), 429, "dashboard.dashboard", field="raw_proxy", focus="raw_proxy")
    return form_success(
        {"id": proxy_id, "status": "pending"},
        status=201,
        endpoint="dashboard.dashboard",
        message="Proxy added and queued for checking.",
    )


@bp.post("/<int:proxy_id>/replace")
@login_required
def replace(proxy_id: int):
    try:
        replace_proxy(get_db(), proxy_id, g.user["id"], request.form.get("raw_proxy", ""))
    except (ProxyParseError, DuplicateCredential) as exc:
        return form_error(
            str(exc),
            400,
            "dashboard.dashboard",
            field="raw_proxy",
            focus=f"replace-{proxy_id}",
        )
    except LookupError as exc:
        return form_error(str(exc), 404, "dashboard.dashboard")
    return form_success(
        {"id": proxy_id, "status": "pending"},
        endpoint="dashboard.dashboard",
        message="Proxy replaced and queued for checking.",
    )


@bp.post("/<int:proxy_id>/delete")
@login_required
def delete(proxy_id: int):
    try:
        archive_proxy(get_db(), proxy_id, g.user["id"])
    except LookupError as exc:
        return form_error(str(exc), 404, "dashboard.dashboard")
    if is_browser_form():
        flash("Proxy removed. Historical earnings are retained.", "success")
        return redirect(url_for("dashboard.dashboard"), code=303)
    return "", 204
