from __future__ import annotations

from flask import Blueprint, flash, g, redirect, request, url_for

from app.auth import login_required
from app.db import get_db
from app.proxy_parser import ProxyParseError
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.proxies import (
    DuplicateCredential,
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
    try:
        proxy_id = add_proxy(get_db(), g.user["id"], request.form.get("raw_proxy", ""))
    except ProxyParseError as exc:
        return form_error(str(exc), 400, "dashboard.dashboard")
    except DuplicateCredential as exc:
        return form_error(str(exc), 409, "dashboard.dashboard")
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
        return form_error(str(exc), 400, "dashboard.dashboard")
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
