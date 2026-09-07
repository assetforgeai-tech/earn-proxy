from __future__ import annotations

import ipaddress
import math
import sqlite3
from datetime import UTC, datetime

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
