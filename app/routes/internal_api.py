from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta

from flask import Blueprint, Response, current_app, jsonify, request

from app.db import get_db
from app.services.checks import checker_settings
from app.services.proxies import reveal_proxy
from app.services.settings import get_setting

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")
api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/proxies")
@api_bp.get("/proxies")
def list_proxies():
    supplied = str(request.headers.get("X-API-Key") or "")
    expected = str(current_app.config.get("INTERNAL_API_KEY") or "")
    if not expected or not hmac.compare_digest(supplied, expected):
        return Response("Unauthorized\n", status=401, mimetype="text/plain")
    db = get_db()
    enabled = []
    if get_setting(db, "api_include_allow", "1") == "1":
        enabled.append("allow")
    if get_setting(db, "api_include_risk", "1") == "1":
        enabled.append("risk")
    if not enabled:
        return Response("", mimetype="text/plain")
    placeholders = ",".join("?" for _ in enabled)
    stale_cutoff = (datetime.now(UTC) - timedelta(minutes=checker_settings(db).health_stale_minutes)).isoformat()
    rows = db.execute(
        f"""
        SELECT p.* FROM proxies p JOIN users u ON u.id=p.user_id
        WHERE p.archived_at IS NULL AND p.status='online' AND p.duplicate_of IS NULL
          AND p.eligibility IN ({placeholders}) AND u.status='active'
          AND p.last_success_at IS NOT NULL AND p.last_success_at >= ?
        ORDER BY p.id
        """,
        [*enabled, stale_cutoff],
    ).fetchall()
    distributable = []
    for row in rows:
        try:
            distributable.append((row, reveal_proxy(row)))
        except ValueError:
            current_app.logger.error("Skipping proxy %s because its credential cannot be decrypted", row["id"])
    if request.args.get("format", "").lower() == "json":
        return jsonify(
            [
                {
                    "raw": parsed.raw,
                    "status": str(row["eligibility"]).capitalize(),
                    "protocol": row["detected_protocol"],
                    "endpoint": f"{row['host']}:{row['port']}",
                }
                for row, parsed in distributable
            ]
        )
    body = "\n".join(parsed.raw for _row, parsed in distributable)
    return Response(body + ("\n" if body else ""), mimetype="text/plain")


@bp.after_request
@api_bp.after_request
def prevent_credential_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response
