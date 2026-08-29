from __future__ import annotations

import hmac

from flask import Blueprint, Response, current_app, jsonify, request

from app.db import get_db
from app.services.proxies import reveal_proxy
from app.services.settings import get_setting

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")


@bp.get("/proxies")
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
    rows = db.execute(
        f"""
        SELECT p.* FROM proxies p JOIN users u ON u.id=p.user_id
        WHERE p.archived_at IS NULL AND p.status='online' AND p.duplicate_of IS NULL
          AND p.eligibility IN ({placeholders}) AND u.status='active'
        ORDER BY p.id
        """,
        enabled,
    ).fetchall()
    if request.args.get("format", "").lower() == "json":
        return jsonify(
            [
                {
                    "raw": reveal_proxy(row).raw,
                    "status": str(row["eligibility"]).capitalize(),
                    "protocol": row["detected_protocol"],
                    "endpoint": f"{row['host']}:{row['port']}",
                }
                for row in rows
            ]
        )
    body = "\n".join(reveal_proxy(row).raw for row in rows)
    return Response(body + ("\n" if body else ""), mimetype="text/plain")
