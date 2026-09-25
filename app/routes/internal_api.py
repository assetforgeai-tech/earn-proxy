from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import requests
from flask import Blueprint, Response, current_app, jsonify, request

from app.crypto import decrypt_secret
from app.db import get_db
from app.proxy_parser import ParsedProxy
from app.services.api_keys import authenticate_api_key
from app.services.checks import checker_settings
from app.services.proxies import reveal_proxy
from app.services.proxiware_qualification import _ip as normalize_exit_ip
from app.services.settings import get_setting

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")
api_bp = Blueprint("api", __name__, url_prefix="/api/v1")
MAX_TRANSFER_FEED_BYTES = 5_000_000


def _api_key_required() -> bool:
    supplied = str(request.headers.get("X-API-Key") or "")
    return authenticate_api_key(get_db(), supplied) is not None


def _raw_rows():
    db = get_db()
    enabled = []
    if get_setting(db, "api_include_allow", "1") == "1":
        enabled.append("allow")
    if get_setting(db, "api_include_risk", "1") == "1":
        enabled.append("risk")
    if not enabled:
        return []
    placeholders = ",".join("?" for _ in enabled)
    stale_cutoff = (datetime.now(UTC) - timedelta(minutes=checker_settings(db).health_stale_minutes)).isoformat()
    rows = db.execute(
        f"""
        SELECT p.* FROM proxies p JOIN users u ON u.id=p.user_id
        WHERE p.archived_at IS NULL AND p.status='online' AND p.duplicate_of IS NULL
          AND p.eligibility IN ({placeholders}) AND u.status='active'
          AND p.exit_ip IS NOT NULL AND trim(p.exit_ip) <> ''
          AND p.egress_attestation_source IN ('https_quorum','earnapp_tls')
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
    if get_setting(db, "proxiware_distribution_enabled", "0") == "1":
        provider_columns = {
            str(row["name"]) for row in db.execute('PRAGMA table_info("provider_assignments")').fetchall()
        }
        required = {
            "distribution_enabled",
            "duplicate_egress",
            "egress_verified_at",
            "protocol",
        }
        if required.issubset(provider_columns):
            provider_rows = db.execute(
                """
                SELECT * FROM provider_assignments
                WHERE provider='proxiware' AND missing_at IS NULL
                  AND status IN ('active','current') AND live_status='live'
                  AND qualification='allow' AND provider_eligible=1
                  AND distribution_enabled=1 AND duplicate_egress=0
                  AND exit_ip IS NOT NULL AND trim(exit_ip)<>''
                  AND egress_verified_at IS NOT NULL AND last_checked_at>=?
                  AND (replacement_ready_at IS NULL OR replacement_ready_at<=?)
                  AND NOT EXISTS (
                      SELECT 1 FROM swap_jobs sj
                      WHERE sj.provider='proxiware' AND sj.subscription_id=provider_assignments.subscription_id
                        AND sj.state IN ('pending','running')
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM proxies p
                      WHERE p.archived_at IS NULL AND p.exit_ip=provider_assignments.exit_ip
                        AND p.duplicate_of IS NULL
                        AND p.egress_attestation_source IN ('https_quorum','earnapp_tls')
                  )
                  AND id = COALESCE(
                      (SELECT MIN(pa2.id) FROM provider_assignments pa2
                       WHERE pa2.provider='proxiware' AND pa2.missing_at IS NULL
                         AND pa2.exit_ip=provider_assignments.exit_ip
                         AND pa2.live_status='live' AND pa2.egress_verified_at IS NOT NULL), id
                  )
                ORDER BY id
                """,
                (stale_cutoff, datetime.now(UTC).isoformat()),
            ).fetchall()
            for row in provider_rows:
                if not normalize_exit_ip(row["exit_ip"]):
                    continue
                try:
                    parsed = ParsedProxy(
                        str(row["protocol"] or "auto"),
                        str(row["host"]),
                        int(row["port"]),
                        decrypt_secret(str(row["username_encrypted"] or "")) if row["username_encrypted"] else "",
                        decrypt_secret(str(row["password_encrypted"] or "")) if row["password_encrypted"] else "",
                    )
                    distributable.append((row, parsed))
                except (TypeError, ValueError):
                    current_app.logger.error(
                        "Skipping provider assignment %s because its credential cannot be decrypted",
                        row["id"],
                    )
    return distributable


def _raw_response(*, include_type: bool = False):
    distributable = _raw_rows()
    if request.args.get("format", "").lower() == "json":
        payload = []
        for row, parsed in distributable:
            row_keys = set(row.keys())
            qualification = str(row["qualification"] if "qualification" in row_keys else row["eligibility"])
            protocol = str(row["protocol"] if "protocol" in row_keys else row["detected_protocol"])
            item = {
                "raw": parsed.raw,
                "status": qualification.capitalize(),
                "protocol": protocol,
                "endpoint": f"{row['host']}:{row['port']}",
            }
            if include_type:
                item["type"] = "raw"
            payload.append(item)
        return jsonify(payload)
    body = "\n".join(parsed.raw for _row, parsed in distributable)
    return Response(body + ("\n" if body else ""), mimetype="text/plain")


def _transfer_feed_target() -> tuple[str, str]:
    target = str(current_app.config.get("RELAY_FEED_URL") or "").strip()
    key = str(current_app.config.get("RELAY_FEED_KEY") or "").strip()
    parsed = urlparse(target)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Transfer feed must be a loopback HTTP endpoint")
    if parsed.query or parsed.fragment:
        raise ValueError("Transfer feed URL must not contain query or fragment")
    return target, key


def _transfer_rows():
    target, key = _transfer_feed_target()
    if not key:
        raise RuntimeError("Transfer feed is not configured")
    response = requests.get(
        target,
        headers={"X-Relay-Feed-Key": key, "Accept": "application/json"},
        timeout=(2, 5),
    )
    response.raise_for_status()
    if len(response.content) > MAX_TRANSFER_FEED_BYTES:
        raise RuntimeError("Transfer feed response is too large")
    payload = response.json()
    rows = payload.get("items", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise RuntimeError("Transfer feed returned an invalid payload")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        proxy = str(row.get("proxy") or row.get("raw") or "").strip()
        if not proxy or len(proxy) > 4096:
            continue
        result.append(
            {
                "proxy": proxy,
                "protocol": str(row.get("protocol") or "unknown"),
                "exit_ip": str(row.get("exit_ip") or ""),
            }
        )
    return result


def _transfer_response():
    try:
        rows = _transfer_rows()
    except (requests.RequestException, ValueError, RuntimeError, TimeoutError) as exc:
        current_app.logger.warning("Transfer feed unavailable: %s", exc)
        return jsonify(error="Transfer feed is temporarily unavailable"), 503
    if request.args.get("format", "").lower() == "json":
        return jsonify([{**row, "type": "transfer"} for row in rows])
    body = "\n".join(row["proxy"] for row in rows)
    return Response(body + ("\n" if body else ""), mimetype="text/plain")


@bp.get("/proxies")
@api_bp.get("/proxies")
def list_proxies():
    if not _api_key_required():
        return Response("Unauthorized\n", status=401, mimetype="text/plain")
    return _raw_response()


@api_bp.get("/proxy-raw")
@bp.get("/proxy-raw")
def list_raw_proxies():
    if not _api_key_required():
        return Response("Unauthorized\n", status=401, mimetype="text/plain")
    return _raw_response(include_type=True)


@api_bp.get("/proxy-transfer")
@bp.get("/proxy-transfer")
def list_transfer_proxies():
    if not _api_key_required():
        return Response("Unauthorized\n", status=401, mimetype="text/plain")
    return _transfer_response()


@bp.after_request
@api_bp.after_request
def prevent_credential_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response
