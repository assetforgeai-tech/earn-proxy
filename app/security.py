from __future__ import annotations

import hmac
import secrets

from flask import current_app, jsonify, request, session

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return str(token)


def protect_csrf():
    if not current_app.config.get("CSRF_ENABLED", True) or request.method in SAFE_METHODS:
        return None
    supplied = str(request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "")
    expected = str(session.get("csrf_token") or "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        return jsonify(error="Invalid CSRF token"), 400
    return None


def init_app(app) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.before_request(protect_csrf)
