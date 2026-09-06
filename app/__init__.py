from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime

from cryptography.fernet import Fernet
from flask import Flask, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from app import auth, db, security


def _is_secret_placeholder(value: object) -> bool:
    text = str(value or "").strip().lower()
    return (
        not text
        or text
        in {
            "dev-change-me",
            "replace-with-a-long-random-session-secret",
            "replace-with-a-valid-fernet-key",
            "replace-with-a-long-random-api-key",
            "replace-with-a-strong-admin-password",
        }
        or text.startswith("replace-with-")
    )


def _valid_fernet_key(value: object) -> bool:
    if _is_secret_placeholder(value):
        return False
    try:
        Fernet(str(value).encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return False
    return True


def create_app(test_config: dict | None = None) -> Flask:
    instance_path = os.environ.get("EARN_PROXY_INSTANCE_PATH")
    flask_kwargs = {"instance_relative_config": True}
    if instance_path:
        flask_kwargs["instance_path"] = instance_path
    app = Flask(__name__, **flask_kwargs)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("EARN_PROXY_SECRET_KEY", "dev-change-me"),
        DATABASE=os.environ.get(
            "EARN_PROXY_DATABASE",
            os.path.join(app.instance_path, "earn-proxy.db"),
        ),
        EARN_PROXY_DOMAIN=os.environ.get("EARN_PROXY_DOMAIN", "proxy.acacondos.com"),
        LEGACY_EARN_PROXY_DOMAIN=os.environ.get("EARN_PROXY_LEGACY_DOMAIN", "earn.proxy.acacondos.com"),
        WHITELIST_HOST=os.environ.get("EARN_PROXY_WHITELIST_HOST", "whitelist.proxy.acacondos.com"),
        WHITELIST_IP=os.environ.get("EARN_PROXY_WHITELIST_IP", "42.96.12.142"),
        RELAY_FEED_URL=os.environ.get("EARN_PROXY_RELAY_FEED_URL", "http://127.0.0.1:8000/internal/feed"),
        RELAY_FEED_KEY=os.environ.get("EARN_PROXY_RELAY_FEED_KEY", ""),
        RELAY_SSO_SECRET=os.environ.get("EARN_PROXY_RELAY_SSO_SECRET", ""),
        RELAY_PUBLIC_URL=os.environ.get("EARN_PROXY_RELAY_PUBLIC_URL", "https://transfer.proxy.acacondos.com"),
        FERNET_KEY=os.environ.get("EARN_PROXY_FERNET_KEY", ""),
        INTERNAL_API_KEY=os.environ.get("EARN_PROXY_INTERNAL_API_KEY", ""),
        ADMIN_EMAIL=os.environ.get("EARN_PROXY_ADMIN_EMAIL", "admin@example.com"),
        ADMIN_PASSWORD=os.environ.get("EARN_PROXY_ADMIN_PASSWORD", ""),
        BSC_RPC_URL=os.environ.get("EARN_PROXY_BSC_RPC_URL", ""),
        BSC_USDT_CONTRACT=os.environ.get(
            "EARN_PROXY_BSC_USDT_CONTRACT",
            "0x55d398326f99059ff775485246999027b3197955",
        ),
        BSC_USDT_DECIMALS=int(os.environ.get("EARN_PROXY_BSC_USDT_DECIMALS", "18")),
        BSC_MIN_CONFIRMATIONS=int(os.environ.get("EARN_PROXY_BSC_MIN_CONFIRMATIONS", "12")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("EARN_PROXY_COOKIE_SECURE", "1") == "1",
        CSRF_ENABLED=True,
        REGISTRATION_MAX_ATTEMPTS=int(os.environ.get("EARN_PROXY_REGISTRATION_MAX_ATTEMPTS", "5")),
        REGISTRATION_RATE_WINDOW_SECONDS=int(os.environ.get("EARN_PROXY_REGISTRATION_RATE_WINDOW_SECONDS", "900")),
        REGISTRATION_GLOBAL_MAX_ATTEMPTS=int(os.environ.get("EARN_PROXY_REGISTRATION_GLOBAL_MAX_ATTEMPTS", "100")),
        LOGIN_IP_MAX_ATTEMPTS=int(os.environ.get("EARN_PROXY_LOGIN_IP_MAX_ATTEMPTS", "30")),
        LOGIN_GLOBAL_MAX_ATTEMPTS=int(os.environ.get("EARN_PROXY_LOGIN_GLOBAL_MAX_ATTEMPTS", "1000")),
        LOGIN_RATE_WINDOW_SECONDS=int(os.environ.get("EARN_PROXY_LOGIN_RATE_WINDOW_SECONDS", "900")),
        MAX_ACTIVE_PROXIES_PER_USER=int(os.environ.get("EARN_PROXY_MAX_ACTIVE_PROXIES_PER_USER", "100")),
        MAX_OUTSTANDING_PAYOUTS_PER_USER=int(os.environ.get("EARN_PROXY_MAX_OUTSTANDING_PAYOUTS_PER_USER", "10")),
        MAX_CONTENT_LENGTH=1024 * 1024,
        MAX_FORM_MEMORY_SIZE=1024 * 1024,
        MAX_FORM_PARTS=64,
        MAX_PROXY_IMPORT_BYTES=int(os.environ.get("EARN_PROXY_MAX_IMPORT_BYTES", str(512 * 1024))),
        MAX_PROXY_IMPORT_LINES=int(os.environ.get("EARN_PROXY_MAX_IMPORT_LINES", "5000")),
    )
    if test_config:
        app.config.update(test_config)

    @app.template_filter("timestamp_label")
    def timestamp_label(value):
        if not value:
            return "Never"
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError:
            return str(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).strftime("%b %d, %Y %H:%M UTC")

    if not app.testing:
        unsafe = (
            _is_secret_placeholder(app.secret_key)
            or not _valid_fernet_key(app.config.get("FERNET_KEY"))
            or _is_secret_placeholder(app.config.get("INTERNAL_API_KEY"))
            or _is_secret_placeholder(app.config.get("ADMIN_PASSWORD"))
        )
        if unsafe:
            raise RuntimeError("Production secrets are missing or still use development placeholders")

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    security.init_app(app)
    app.before_request(auth.load_logged_in_user)
    # Caddy terminates TLS and supplies the client address/scheme headers.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    @app.context_processor
    def inject_shell_context():
        endpoint = str(request.endpoint or "")
        route_shell = {
            "admin.dashboard": ("overview", "Overview"),
            "admin.checker": ("checker", "Health checker"),
            "admin.users": ("users", "Users"),
            "admin.payouts": ("payouts", "Payouts"),
            "admin.integrations": ("integrations", "Distribution API"),
            "admin.api_keys_workspace": ("api_keys", "API keys"),
            "admin.transfer_proxy": ("transfer_proxy", "Transfer Proxy"),
            "dashboard.dashboard": ("dashboard", "Overview"),
            "dashboard.proxies": ("proxy_pool", "Proxy pool"),
            "dashboard.earnings": ("earnings", "Earnings"),
            "dashboard.wallet": ("wallet", "Wallet & payouts"),
        }
        active_nav, shell_title = route_shell.get(endpoint, ("dashboard", "Overview"))
        return {"active_nav": active_nav, "shell_title": shell_title}

    from app.routes import admin, dashboard, internal_api, proxies, wallets
    from app.routes import auth as auth_routes

    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(proxies.bp)
    app.register_blueprint(internal_api.bp)
    app.register_blueprint(internal_api.api_bp)
    app.register_blueprint(wallets.bp)

    def _wants_json_error() -> bool:
        accept = request.headers.get("Accept", "")
        return request.is_json or ("application/json" in accept and "text/html" not in accept)

    @app.errorhandler(401)
    def handle_unauthorized(error):
        if _wants_json_error():
            return jsonify(error="Authentication required"), 401
        return (
            render_template(
                "error.html",
                status_code=401,
                title="Sign in to continue",
                message="Your session is missing or has expired. Sign in again to continue.",
                recovery_endpoint="auth.login",
                recovery_label="Go to sign in",
            ),
            401,
        )

    @app.errorhandler(403)
    def handle_forbidden(error):
        if _wants_json_error():
            return jsonify(error="Access denied"), 403
        recovery_endpoint = (
            "admin.dashboard" if g.user is not None and g.user["role"] == "admin" else "dashboard.dashboard"
        )
        recovery_label = "Return to dashboard"
        if g.user is None:
            recovery_endpoint = "auth.login"
            recovery_label = "Go to sign in"
        return (
            render_template(
                "error.html",
                status_code=403,
                title="Access denied",
                message="You do not have permission to view this page.",
                recovery_endpoint=recovery_endpoint,
                recovery_label=recovery_label,
            ),
            403,
        )

    @app.errorhandler(404)
    def handle_not_found(error):
        if _wants_json_error():
            return jsonify(error="Resource not found"), 404
        recovery_endpoint = "dashboard.dashboard" if g.user is not None else "auth.login"
        return (
            render_template(
                "error.html",
                status_code=404,
                title="Page not found",
                message="The page you requested could not be found.",
                recovery_endpoint=recovery_endpoint,
                recovery_label="Return to dashboard" if g.user is not None else "Go to sign in",
            ),
            404,
        )

    with app.app_context():
        database = db.get_db()
        from app.services.api_keys import ensure_legacy_api_key

        # Keep the pre-existing environment key working while moving auth to
        # revocable, database-backed key records. Only its digest is stored.
        ensure_legacy_api_key(database, app.config.get("INTERNAL_API_KEY"))
        admin_email = str(app.config.get("ADMIN_EMAIL") or "").strip().lower()
        admin_password = str(app.config.get("ADMIN_PASSWORD") or "")
        if admin_email and admin_password:
            existing = database.execute("SELECT id FROM users WHERE email=?", (admin_email,)).fetchone()
            if existing is None:
                from app.services.users import create_user

                try:
                    create_user(database, admin_email, admin_password, status="active", role="admin")
                except sqlite3.IntegrityError:
                    existing = database.execute(
                        "SELECT role,status FROM users WHERE email=?", (admin_email,)
                    ).fetchone()
                    if existing is None or existing["role"] != "admin" or existing["status"] != "active":
                        raise

    @app.get("/healthz")
    def healthz():
        return jsonify(service="earn-proxy", status="ok")

    return app


__all__ = ["create_app"]
