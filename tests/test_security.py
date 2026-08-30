from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from app import create_app


def test_production_rejects_placeholder_or_missing_secrets(tmp_path):
    try:
        create_app(
            {
                "TESTING": False,
                "DATABASE": str(tmp_path / "prod.db"),
                "SECRET_KEY": "dev-change-me",
                "FERNET_KEY": "",
                "INTERNAL_API_KEY": "",
            }
        )
    except RuntimeError as exc:
        assert "production secrets" in str(exc).lower()
    else:
        raise AssertionError("Production app accepted unsafe secrets")


def test_production_rejects_env_example_placeholders(tmp_path):
    try:
        create_app(
            {
                "TESTING": False,
                "DATABASE": str(tmp_path / "prod-placeholders.db"),
                "SECRET_KEY": "replace-with-a-long-random-session-secret",
                "FERNET_KEY": "replace-with-a-valid-fernet-key",
                "INTERNAL_API_KEY": "replace-with-a-long-random-api-key",
                "ADMIN_EMAIL": "admin@example.com",
                "ADMIN_PASSWORD": "replace-with-a-strong-admin-password",
            }
        )
    except RuntimeError as exc:
        assert "production secrets" in str(exc).lower()
    else:
        raise AssertionError("Production app accepted .env.example placeholders")


def test_session_cookie_security_defaults(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["MAX_CONTENT_LENGTH"] == 64 * 1024


def test_state_changing_routes_require_csrf_token(app, client):
    app.config["CSRF_ENABLED"] = True
    response = client.post("/register", data={"email": "member@example.com", "password": "member-password"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid CSRF token"


def test_admin_bootstrap_tolerates_another_process_winning_the_insert_race(tmp_path, monkeypatch):
    from app.services import users as users_service

    def concurrent_admin_insert(db, email, _password, *, status="pending", role="user"):
        db.execute(
            "INSERT INTO users(email,password_hash,role,status,created_at) VALUES(?,?,?,?,?)",
            (email, "concurrent-hash", role, status, datetime.now(UTC).isoformat()),
        )
        db.commit()
        raise sqlite3.IntegrityError("simulated concurrent admin insert")

    monkeypatch.setattr(users_service, "create_user", concurrent_admin_insert)
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "admin-race.db"),
            "SECRET_KEY": "test-session-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
            "INTERNAL_API_KEY": "internal-test-key",
            "ADMIN_EMAIL": "admin-race@example.com",
            "ADMIN_PASSWORD": "correct horse battery staple",
            "SESSION_COOKIE_SECURE": False,
        }
    )

    with application.app_context():
        from app.db import get_db

        admin = get_db().execute("SELECT role,status FROM users WHERE email=?", ("admin-race@example.com",)).fetchone()
    assert admin["role"] == "admin"
    assert admin["status"] == "active"
