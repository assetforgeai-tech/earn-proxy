from __future__ import annotations

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
