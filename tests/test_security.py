from __future__ import annotations

import sqlite3
import threading
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
    assert app.config["MAX_CONTENT_LENGTH"] == 1024 * 1024
    assert app.config["MAX_PROXY_IMPORT_BYTES"] == 512 * 1024
    assert app.config["MAX_PROXY_IMPORT_LINES"] == 5000


def test_state_changing_routes_require_csrf_token(app, client):
    app.config["CSRF_ENABLED"] = True
    response = client.post("/register", data={"email": "member@example.com", "password": "member-password"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Invalid CSRF token"


def test_public_registration_uses_a_generic_duplicate_response(app, client):
    first = client.post("/register", data={"email": "same@example.com", "password": "member-password"})
    duplicate = client.post("/register", data={"email": "same@example.com", "password": "another-password"})

    assert first.status_code == 201
    assert duplicate.status_code == first.status_code
    assert duplicate.get_json() == first.get_json()


def test_login_runs_password_verification_for_unknown_and_existing_email(app, client, monkeypatch):
    from app.db import get_db
    from app.services.users import create_user

    with app.app_context():
        create_user(get_db(), "known-login@example.com", "member-password", status="active")

    verified_hashes = []

    def record_password_check(password_hash, _password):
        verified_hashes.append(password_hash)
        return False

    monkeypatch.setattr("app.routes.auth.check_password_hash", record_password_check)

    unknown = client.post(
        "/login",
        data={"email": "unknown-login@example.com", "password": "wrong-password"},
    )
    known = client.post(
        "/login",
        data={"email": "known-login@example.com", "password": "wrong-password"},
    )

    assert unknown.status_code == 401
    assert known.status_code == 401
    assert len(verified_hashes) == 2
    assert verified_hashes[0]
    assert verified_hashes[1]


def test_login_rate_limit_rejects_before_password_work(app, client, monkeypatch):
    app.config["LOGIN_IP_MAX_ATTEMPTS"] = 1
    calls = 0

    def record_password_check(_password_hash, _password):
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr("app.routes.auth.check_password_hash", record_password_check)

    first = client.post(
        "/login",
        data={"email": "first-login@example.com", "password": "wrong-password"},
    )
    second = client.post(
        "/login",
        data={"email": "first-login@example.com", "password": "wrong-password"},
    )

    assert first.status_code == 401
    assert second.status_code == 429
    assert calls == 1


def test_wrong_passwords_cannot_lock_a_target_account(app, client):
    from app.db import get_db
    from app.services.users import create_user

    app.config["LOGIN_IP_MAX_ATTEMPTS"] = 100
    app.config["LOGIN_GLOBAL_MAX_ATTEMPTS"] = 100
    app.config["LOGIN_MAX_ATTEMPTS"] = 2
    with app.app_context():
        create_user(get_db(), "target@example.com", "correct-password", status="active")

    for _attempt in range(2):
        response = client.post(
            "/login",
            data={"email": "target@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401

    accepted = client.post(
        "/login",
        data={"email": "target@example.com", "password": "correct-password"},
    )

    assert accepted.status_code == 200


def test_registration_rate_limit_rejects_before_password_work(app, client, monkeypatch):
    app.config["REGISTRATION_MAX_ATTEMPTS"] = 1
    assert (
        client.post("/register", data={"email": "first@example.com", "password": "member-password"}).status_code == 201
    )

    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("password hashing/user creation should not run after the registration limit")

    monkeypatch.setattr("app.routes.auth.create_user", fail_if_called)
    blocked = client.post("/register", data={"email": "second@example.com", "password": "member-password"})

    assert blocked.status_code == 429
    assert blocked.get_json()["error"] == "Too many registration attempts. Try again later."
    assert called is False


def test_registration_limit_is_shared_across_web_processes(tmp_path):
    config = {
        "TESTING": True,
        "DATABASE": str(tmp_path / "shared-registration-limit.db"),
        "SECRET_KEY": "test-session-secret",
        "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        "INTERNAL_API_KEY": "internal-test-key",
        "ADMIN_EMAIL": "admin@example.com",
        "ADMIN_PASSWORD": "correct horse battery staple",
        "SESSION_COOKIE_SECURE": False,
        "CSRF_ENABLED": False,
        "REGISTRATION_MAX_ATTEMPTS": 1,
    }
    first_process = create_app(config)
    second_process = create_app(config)

    assert (
        first_process.test_client()
        .post("/register", data={"email": "first@example.com", "password": "member-password"})
        .status_code
        == 201
    )
    blocked = second_process.test_client().post(
        "/register", data={"email": "second@example.com", "password": "member-password"}
    )

    assert blocked.status_code == 429


def test_active_user_proxy_quota_is_enforced_before_proxy_parsing(app, client, monkeypatch):
    from app.db import get_db
    from app.services.users import create_user

    app.config["MAX_ACTIVE_PROXIES_PER_USER"] = 1
    with app.app_context():
        user_id = create_user(get_db(), "quota@example.com", "member-password", status="active")
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["session_version"] = 1

    assert client.post("/proxies", data={"raw_proxy": "one.example:9000:u:p"}).status_code == 201
    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("proxy parsing/encryption should not run after quota exhaustion")

    monkeypatch.setattr("app.routes.proxies.add_proxy", fail_if_called)
    blocked = client.post("/proxies", data={"raw_proxy": "two.example:9000:u:p"})

    assert blocked.status_code == 429
    assert "maximum number of active proxies" in blocked.get_json()["error"].lower()
    assert called is False


def test_active_user_proxy_quota_is_atomic_under_concurrent_requests(app, monkeypatch):
    from app.db import get_db
    from app.routes import proxies as proxies_route
    from app.services.users import create_user

    app.config["MAX_ACTIVE_PROXIES_PER_USER"] = 1
    with app.app_context():
        user_id = create_user(get_db(), "quota-race@example.com", "member-password", status="active")

    # Force both requests past the old COUNT-then-INSERT gap before either insert.
    original_add_proxy = proxies_route.add_proxy
    barrier = threading.Barrier(2)

    def synchronized_add_proxy(*args, **kwargs):
        barrier.wait(timeout=5)
        return original_add_proxy(*args, **kwargs)

    monkeypatch.setattr(proxies_route, "add_proxy", synchronized_add_proxy)
    responses = []

    def submit(raw_proxy: str) -> None:
        request_client = app.test_client()
        with request_client.session_transaction() as session:
            session["user_id"] = user_id
            session["session_version"] = 1
        responses.append(request_client.post("/proxies", data={"raw_proxy": raw_proxy}).status_code)

    threads = [
        threading.Thread(target=submit, args=("race-one.example:9000:u:one",)),
        threading.Thread(target=submit, args=("race-two.example:9001:u:two",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    with app.app_context():
        count = (
            get_db()
            .execute(
                "SELECT COUNT(*) AS count FROM proxies WHERE user_id=? AND archived_at IS NULL",
                (user_id,),
            )
            .fetchone()["count"]
        )

    assert sorted(responses) == [201, 429]
    assert count == 1


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
