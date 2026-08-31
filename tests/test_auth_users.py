from conftest import login, login_admin, register

from app.db import get_db


def test_root_redirects_anonymous_visitors_to_login(client):
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_root_redirects_admin_to_admin_dashboard(client):
    login_admin(client)

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin")


def test_root_redirects_active_user_to_user_dashboard(app, client):
    register(client)
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email = ?", ("member@example.com",)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client)

    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_registration_is_pending_until_admin_approves(app, client):
    response = register(client)
    assert response.status_code == 201
    assert login(client).status_code == 403

    assert login_admin(client).status_code == 200
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email = ?", ("member@example.com",)).fetchone()["id"]
    assert client.post(f"/admin/users/{user_id}/approve").status_code == 200

    client.post("/logout")
    assert login(client).status_code == 200


def test_block_revokes_existing_session(app, client):
    register(client)
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email = ?", ("member@example.com",)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client)
    assert client.get("/dashboard").status_code == 200

    admin = app.test_client()
    login_admin(admin)
    assert admin.post(f"/admin/users/{user_id}/block").status_code == 200
    assert client.get("/dashboard").status_code == 401


def test_pause_earn_does_not_block_user_login(app, client):
    register(client)
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email = ?", ("member@example.com",)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post(f"/admin/users/{user_id}/pause-earn")
    client.post("/logout")

    assert login(client).status_code == 200
    with app.app_context():
        row = get_db().execute("SELECT earn_paused FROM users WHERE id = ?", (user_id,)).fetchone()
        assert row["earn_paused"] == 1


def test_existing_session_is_rejected_if_account_is_no_longer_active(app, client):
    register(client, "status-change@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='status-change@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    assert (
        client.post(
            "/login",
            data={"email": "status-change@example.com", "password": "member-password"},
        ).status_code
        == 200
    )
    with app.app_context():
        get_db().execute("UPDATE users SET status='pending' WHERE id=?", (user_id,))
        get_db().commit()
    assert client.get("/dashboard").status_code == 401


def test_logout_revokes_a_replayed_session_cookie(app, client):
    register(client, "logout-replay@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='logout-replay@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    assert login(client, "logout-replay@example.com", "member-password").status_code == 200

    captured = client.get_cookie("session")
    assert captured is not None
    replay = app.test_client()
    replay.set_cookie("session", captured.value)

    assert client.post("/logout").status_code == 204
    assert replay.get("/dashboard").status_code == 401
