from conftest import login_admin, register

from app.db import get_db


def test_admin_can_create_and_delete_a_user_without_reusing_the_record(app, client):
    login_admin(client)
    created = client.post(
        "/admin/users",
        data={"email": "created@example.com", "password": "created-password"},
    )
    assert created.status_code == 201
    user_id = created.get_json()["id"]
    deleted = client.post(f"/admin/users/{user_id}/delete")
    assert deleted.status_code == 200
    with app.app_context():
        row = get_db().execute("SELECT status, session_version FROM users WHERE id=?", (user_id,)).fetchone()
    assert row["status"] == "deleted"
    assert row["session_version"] > 1


def test_admin_rejects_email_longer_than_rfc_limit(app, client):
    login_admin(client)
    oversized = "a" * 245 + "@example.com"

    response = client.post(
        "/admin/users",
        data={"email": oversized, "password": "created-password"},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "A valid email and password of at least 8 characters are required"
    with app.app_context():
        assert (
            get_db().execute("SELECT COUNT(*) AS count FROM users WHERE email=?", (oversized,)).fetchone()["count"] == 0
        )


def test_deleted_user_cannot_login_or_add_proxy(app, client):
    register(client, "delete-me@example.com", "delete-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='delete-me@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/delete")
    client.post("/logout")
    assert (
        client.post(
            "/login",
            data={"email": "delete-me@example.com", "password": "delete-password"},
        ).status_code
        == 403
    )
