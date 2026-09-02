from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

from app.db import get_db, init_db
from app.services.api_keys import (
    authenticate_api_key,
    create_api_key,
    ensure_legacy_api_key,
    revoke_api_key,
    rotate_api_key,
)
from app.services.users import create_user


def test_created_api_key_is_authenticatable_but_plaintext_is_never_stored(app):
    with app.app_context():
        db = get_db()
        admin_id = create_user(db, "key-admin@example.com", "password", status="active", role="admin")
        key_id, token = create_api_key(db, "Distribution client", created_by_user_id=admin_id)

        row = db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
        assert row["name"] == "Distribution client"
        assert row["token_hash"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
        assert token not in dict(row).values()
        assert authenticate_api_key(db, token)["id"] == key_id
        assert db.execute("SELECT last_used_at FROM api_keys WHERE id=?", (key_id,)).fetchone()["last_used_at"]


def test_authentication_throttles_last_used_writes(app, monkeypatch):
    from app.services import api_keys as module

    created = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        key_id, token = create_api_key(db, "Telemetry", now=created)
        first = created + timedelta(minutes=1)
        monkeypatch.setattr(module, "_utcnow", lambda: first)
        assert authenticate_api_key(db, token) is not None
        first_used = db.execute("SELECT last_used_at FROM api_keys WHERE id=?", (key_id,)).fetchone()["last_used_at"]

        monkeypatch.setattr(module, "_utcnow", lambda: first + timedelta(minutes=2))
        assert authenticate_api_key(db, token) is not None
        second_used = db.execute("SELECT last_used_at FROM api_keys WHERE id=?", (key_id,)).fetchone()["last_used_at"]

        monkeypatch.setattr(module, "_utcnow", lambda: first + timedelta(minutes=6))
        assert authenticate_api_key(db, token) is not None
        third_used = db.execute("SELECT last_used_at FROM api_keys WHERE id=?", (key_id,)).fetchone()["last_used_at"]

    assert first_used == first.isoformat()
    assert second_used == first_used
    assert third_used == (first + timedelta(minutes=6)).isoformat()


def test_legacy_environment_key_import_is_idempotent_and_revocable(app):
    with app.app_context():
        db = get_db()
        before = db.execute("SELECT COUNT(*) AS count FROM api_keys WHERE source='legacy'").fetchone()["count"]
        ensure_legacy_api_key(db, "legacy-secret")
        middle = db.execute("SELECT COUNT(*) AS count FROM api_keys WHERE source='legacy'").fetchone()["count"]
        ensure_legacy_api_key(db, "legacy-secret")
        rows = db.execute(
            "SELECT * FROM api_keys WHERE source='legacy' AND token_hash=?",
            (hashlib.sha256(b"legacy-secret").hexdigest(),),
        ).fetchall()
        assert len(rows) == 1
        assert middle == before + 1
        assert authenticate_api_key(db, "legacy-secret") is not None
        revoke_api_key(db, rows[0]["id"])
        assert authenticate_api_key(db, "legacy-secret") is None


def test_legacy_environment_key_rotation_revokes_the_previous_configured_key(app):
    with app.app_context():
        db = get_db()
        first_id = ensure_legacy_api_key(
            db,
            "legacy-before-rotation",
            now=datetime(2026, 8, 31, 12, 0, tzinfo=UTC),
        )
        second_id = ensure_legacy_api_key(
            db,
            "legacy-after-rotation",
            now=datetime(2026, 8, 31, 12, 1, tzinfo=UTC),
        )

        assert first_id != second_id
        assert authenticate_api_key(db, "legacy-before-rotation") is None
        assert authenticate_api_key(db, "legacy-after-rotation") is not None
        assert db.execute("SELECT revoked_at FROM api_keys WHERE id=?", (first_id,)).fetchone()["revoked_at"]


def test_empty_legacy_environment_key_revokes_existing_legacy_keys(app):
    with app.app_context():
        db = get_db()
        key_id = ensure_legacy_api_key(db, "legacy-to-disable")
        assert authenticate_api_key(db, "legacy-to-disable") is not None

        assert ensure_legacy_api_key(db, "", now=datetime(2026, 8, 31, 12, 2, tzinfo=UTC)) is None
        assert authenticate_api_key(db, "legacy-to-disable") is None
        assert db.execute("SELECT revoked_at FROM api_keys WHERE id=?", (key_id,)).fetchone()["revoked_at"]


def test_rotate_revokes_old_key_and_returns_a_new_one(app):
    with app.app_context():
        db = get_db()
        admin_id = create_user(db, "rotate-admin@example.com", "password", status="active", role="admin")
        old_id, old_token = create_api_key(db, "Primary client", created_by_user_id=admin_id)
        new_id, new_token = rotate_api_key(db, old_id, created_by_user_id=admin_id)

        assert new_id != old_id
        assert old_token != new_token
        assert authenticate_api_key(db, old_token) is None
        assert authenticate_api_key(db, new_token)["id"] == new_id
        assert db.execute("SELECT revoked_at FROM api_keys WHERE id=?", (old_id,)).fetchone()["revoked_at"]


def test_admin_key_workspace_reveals_token_once_and_masks_listing(app, client):
    from conftest import login_admin

    login_admin(client)
    response = client.post(
        "/admin/integrations/api-keys",
        data={"name": "External distributor", "ui": "1"},
        follow_redirects=True,
    )
    page = response.get_data(as_text=True)
    match = re.search(r"ep_live_[A-Za-z0-9_-]+", page)
    assert response.status_code == 200
    assert match is not None
    token = match.group(0)
    assert "Copy this token now" in page
    assert "token_hash" not in page
    assert "Secret material is never shown again" in page

    listing = client.get("/admin/integrations/api-keys").get_data(as_text=True)
    assert token not in listing
    assert "External distributor" in listing
    assert "Revoke" in listing
    assert "Rotate" in listing
    assert 'data-confirm-title="Revoke API key?"' in listing
    assert 'data-confirm-title="Rotate API key?"' in listing


def test_browser_refresh_does_not_create_a_second_key_or_reveal_secret_again(app, client):
    from conftest import login_admin

    login_admin(client)
    response = client.post(
        "/admin/integrations/api-keys",
        data={"name": "Refresh safe", "ui": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    reveal_url = response.headers["Location"]
    reveal = client.get(reveal_url)
    token = re.search(r"ep_live_[A-Za-z0-9_-]+", reveal.get_data(as_text=True)).group(0)
    refreshed = client.get(reveal_url).get_data(as_text=True)

    with app.app_context():
        count = get_db().execute("SELECT COUNT(*) AS count FROM api_keys WHERE name='Refresh safe'").fetchone()["count"]
    assert count == 1
    assert token not in refreshed


def test_one_time_reveal_vault_never_stores_plaintext_token(app, client):
    from conftest import login_admin

    login_admin(client)
    response = client.post(
        "/admin/integrations/api-keys",
        data={"name": "Vault check", "ui": "1"},
        follow_redirects=False,
    )
    with app.app_context():
        reveal = get_db().execute("SELECT * FROM api_key_reveals ORDER BY id DESC LIMIT 1").fetchone()
    assert reveal is not None
    assert reveal["token_encrypted"]
    assert "ep_live_" not in reveal["token_encrypted"]
    assert response.headers["Cache-Control"] == "no-store"


def test_reveal_is_consumed_atomically_and_expires(app):
    from app.services.api_keys import consume_api_key_reveal, create_api_key_reveal

    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        reveal_id = create_api_key_reveal(db, "ep_live_secret", "copy", now=now)
        first = consume_api_key_reveal(db, reveal_id, now=now + timedelta(minutes=1))
        second = consume_api_key_reveal(db, reveal_id, now=now + timedelta(minutes=1))
        expired_id = create_api_key_reveal(db, "ep_live_expired", "copy", now=now)
        expired = consume_api_key_reveal(db, expired_id, now=now + timedelta(minutes=11))

    assert first == ("ep_live_secret", "copy")
    assert second is None
    assert expired is None


def test_managed_key_authenticates_canonical_api_and_revocation_is_immediate(app, client):
    from conftest import login_admin

    login_admin(client)
    created = client.post("/admin/integrations/api-keys", data={"name": "Machine client"})
    token = created.get_json()["token"]
    public_id = created.get_json()["id"]
    assert public_id.startswith("key_")

    allowed = client.get("/api/v1/proxies", headers={"X-API-Key": token})
    assert allowed.status_code == 200
    revoked = client.post(f"/admin/integrations/api-keys/{public_id}/revoke")
    assert revoked.status_code == 200
    denied = client.get("/api/v1/proxies", headers={"X-API-Key": token})
    assert denied.status_code == 401


def test_api_key_actions_use_random_public_ids_instead_of_database_ids(app, client):
    from conftest import login_admin

    login_admin(client)
    created = client.post("/admin/integrations/api-keys", data={"name": "Public route"}).get_json()
    with app.app_context():
        row = get_db().execute("SELECT id,public_id FROM api_keys WHERE public_id=?", (created["id"],)).fetchone()

    listing = client.get("/admin/integrations/api-keys").get_data(as_text=True)
    assert f"/admin/integrations/api-keys/{row['public_id']}/rotate" in listing
    assert f"/admin/integrations/api-keys/{row['id']}/rotate" not in listing
    assert client.post(f"/admin/integrations/api-keys/{row['id']}/revoke").status_code == 404


def test_api_key_workspace_requires_admin_and_dangerous_actions_have_confirmation(client):
    assert client.get("/admin/integrations/api-keys").status_code == 403


def test_database_initialization_does_not_duplicate_configured_legacy_key(app):
    with app.app_context():
        db = get_db()
        before = db.execute("SELECT COUNT(*) AS count FROM api_keys WHERE source='legacy'").fetchone()["count"]
        init_db()
        after = db.execute("SELECT COUNT(*) AS count FROM api_keys WHERE source='legacy'").fetchone()["count"]
        assert before == after == 1
