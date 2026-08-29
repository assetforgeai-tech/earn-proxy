from __future__ import annotations

import sqlite3

from app import create_app
from app.crypto import decrypt_secret
from app.db import get_db


def test_existing_legacy_proxy_database_is_migrated_without_plaintext_credentials(
    tmp_path,
):
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE proxies(
            id INTEGER PRIMARY KEY, user_id INTEGER, host TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT, password TEXT, status TEXT DEFAULT 'unknown', created_at TEXT
        );
        INSERT INTO users VALUES(1, 'legacy@example.com', 'hash', 'user', 'active', '2026-01-01T00:00:00+00:00');
        INSERT INTO proxies VALUES(1, 1, 'legacy.example', 8080, 'legacy-user', 'legacy-secret', 'online', '2026-01-01T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )
    with app.app_context():
        db = get_db()
        columns = {row["name"] for row in db.execute("PRAGMA table_info(proxies)").fetchall()}
        row = db.execute("SELECT * FROM proxies WHERE id=1").fetchone()
    assert {
        "username_encrypted",
        "password_encrypted",
        "credential_fingerprint",
        "credential_generation",
        "check_claim_token",
        "earnapp_claim_token",
        "next_check_at",
    }.issubset(columns)
    with app.app_context():
        assert decrypt_secret(row["username_encrypted"]) == "legacy-user"
        assert decrypt_secret(row["password_encrypted"]) == "legacy-secret"
    assert row["credential_fingerprint"]
