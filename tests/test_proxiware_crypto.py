import json

from cryptography.fernet import Fernet

from app.crypto import decrypt_secret, encrypt_secret
from app.services.proxiware_credentials import load_provider_session, store_provider_session
from app.services.proxiware_crypto import decrypt_worker_secret, migrate_provider_worker_secrets


def test_worker_session_uses_a_dedicated_encryption_key(app, db):
    app.config["PROXIWARE_WORKER_FERNET_KEY"] = Fernet.generate_key().decode("ascii")

    store_provider_session(db, {"session": "provider-cookie"})
    row = db.execute(
        "SELECT cookie_encrypted,worker_cookie_encrypted FROM provider_sessions WHERE provider='proxiware'"
    ).fetchone()

    assert json.loads(decrypt_secret(row["cookie_encrypted"])) == {"session": "provider-cookie"}
    assert json.loads(decrypt_worker_secret(row["worker_cookie_encrypted"])) == {"session": "provider-cookie"}
    app.config["RUNTIME_PROFILE"] = "proxiware_worker"
    assert load_provider_session(db) == {"session": "provider-cookie"}


def test_provider_session_crypto_migration_adds_worker_cipher_without_replacing_legacy_cipher(app, db):
    global_value = json.dumps({"session": "legacy-cookie"})
    db.execute(
        "INSERT INTO provider_sessions(provider,cookie_encrypted,expires_at,state,updated_at) VALUES(?,?,?,?,?)",
        ("proxiware", encrypt_secret(global_value), None, "active", "2026-01-01T00:00:00+00:00"),
    )
    db.commit()
    app.config["PROXIWARE_WORKER_FERNET_KEY"] = Fernet.generate_key().decode("ascii")

    migrate_provider_worker_secrets(db)

    row = db.execute(
        "SELECT cookie_encrypted,worker_cookie_encrypted FROM provider_sessions WHERE provider='proxiware'"
    ).fetchone()
    assert decrypt_secret(row["cookie_encrypted"]) == global_value
    assert decrypt_worker_secret(row["worker_cookie_encrypted"]) == global_value
