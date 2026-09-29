import json

from cryptography.fernet import Fernet

from app.crypto import decrypt_secret, encrypt_secret
from app.services.proxiware_credentials import (
    get_provider_secret,
    get_provider_secret_metadata,
    load_provider_session,
    save_provider_secret,
    store_provider_session,
)
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


def test_worker_profile_reads_provider_credentials_from_worker_ciphertext(app, db):
    app.config["PROXIWARE_WORKER_FERNET_KEY"] = Fernet.generate_key().decode("ascii")
    save_provider_secret(db, "login_email", "owner@example.com")

    app.config["RUNTIME_PROFILE"] = "proxiware_worker"

    assert get_provider_secret(db, "login_email") == "owner@example.com"
    row = db.execute(
        "SELECT secret_encrypted,worker_secret_encrypted FROM provider_credentials WHERE name='login_email'"
    ).fetchone()
    assert decrypt_secret(row["secret_encrypted"]) == "owner@example.com"
    assert decrypt_worker_secret(row["worker_secret_encrypted"]) == "owner@example.com"


def test_worker_profile_reads_worker_ciphertext_when_legacy_ciphertext_is_empty(app, db):
    app.config["PROXIWARE_WORKER_FERNET_KEY"] = Fernet.generate_key().decode("ascii")
    save_provider_secret(db, "login_email", "owner@example.com")
    db.execute("UPDATE provider_credentials SET secret_encrypted='' WHERE provider='proxiware' AND name='login_email'")
    db.commit()
    app.config["RUNTIME_PROFILE"] = "proxiware_worker"

    assert get_provider_secret(db, "login_email") == "owner@example.com"


def test_worker_profile_metadata_uses_worker_ciphertext(app, db):
    app.config["PROXIWARE_WORKER_FERNET_KEY"] = Fernet.generate_key().decode("ascii")
    save_provider_secret(db, "api_key", "provider-api-key")
    db.execute("UPDATE provider_credentials SET secret_encrypted='' WHERE provider='proxiware' AND name='api_key'")
    db.commit()
    app.config["RUNTIME_PROFILE"] = "proxiware_worker"

    metadata = get_provider_secret_metadata(db)

    assert metadata["api_key"]["configured"] is True
    assert metadata["api_key"]["last_four"] == "-key"


def test_worker_profile_can_store_renewed_session_without_global_key(app, db):
    app.config.update(
        RUNTIME_PROFILE="proxiware_worker",
        FERNET_KEY="",
        PROXIWARE_WORKER_FERNET_KEY=Fernet.generate_key().decode("ascii"),
    )

    store_provider_session(db, {"session": "renewed-cookie"})

    row = db.execute(
        "SELECT cookie_encrypted,worker_cookie_encrypted,state FROM provider_sessions WHERE provider='proxiware'"
    ).fetchone()
    assert row["cookie_encrypted"] == ""
    assert json.loads(decrypt_worker_secret(row["worker_cookie_encrypted"])) == {"session": "renewed-cookie"}
    assert row["state"] == "active"
