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
        "last_success_at",
        "health_mode",
        "next_probe_index",
        "last_probe_endpoint",
        "last_latency_ms",
        "failure_kind",
    }.issubset(columns)
    with app.app_context():
        assert decrypt_secret(row["username_encrypted"]) == "legacy-user"
        assert decrypt_secret(row["password_encrypted"]) == "legacy-secret"
    assert row["username"] == ""
    assert row["password"] == ""
    assert row["credential_fingerprint"]
    # A legacy `online` label is not proof of a successful health observation;
    # distribution must remain fail-closed until the new checker confirms it.
    assert row["last_success_at"] is None


def test_migration_inspects_existing_schema_inside_a_serialized_transaction(tmp_path, monkeypatch):
    database = tmp_path / "serialized-migration.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE proxies(
            id INTEGER PRIMARY KEY, user_id INTEGER, host TEXT NOT NULL, port INTEGER NOT NULL,
            username TEXT, password TEXT, status TEXT DEFAULT 'unknown', created_at TEXT
        );
        """
    )
    connection.commit()
    connection.close()

    from app import db as db_module

    original_columns = db_module._columns
    transaction_states = []

    def observed_columns(db, table):
        transaction_states.append(db.in_transaction)
        return original_columns(db, table)

    monkeypatch.setattr(db_module, "_columns", observed_columns)
    create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    assert transaction_states
    assert all(transaction_states)


def test_existing_payout_database_gets_a_wallet_address_snapshot_column(tmp_path):
    database = tmp_path / "legacy-payout.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE wallets(id INTEGER PRIMARY KEY, user_id INTEGER, address TEXT, locked_until TEXT, updated_at TEXT);
        CREATE TABLE payouts(
            id INTEGER PRIMARY KEY, user_id INTEGER, wallet_id INTEGER, amount_micro_usd INTEGER,
            status TEXT, tx_hash TEXT, created_at TEXT, updated_at TEXT
        );
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        columns = {row["name"] for row in get_db().execute("PRAGMA table_info(payouts)").fetchall()}
    assert "wallet_address" in columns
    assert {"fee_bps", "fee_micro_usd", "net_micro_usd", "processing_due_at"}.issubset(columns)


def test_legacy_payout_migration_preserves_original_transfer_amount(tmp_path):
    database = tmp_path / "legacy-payout-fee.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE wallets(id INTEGER PRIMARY KEY, user_id INTEGER, address TEXT, locked_until TEXT, updated_at TEXT);
        CREATE TABLE payouts(
            id INTEGER PRIMARY KEY, user_id INTEGER, wallet_id INTEGER, amount_micro_usd INTEGER,
            status TEXT, tx_hash TEXT, created_at TEXT, updated_at TEXT
        );
        INSERT INTO payouts VALUES(
            1, 1, 1, 12000000, 'requested', '',
            '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
        );
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        row = (
            get_db()
            .execute("SELECT fee_bps, fee_micro_usd, net_micro_usd, processing_due_at FROM payouts WHERE id=1")
            .fetchone()
        )

    assert row["fee_bps"] == 0
    assert row["fee_micro_usd"] == 0
    assert row["net_micro_usd"] == 12_000_000
    assert row["processing_due_at"] == "2026-01-03T00:00:00+00:00"


def test_legacy_sent_payout_remains_reserved_after_verification_migration(tmp_path):
    database = tmp_path / "legacy-sent-payout.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE wallets(id INTEGER PRIMARY KEY, user_id INTEGER, address TEXT, locked_until TEXT, updated_at TEXT);
        CREATE TABLE payouts(
            id INTEGER PRIMARY KEY, user_id INTEGER, wallet_id INTEGER, amount_micro_usd INTEGER,
            status TEXT, tx_hash TEXT, created_at TEXT, updated_at TEXT
        );
        INSERT INTO users VALUES(1, 'legacy-paid@example.com', 'hash', 'user', 'active', '2026-01-01T00:00:00+00:00');
        INSERT INTO wallets VALUES(1, 1, '0x1111111111111111111111111111111111111111', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        INSERT INTO payouts VALUES(1, 1, 1, 500000, 'sent', '0xabc123', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        row = get_db().execute("SELECT status, verification_error FROM payouts WHERE id=1").fetchone()

    assert row["status"] == "sent"
    assert "legacy" in row["verification_error"].lower()


def test_payout_migration_tolerates_duplicate_legacy_short_transaction_labels(tmp_path):
    database = tmp_path / "legacy-duplicate-short-tx.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE wallets(id INTEGER PRIMARY KEY, user_id INTEGER, address TEXT, locked_until TEXT, updated_at TEXT);
        CREATE TABLE payouts(
            id INTEGER PRIMARY KEY, user_id INTEGER, wallet_id INTEGER, amount_micro_usd INTEGER,
            status TEXT, tx_hash TEXT, created_at TEXT, updated_at TEXT
        );
        INSERT INTO payouts VALUES(1, 1, 1, 500000, 'sent', 'manual', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        INSERT INTO payouts VALUES(2, 1, 1, 500000, 'sent', 'manual', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        index = (
            get_db()
            .execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='payouts_tx_hash_uidx'")
            .fetchone()
        )

    assert index is not None
    assert "length(tx_hash)=66" in index["sql"].replace(" ", "")


def test_payout_migration_reconciles_duplicate_full_transaction_hashes(tmp_path):
    database = tmp_path / "legacy-duplicate-full-tx.db"
    duplicate_hash = "0x" + "ab" * 32
    connection = sqlite3.connect(database)
    connection.executescript(
        f"""
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE wallets(id INTEGER PRIMARY KEY, user_id INTEGER, address TEXT, locked_until TEXT, updated_at TEXT);
        CREATE TABLE payouts(
            id INTEGER PRIMARY KEY, user_id INTEGER, wallet_id INTEGER, amount_micro_usd INTEGER,
            status TEXT, tx_hash TEXT, created_at TEXT, updated_at TEXT
        );
        INSERT INTO payouts VALUES(1, 1, 1, 500000, 'sent', '{duplicate_hash}', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        INSERT INTO payouts VALUES(2, 1, 1, 500000, 'sent', '{duplicate_hash.upper()}', '2026-01-02T00:00:00+00:00', '2026-01-02T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        rows = get_db().execute("SELECT id, tx_hash, verification_error FROM payouts ORDER BY id").fetchall()
        index = (
            get_db()
            .execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='payouts_tx_hash_uidx'")
            .fetchone()
        )

    assert rows[0]["tx_hash"] == duplicate_hash
    assert rows[1]["tx_hash"] == ""
    assert "duplicate" in rows[1]["verification_error"].lower()
    assert index is not None


def test_migration_handles_multiple_rows_with_unknown_fingerprints(tmp_path):
    database = tmp_path / "partial-migration.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE proxies(
            id INTEGER PRIMARY KEY, user_id INTEGER, host TEXT NOT NULL, port INTEGER NOT NULL,
            username_encrypted TEXT, password_encrypted TEXT, credential_fingerprint TEXT,
            status TEXT DEFAULT 'pending', created_at TEXT
        );
        INSERT INTO users VALUES(1, 'partial@example.com', 'hash', 'user', 'active', '2026-01-01T00:00:00+00:00');
        INSERT INTO proxies VALUES(1, 1, 'one.example', 8080, '', '', '', 'pending', '2026-01-01T00:00:00+00:00');
        INSERT INTO proxies VALUES(2, 1, 'two.example', 8081, '', '', '', 'pending', '2026-01-01T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        rows = get_db().execute("SELECT id, credential_fingerprint FROM proxies ORDER BY id").fetchall()
        index = (
            get_db()
            .execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='proxies_credential_fingerprint_uidx'")
            .fetchone()
        )

    assert len(rows) == 2
    assert all(row["credential_fingerprint"] == "" for row in rows)
    assert index is not None
    assert "WHERE credential_fingerprint <> ''" in index["sql"]


def test_attestation_hardening_migration_invalidates_legacy_egress_identity(tmp_path):
    database = tmp_path / "legacy-egress.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, role TEXT, status TEXT, created_at TEXT);
        CREATE TABLE proxies(
            id INTEGER PRIMARY KEY, user_id INTEGER, host TEXT NOT NULL, port INTEGER NOT NULL,
            protocol_hint TEXT, detected_protocol TEXT, username_encrypted TEXT, password_encrypted TEXT,
            credential_fingerprint TEXT, credential_generation INTEGER, status TEXT, eligibility TEXT,
            earnapp_verdict TEXT, earnapp_reason TEXT, earnapp_checked_at TEXT, earnapp_next_check_at TEXT,
            egress_verified_at TEXT, earnapp_claimed_until TEXT, earnapp_claim_token TEXT, exit_ip TEXT,
            country_code TEXT, duplicate_of INTEGER, consecutive_failures INTEGER, online_since TEXT,
            offline_since TEXT, last_checked_at TEXT, last_success_at TEXT, next_check_at TEXT,
            check_claimed_until TEXT, check_claim_token TEXT, health_mode TEXT, next_probe_index INTEGER,
            last_probe_endpoint TEXT, last_latency_ms INTEGER, failure_kind TEXT, accrual_cursor_at TEXT,
            probation_started_at TEXT, accumulated_online_seconds INTEGER, accumulated_offline_seconds INTEGER,
            continuous_dead_since TEXT, archived_at TEXT, last_error TEXT, created_at TEXT, updated_at TEXT
        );
        CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
        INSERT INTO users VALUES(1, 'legacy-egress@example.com', 'hash', 'user', 'active', '2026-01-01T00:00:00+00:00');
        INSERT INTO proxies VALUES(
            1, 1, 'legacy-egress.example', 8080, 'auto', 'socks5', '', '', 'fingerprint', 1,
            'online', 'allow', 'CID_SET', 'cid', '2026-01-01T00:00:00+00:00', NULL,
            '2026-01-01T00:00:00+00:00', NULL, NULL, '198.51.100.20', 'US', NULL, 0,
            '2026-01-01T00:00:00+00:00', NULL, '2026-01-01T00:00:00+00:00',
            '2026-01-01T00:00:00+00:00', '2026-01-01T01:00:00+00:00', NULL, NULL, 'fast', 0,
            '', 100, '', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', 0, 0,
            NULL, NULL, '', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
        );
        """
    )
    connection.commit()
    connection.close()

    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(database),
            "SECRET_KEY": "migration-secret",
            "FERNET_KEY": "-WjNr7wJTuNQqnbsZog_WamxH_0FcKscBU8vcR2ThIY=",
        }
    )

    with application.app_context():
        db = get_db()
        row = db.execute(
            "SELECT status, eligibility, exit_ip, egress_verified_at, egress_attestation_source, "
            "country_code, duplicate_of, "
            "health_mode, next_check_at FROM proxies WHERE id=1"
        ).fetchone()

    assert row["status"] == "online"
    assert row["eligibility"] == "pending"
    assert row["exit_ip"] is None
    assert row["egress_verified_at"] is None
    assert row["egress_attestation_source"] == ""
    assert row["country_code"] == ""
    assert row["duplicate_of"] is None
    assert row["health_mode"] == "strong"
    assert row["next_check_at"] <= "1970-01-01T00:00:00+00:00"


def test_attestation_migration_invalidates_rows_with_untrusted_existing_source(app):
    from app.services.proxies import add_proxy
    from app.services.users import create_user

    with app.app_context():
        db = get_db()
        user_id = create_user(db, "intermediate-egress@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "intermediate-egress.example:9000:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', "
            "exit_ip='198.51.100.30', egress_verified_at='2026-01-01T00:00:00+00:00', "
            "egress_attestation_source='', country_code='US', duplicate_of=NULL, health_mode='fast' "
            "WHERE id=?",
            (proxy_id,),
        )
        db.commit()

        from app.db import migrate_db

        migrate_db(db)
        row = db.execute(
            "SELECT eligibility, exit_ip, egress_verified_at, egress_attestation_source, "
            "country_code, duplicate_of, health_mode FROM proxies WHERE id=?",
            (proxy_id,),
        ).fetchone()

    assert row["eligibility"] == "pending"
    assert row["exit_ip"] is None
    assert row["egress_verified_at"] is None
    assert row["egress_attestation_source"] == ""
    assert row["country_code"] == ""
    assert row["duplicate_of"] is None
    assert row["health_mode"] == "strong"
