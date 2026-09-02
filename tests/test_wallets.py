import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.services.users import create_user
from app.services.wallets import WalletInUse, WalletLocked, set_wallet


def test_one_bep20_wallet_cannot_belong_to_two_active_accounts(app):
    address = "0x1111111111111111111111111111111111111111"
    with app.app_context():
        db = get_db()
        first = create_user(db, "one@example.com", "password", status="active")
        second = create_user(db, "two@example.com", "password", status="active")
        set_wallet(db, first, address)
        with pytest.raises(WalletInUse):
            set_wallet(db, second, address.upper())


def test_wallet_change_locks_payout_for_48_hours(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        wallet = set_wallet(db, user_id, "0x2222222222222222222222222222222222222222", now=now)
        assert datetime.fromisoformat(wallet.locked_until) == now + timedelta(hours=48)
        with pytest.raises(WalletLocked):
            set_wallet(
                db,
                user_id,
                "0x3333333333333333333333333333333333333333",
                now=now + timedelta(hours=1),
            )


def test_wallet_can_be_reused_after_previous_account_is_blocked(app):
    address = "0x4444444444444444444444444444444444444444"
    with app.app_context():
        db = get_db()
        first = create_user(db, "blocked@example.com", "password", status="active")
        second = create_user(db, "replacement@example.com", "password", status="active")
        set_wallet(db, first, address)
        db.execute("UPDATE users SET status='blocked' WHERE id=?", (first,))
        db.commit()

        wallet = set_wallet(db, second, address)

    assert wallet.address == address


def test_concurrent_wallet_changes_cannot_bypass_the_security_lock(app):
    now = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "wallet-race@example.com", "member-password", status="active")
        set_wallet(
            db,
            user_id,
            "0x1111111111111111111111111111111111111111",
            now=now - timedelta(hours=49),
        )
        database_path = app.config["DATABASE"]

    barrier = threading.Barrier(2)
    successes = []
    errors = []

    class CoordinatedConnection:
        def __init__(self):
            self.connection = sqlite3.connect(database_path, timeout=30)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA busy_timeout = 30000")

        @property
        def in_transaction(self):
            return self.connection.in_transaction

        def execute(self, sql, parameters=()):
            if sql.strip().startswith("SELECT * FROM wallets WHERE user_id") and not self.connection.in_transaction:
                row = self.connection.execute(sql, parameters).fetchone()
                barrier.wait(timeout=5)

                class FixedResult:
                    def fetchone(self):
                        return row

                return FixedResult()
            return self.connection.execute(sql, parameters)

        def executemany(self, sql, parameters):
            return self.connection.executemany(sql, parameters)

        def commit(self):
            self.connection.commit()

        def rollback(self):
            self.connection.rollback()

        def close(self):
            self.connection.close()

    def change_wallet(address):
        db = CoordinatedConnection()
        try:
            successes.append(set_wallet(db, user_id, address, now=now))
        except Exception as exc:  # noqa: BLE001 - assert the losing update is rejected
            errors.append(exc)
        finally:
            db.close()

    threads = [
        threading.Thread(target=change_wallet, args=("0x2222222222222222222222222222222222222222",)),
        threading.Thread(target=change_wallet, args=("0x3333333333333333333333333333333333333333",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], WalletLocked)
