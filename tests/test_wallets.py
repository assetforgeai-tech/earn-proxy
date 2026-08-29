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
