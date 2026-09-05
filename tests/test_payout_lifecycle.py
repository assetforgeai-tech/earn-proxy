from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.services import payouts as payout_service
from app.services.payout_verification import VerificationResult, apply_payout_verification
from app.services.payouts import approve_payout, mark_payout_sent, request_payout
from app.services.proxies import add_proxy
from app.services.users import create_user
from app.services.wallets import set_wallet


def test_payout_quote_applies_minimum_and_fee_tier_boundaries():
    minimum = 10_000_000
    low_fee = 1_000
    high_fee = 200
    with pytest.raises(ValueError, match="minimum payout"):
        payout_service.quote_payout(minimum - 1)

    low = payout_service.quote_payout(minimum)
    boundary = payout_service.quote_payout(49_999_999)
    high = payout_service.quote_payout(50_000_000)

    assert low.fee_bps == low_fee
    assert low.fee_micro_usd == 1_000_000
    assert low.net_micro_usd == 9_000_000
    assert boundary.fee_bps == low_fee
    assert high.fee_bps == high_fee
    assert high.fee_micro_usd == 1_000_000
    assert high.net_micro_usd == 49_000_000


def test_payout_request_snapshots_fee_net_and_processing_deadline(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "fee-snapshot@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "fee-snapshot.example:9000:u:p")
        set_wallet(db, user_id, "0x1111111111111111111111111111111111111111", now=now - timedelta(hours=49))
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                20_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        payout_id = request_payout(db, user_id, 10_000_000, now=now)
        row = db.execute(
            "SELECT amount_micro_usd, fee_bps, fee_micro_usd, net_micro_usd, processing_due_at FROM payouts WHERE id=?",
            (payout_id,),
        ).fetchone()

    assert row["amount_micro_usd"] == 10_000_000
    assert row["fee_bps"] == 1_000
    assert row["fee_micro_usd"] == 1_000_000
    assert row["net_micro_usd"] == 9_000_000
    assert row["processing_due_at"] == (now + timedelta(hours=48)).isoformat()


def test_payout_requires_admin_approval_before_marking_sent(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "proxy.example:9000:u:p")
        set_wallet(
            db,
            user_id,
            "0x1111111111111111111111111111111111111111",
            now=now - timedelta(hours=49),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                20_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        payout_id = request_payout(db, user_id, 10_000_000, now=now)
        tx_hash = "0x" + "ab" * 32
        try:
            mark_payout_sent(db, payout_id, tx_hash, now=now)
        except LookupError:
            pass
        else:
            raise AssertionError("Unapproved payout was submitted for verification")
        approve_payout(db, payout_id, now=now)
        mark_payout_sent(db, payout_id, tx_hash, now=now)
        row = db.execute("SELECT status, tx_hash FROM payouts WHERE id=?", (payout_id,)).fetchone()
    assert (row["status"], row["tx_hash"]) == ("verifying", tx_hash)


def test_payout_keeps_the_wallet_address_that_was_requested(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    first_address = "0x1111111111111111111111111111111111111111"
    second_address = "0x2222222222222222222222222222222222222222"
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "wallet-snapshot@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "snapshot.example:9000:u:p")
        set_wallet(db, user_id, first_address, now=now - timedelta(hours=49))
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                20_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        payout_id = request_payout(db, user_id, 10_000_000, now=now)
        set_wallet(db, user_id, second_address, now=now + timedelta(hours=49))
        payout = db.execute("SELECT wallet_address FROM payouts WHERE id=?", (payout_id,)).fetchone()

    assert payout["wallet_address"] == first_address


def test_concurrent_payout_requests_cannot_reserve_more_than_available(app, monkeypatch):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "race@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "race.example:9000:u:p")
        set_wallet(
            db,
            user_id,
            "0x3333333333333333333333333333333333333333",
            now=now - timedelta(hours=49),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                20_000_000,
                now.isoformat(),
            ),
        )
        db.commit()

    barrier = threading.Barrier(2)
    results: list[int] = []
    errors: list[Exception] = []

    def request_from_second_session():
        barrier.wait(timeout=5)
        with app.app_context():
            try:
                results.append(request_payout(get_db(), user_id, 14_000_000, now=now))
            except Exception as exc:  # noqa: BLE001 - assert one request is rejected
                errors.append(exc)

    threads = [threading.Thread(target=request_from_second_session) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    with app.app_context():
        total = (
            get_db()
            .execute(
                "SELECT COALESCE(SUM(amount_micro_usd), 0) AS total FROM payouts WHERE user_id=?",
                (user_id,),
            )
            .fetchone()["total"]
        )
    assert len(results) == 1
    assert len(errors) == 1
    assert total <= 20_000_000


def test_nonterminal_payout_request_cap_rejects_new_rows_but_terminal_rows_do_not_count(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "payout-cap@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "payout-cap.example:9000:u:p")
        set_wallet(
            db,
            user_id,
            "0x4444444444444444444444444444444444444444",
            now=now - timedelta(hours=49),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                30_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        first = request_payout(db, user_id, 10_000_000, now=now, max_outstanding_payouts=1)
        with pytest.raises(ValueError, match="Maximum number of outstanding payouts"):
            request_payout(db, user_id, 10_000_000, now=now, max_outstanding_payouts=1)

        # Historical terminal payouts remain durable but must not consume the
        # queue-slot cap once they are confirmed.
        db.execute("UPDATE payouts SET status='confirmed' WHERE id=?", (first,))
        db.commit()
        second = request_payout(db, user_id, 10_000_000, now=now, max_outstanding_payouts=1)

    assert second != first


def test_failed_payout_releases_nonterminal_request_slot(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    tx_hash = "0x" + "cd" * 32
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "payout-failed-cap@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "payout-failed-cap.example:9000:u:p")
        set_wallet(
            db,
            user_id,
            "0x5555555555555555555555555555555555555555",
            now=now - timedelta(hours=49),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                20_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        first = request_payout(db, user_id, 10_000_000, now=now, max_outstanding_payouts=1)
        approve_payout(db, first, now=now)
        mark_payout_sent(db, first, tx_hash, now=now)
        apply_payout_verification(
            db,
            first,
            VerificationResult("failed", "wrong recipient"),
            now=now + timedelta(minutes=1),
        )
        second = request_payout(db, user_id, 10_000_000, now=now + timedelta(minutes=2), max_outstanding_payouts=1)

    assert second != first
