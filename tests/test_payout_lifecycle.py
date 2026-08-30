from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.payouts import approve_payout, mark_payout_sent, request_payout
from app.services.proxies import add_proxy
from app.services.users import create_user
from app.services.wallets import set_wallet


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
                1_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        payout_id = request_payout(db, user_id, 500_000, now=now)
        try:
            mark_payout_sent(db, payout_id, "0xnot-approved", now=now)
        except LookupError:
            pass
        else:
            raise AssertionError("Unapproved payout was marked sent")
        approve_payout(db, payout_id, now=now)
        mark_payout_sent(db, payout_id, "0xapproved", now=now)
        row = db.execute("SELECT status, tx_hash FROM payouts WHERE id=?", (payout_id,)).fetchone()
    assert (row["status"], row["tx_hash"]) == ("sent", "0xapproved")


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
                1_000_000,
                now.isoformat(),
            ),
        )
        db.commit()
        payout_id = request_payout(db, user_id, 500_000, now=now)
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
                1_000_000,
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
                results.append(request_payout(get_db(), user_id, 700_000, now=now))
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
    assert total <= 1_000_000
