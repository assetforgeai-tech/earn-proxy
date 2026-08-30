from __future__ import annotations

from datetime import UTC, datetime

from app.services.earnings import balances_for_user


def request_payout(db, user_id: int, amount_micro_usd: int, *, now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    amount = int(amount_micro_usd)
    if amount <= 0:
        raise ValueError("Payout amount must be positive")
    try:
        # Serialize balance validation and reservation so simultaneous requests
        # cannot each observe the same unreserved funds.
        db.execute("BEGIN IMMEDIATE")
        wallet = db.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,)).fetchone()
        if wallet is None:
            raise ValueError("Set a wallet before requesting payout")
        locked_until = datetime.fromisoformat(wallet["locked_until"])
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        if locked_until > current:
            raise ValueError("Wallet is still under the 48-hour security lock")
        available = balances_for_user(db, user_id).available_micro_usd
        reserved = db.execute(
            "SELECT COALESCE(SUM(amount_micro_usd),0) AS total FROM payouts WHERE user_id=? AND status IN ('requested','approved','sent')",
            (user_id,),
        ).fetchone()["total"]
        if amount > available - int(reserved):
            raise ValueError("Payout amount exceeds available balance")
        cursor = db.execute(
            "INSERT INTO payouts(user_id,wallet_id,wallet_address,amount_micro_usd,status,created_at,updated_at) VALUES(?,?,?,?,'requested',?,?)",
            (user_id, wallet["id"], wallet["address"], amount, current.isoformat(), current.isoformat()),
        )
        db.commit()
        return int(cursor.lastrowid)
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise


def approve_payout(db, payout_id: int, *, now: datetime | None = None) -> None:
    """Move a requested payout into the administrator-approved state."""
    current = now or datetime.now(UTC)
    cursor = db.execute(
        "UPDATE payouts SET status='approved', updated_at=? WHERE id=? AND status='requested'",
        (current.isoformat(), payout_id),
    )
    if cursor.rowcount != 1:
        raise LookupError("Payout not found or not awaiting approval")
    db.commit()


def mark_payout_sent(db, payout_id: int, tx_hash: str, *, now: datetime | None = None) -> None:
    value = str(tx_hash or "").strip()
    if not value:
        raise ValueError("Transaction hash is required")
    cursor = db.execute(
        "UPDATE payouts SET status='sent', tx_hash=?, updated_at=? WHERE id=? AND status='approved'",
        (value, (now or datetime.now(UTC)).isoformat(), payout_id),
    )
    if cursor.rowcount != 1:
        raise LookupError("Payout not found or already completed")
    db.commit()
