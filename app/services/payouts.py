from __future__ import annotations

from datetime import UTC, datetime

from app.services.earnings import balances_for_user

DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER = 10
MAX_MAX_OUTSTANDING_PAYOUTS_PER_USER = 1_000
NONTERMINAL_PAYOUT_STATUSES = ("requested", "approved", "verifying")
MAX_PAYOUT_MICRO_USD = 10**15


class PayoutQuotaExceeded(ValueError):
    """Raised when a user already has the maximum number of queued payouts."""


def _outstanding_limit(value: int | None) -> int:
    try:
        parsed = int(value if value is not None else DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER)
    except (TypeError, ValueError):
        parsed = DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER
    return max(1, min(MAX_MAX_OUTSTANDING_PAYOUTS_PER_USER, parsed))


def request_payout(
    db,
    user_id: int,
    amount_micro_usd: int,
    *,
    now: datetime | None = None,
    max_outstanding_payouts: int | None = None,
) -> int:
    current = now or datetime.now(UTC)
    amount = int(amount_micro_usd)
    if amount <= 0:
        raise ValueError("Payout amount must be positive")
    if amount > MAX_PAYOUT_MICRO_USD:
        raise ValueError("Payout amount is above the supported maximum")
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
        limit = _outstanding_limit(max_outstanding_payouts)
        placeholders = ",".join("?" for _ in NONTERMINAL_PAYOUT_STATUSES)
        outstanding = db.execute(
            f"SELECT COUNT(*) AS count FROM payouts WHERE user_id=? AND status IN ({placeholders})",
            (user_id, *NONTERMINAL_PAYOUT_STATUSES),
        ).fetchone()["count"]
        if int(outstanding) >= limit:
            raise PayoutQuotaExceeded(
                f"Maximum number of outstanding payouts reached ({limit}); wait for processing before requesting another payout"
            )
        available = balances_for_user(db, user_id).available_micro_usd
        reserved = db.execute(
            "SELECT COALESCE(SUM(amount_micro_usd),0) AS total FROM payouts WHERE user_id=? "
            "AND status IN ('requested','approved','verifying','confirmed','sent')",
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
    """Compatibility name: submit a transaction for independent verification."""
    from app.services.payout_verification import submit_payout_transaction

    submit_payout_transaction(db, payout_id, tx_hash, now=now)
