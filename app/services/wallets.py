from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


class WalletInUse(ValueError):
    pass


class WalletLocked(ValueError):
    pass


@dataclass(frozen=True)
class Wallet:
    address: str
    locked_until: str


def set_wallet(db, user_id: int, address: str, *, now: datetime | None = None) -> Wallet:
    current = now or datetime.now(UTC)
    normalized = str(address or "").strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", normalized):
        raise ValueError("Wallet must be a valid USDT BEP20 address")
    existing = db.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,)).fetchone()
    if existing and _as_utc(datetime.fromisoformat(existing["locked_until"])) > current:
        raise WalletLocked("Wallet cannot be changed during the 48-hour security lock")
    conflict = db.execute(
        """
        SELECT w.user_id FROM wallets w JOIN users u ON u.id=w.user_id
        WHERE lower(w.address)=? AND w.user_id<>? AND u.status IN ('pending','active')
        """,
        (normalized, user_id),
    ).fetchone()
    if conflict:
        raise WalletInUse("Wallet is already assigned to another active account")
    # Inactive accounts no longer reserve a wallet address. Preserve their
    # payout history by removing only wallets that have never been referenced.
    stale = db.execute(
        """
        SELECT w.id FROM wallets w JOIN users u ON u.id=w.user_id
        WHERE lower(w.address)=? AND w.user_id<>? AND u.status NOT IN ('pending','active')
          AND NOT EXISTS (SELECT 1 FROM payouts p WHERE p.wallet_id=w.id)
        """,
        (normalized, user_id),
    ).fetchall()
    if stale:
        db.executemany("DELETE FROM wallets WHERE id=?", [(row["id"],) for row in stale])
    locked_until = current + timedelta(hours=48)
    try:
        db.execute(
            """
            INSERT INTO wallets(user_id, address, locked_until, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET address=excluded.address,
                locked_until=excluded.locked_until, updated_at=excluded.updated_at
            """,
            (user_id, normalized, locked_until.isoformat(), current.isoformat()),
        )
    except sqlite3.IntegrityError:
        db.rollback()
        raise WalletInUse("Wallet is retained by an inactive account's payout history") from None
    db.commit()
    return Wallet(normalized, locked_until.isoformat())


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
