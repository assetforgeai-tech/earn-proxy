from __future__ import annotations

import argparse
import signal
import threading
from datetime import UTC, datetime, timedelta

from app import create_app
from app.db import get_db
from app.services.payout_verification import apply_payout_verification, verify_bsc_payout

DEFAULT_INTERVAL_SECONDS = 60
CLAIM_MINUTES = 5


class PayoutVerifierRunner:
    def __init__(
        self,
        *,
        app=None,
        rpc_url: str | None = None,
        token_contract: str | None = None,
        token_decimals: int | None = None,
        min_confirmations: int | None = None,
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
        verifier=verify_bsc_payout,
    ):
        self.app = app
        config = app.config if app is not None else {}
        self.rpc_url = str(rpc_url if rpc_url is not None else config.get("BSC_RPC_URL") or "").strip()
        self.token_contract = str(
            token_contract if token_contract is not None else config.get("BSC_USDT_CONTRACT") or ""
        ).strip()
        self.token_decimals = int(token_decimals if token_decimals is not None else config.get("BSC_USDT_DECIMALS", 18))
        self.min_confirmations = int(
            min_confirmations if min_confirmations is not None else config.get("BSC_MIN_CONFIRMATIONS", 12)
        )
        self.interval_seconds = max(15, min(3600, int(interval_seconds)))
        self.verifier = verifier
        self._stop = threading.Event()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def _claim_one(db, now: datetime):
        db.execute("BEGIN IMMEDIATE")
        try:
            row = db.execute(
                """
                SELECT * FROM payouts
                WHERE status='verifying'
                  AND (next_verification_at IS NULL OR next_verification_at <= ?)
                  AND (verification_claimed_until IS NULL OR verification_claimed_until <= ?)
                ORDER BY COALESCE(next_verification_at, created_at), id
                LIMIT 1
                """,
                (now.isoformat(), now.isoformat()),
            ).fetchone()
            if row is None:
                db.commit()
                return None
            import secrets

            token = secrets.token_urlsafe(24)
            claimed_until = now + timedelta(minutes=CLAIM_MINUTES)
            cursor = db.execute(
                """
                UPDATE payouts SET verification_claimed_until=?, verification_claim_token=?
                WHERE id=? AND status='verifying'
                  AND (verification_claimed_until IS NULL OR verification_claimed_until <= ?)
                """,
                (claimed_until.isoformat(), token, row["id"], now.isoformat()),
            )
            if cursor.rowcount != 1:
                db.rollback()
                return None
            db.commit()
            return db.execute("SELECT * FROM payouts WHERE id=?", (row["id"],)).fetchone()
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise

    @staticmethod
    def _release_claim(db, payout_id: int, claim_token: str) -> None:
        db.execute(
            """
            UPDATE payouts SET verification_claimed_until=NULL, verification_claim_token=NULL
            WHERE id=? AND verification_claim_token=? AND status='verifying'
            """,
            (int(payout_id), str(claim_token or "")),
        )
        db.commit()

    def run_batch(self, *, now: datetime | None = None) -> int:
        if self.app is None or not self.rpc_url or not self.token_contract:
            return 0
        current = now or datetime.now(UTC)
        with self.app.app_context():
            db = get_db()
            row = self._claim_one(db, current)
            if row is None:
                return 0
            payout_id = int(row["id"])
            claim_token = str(row["verification_claim_token"] or "")
            try:
                result = self.verifier(
                    row,
                    rpc_url=self.rpc_url,
                    token_contract=self.token_contract,
                    token_decimals=self.token_decimals,
                    min_confirmations=self.min_confirmations,
                )
                apply_payout_verification(db, payout_id, result, claim_token=claim_token, now=current)
            except Exception:
                # Preserve the durable row for a later retry. The external RPC
                # error itself is handled by the verifier as a pending result;
                # this catch protects against unexpected worker failures.
                self._release_claim(db, payout_id, claim_token)
                raise
        return 1

    def run_forever(self) -> None:
        while not self.stopped:
            self.run_batch()
            self._stop.wait(self.interval_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify submitted USDT BEP20 payout transactions")
    parser.add_argument("--once", action="store_true", help="Run one verifier batch and exit")
    parser.add_argument("--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS)
    args = parser.parse_args()
    runner = PayoutVerifierRunner(app=create_app(), interval_seconds=args.interval_seconds)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_batch()
        return 0
    runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
