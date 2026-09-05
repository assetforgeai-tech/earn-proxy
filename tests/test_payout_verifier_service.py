from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.payout_verifier_service import PayoutVerifierRunner
from app.services.payout_verification import VerificationResult, submit_payout_transaction
from app.services.payouts import approve_payout, request_payout
from app.services.proxies import add_proxy
from app.services.users import create_user
from app.services.wallets import set_wallet

TX_HASH = "0x" + "ab" * 32
USDT = "0x55d398326f99059ff775485246999027b3197955"


def _verifying_payout(app, *, now: datetime) -> int:
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "worker-payout@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "worker-payout.example:9000:u:p")
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
        approve_payout(db, payout_id, now=now)
        submit_payout_transaction(db, payout_id, TX_HASH, now=now)
        return payout_id


def test_runner_claims_due_payout_and_applies_confirmed_result(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    payout_id = _verifying_payout(app, now=now)
    runner = PayoutVerifierRunner(
        app=app,
        rpc_url="https://rpc.example",
        verifier=lambda payout, **_kwargs: VerificationResult("confirmed", confirmations=12, block_number=100),
    )

    assert runner.run_batch(now=now) == 1
    with app.app_context():
        row = get_db().execute("SELECT * FROM payouts WHERE id=?", (payout_id,)).fetchone()
    assert row["status"] == "confirmed"
    assert row["verification_claim_token"] is None


def test_runner_pending_result_schedules_retry_and_releases_claim(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    payout_id = _verifying_payout(app, now=now)
    runner = PayoutVerifierRunner(
        app=app,
        rpc_url="https://rpc.example",
        verifier=lambda payout, **_kwargs: VerificationResult("pending", "receipt missing"),
    )

    assert runner.run_batch(now=now) == 1
    with app.app_context():
        row = get_db().execute("SELECT * FROM payouts WHERE id=?", (payout_id,)).fetchone()
    assert row["status"] == "verifying"
    assert datetime.fromisoformat(row["next_verification_at"]) > now
    assert row["verification_claim_token"] is None


def test_runner_without_rpc_configuration_leaves_due_rows_unclaimed(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    payout_id = _verifying_payout(app, now=now)
    runner = PayoutVerifierRunner(app=app, rpc_url="")

    assert runner.run_batch(now=now) == 0
    with app.app_context():
        row = (
            get_db().execute("SELECT status, verification_claim_token FROM payouts WHERE id=?", (payout_id,)).fetchone()
        )
    assert row["status"] == "verifying"
    assert row["verification_claim_token"] is None


def test_runner_reclaims_an_expired_durable_claim(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    payout_id = _verifying_payout(app, now=now)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE payouts SET verification_claimed_until=?, verification_claim_token='stale' WHERE id=?",
            ((now - timedelta(minutes=1)).isoformat(), payout_id),
        )
        db.commit()
    runner = PayoutVerifierRunner(
        app=app,
        rpc_url="https://rpc.example",
        verifier=lambda payout, **_kwargs: VerificationResult("confirmed", confirmations=12, block_number=100),
    )

    assert runner.run_batch(now=now) == 1


def test_runner_passes_claim_token_to_atomic_apply(app, monkeypatch):
    from app import payout_verifier_service as module

    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    payout_id = _verifying_payout(app, now=now)
    observed = {}

    def apply(db, applied_payout_id, result, *, claim_token, now):
        observed.update(
            payout_id=applied_payout_id,
            result=result,
            claim_token=claim_token,
            now=now,
        )
        db.execute(
            "UPDATE payouts SET status='confirmed', verification_claim_token=NULL, verification_claimed_until=NULL "
            "WHERE id=? AND verification_claim_token=?",
            (applied_payout_id, claim_token),
        )
        db.commit()

    monkeypatch.setattr(module, "apply_payout_verification", apply)
    runner = PayoutVerifierRunner(
        app=app,
        rpc_url="https://rpc.example",
        token_contract=USDT,
        verifier=lambda payout, **_kwargs: VerificationResult("confirmed", confirmations=12, block_number=100),
    )

    assert runner.run_batch(now=now) == 1
    assert observed["payout_id"] == payout_id
    assert observed["claim_token"]
