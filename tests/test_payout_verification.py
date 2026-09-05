from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db import get_db
from app.services.payout_verification import (
    TRANSFER_TOPIC,
    VerificationResult,
    apply_payout_verification,
    submit_payout_transaction,
    verify_bsc_payout,
)
from app.services.payouts import approve_payout, request_payout
from app.services.proxies import add_proxy
from app.services.users import create_user
from app.services.wallets import set_wallet

USDT = "0x55d398326f99059ff775485246999027b3197955"
WALLET = "0x1111111111111111111111111111111111111111"
TX_HASH = "0x" + "ab" * 32


def _topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def _rpc(receipt, *, current_block: int = 110, chain_id: int = 56):
    def call(method: str, _params: list):
        if method == "eth_chainId":
            return hex(chain_id)
        if method == "eth_getTransactionReceipt":
            return receipt
        if method == "eth_blockNumber":
            return hex(current_block)
        raise AssertionError(method)

    return call


def _receipt(*, recipient: str = WALLET, amount_units: int = 1_500_000 * 10**12, contract: str = USDT):
    return {
        "status": "0x1",
        "blockNumber": hex(100),
        "logs": [
            {
                "address": contract,
                "topics": [
                    TRANSFER_TOPIC,
                    _topic_address("0x2222222222222222222222222222222222222222"),
                    _topic_address(recipient),
                ],
                "data": hex(amount_units),
            }
        ],
    }


def _payout():
    return {"tx_hash": TX_HASH, "wallet_address": WALLET, "amount_micro_usd": 1_500_000}


def test_valid_bsc_usdt_transfer_is_confirmed_after_required_depth():
    result = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=10,
        rpc_call=_rpc(_receipt()),
    )

    assert result.status == "confirmed"
    assert result.confirmations == 11
    assert result.block_number == 100


def test_fee_bearing_payout_verifies_the_net_transfer_amount():
    payout = {
        "tx_hash": TX_HASH,
        "wallet_address": WALLET,
        "amount_micro_usd": 10_000_000,
        "net_micro_usd": 9_000_000,
    }
    result = verify_bsc_payout(
        payout,
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=10,
        rpc_call=_rpc(_receipt(amount_units=9_000_000 * 10**12)),
    )

    assert result.status == "confirmed"


@pytest.mark.parametrize(
    ("receipt", "error"),
    [
        ({"status": "0x0", "blockNumber": "0x64", "logs": []}, "reverted"),
        (_receipt(contract="0x3333333333333333333333333333333333333333"), "contract"),
        (_receipt(recipient="0x4444444444444444444444444444444444444444"), "recipient"),
        (_receipt(amount_units=1_400_000 * 10**12), "amount"),
    ],
)
def test_finalized_wrong_transaction_is_failed(receipt, error):
    result = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=5,
        rpc_call=_rpc(receipt),
    )

    assert result.status == "failed"
    assert error in result.error.lower()


def test_pending_receipt_or_insufficient_confirmations_stays_retryable():
    missing = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=5,
        rpc_call=_rpc(None),
    )
    shallow = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=15,
        rpc_call=_rpc(_receipt()),
    )
    assert missing.status == "pending"
    assert shallow.status == "pending"
    assert shallow.confirmations == 11


def test_rpc_and_wrong_chain_errors_do_not_false_fail_a_payout():
    def broken(_method, _params):
        raise RuntimeError("provider unavailable")

    rpc_error = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=5,
        rpc_call=broken,
    )
    wrong_chain = verify_bsc_payout(
        _payout(),
        rpc_url="https://rpc.example",
        token_contract=USDT,
        token_decimals=18,
        min_confirmations=5,
        rpc_call=_rpc(_receipt(), chain_id=1),
    )
    assert rpc_error.status == "pending"
    assert wrong_chain.status == "pending"


def test_rpc_url_must_be_https_and_resolve_only_to_public_addresses(monkeypatch):
    from app.services import payout_verification as module

    with pytest.raises(ValueError):
        module._validate_rpc_url("http://rpc.example")
    monkeypatch.setattr(
        module, "resolve_public_proxy_host", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError())
    )
    with pytest.raises(ValueError):
        module._validate_rpc_url("https://rpc.example")


def test_rpc_transport_pins_public_ip_and_preserves_tls_hostname(monkeypatch):
    from app.services import payout_verification as module

    calls = {}

    class Response:
        data = b'{"jsonrpc":"2.0","id":1,"result":"0x38"}'
        headers = {"Content-Type": "application/json"}
        status = 200

        def read(self, amount, **_kwargs):
            calls["read_amount"] = amount
            return self.data

        def close(self):
            calls["response_closed"] = True

    class Pool:
        def __init__(self, host, port, **kwargs):
            calls["pool"] = (host, port, kwargs)

        def urlopen(self, method, path, **kwargs):
            calls["request"] = (method, path, kwargs)
            return Response()

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(module, "resolve_public_proxy_host", lambda *_args, **_kwargs: "203.0.113.10")
    monkeypatch.setattr(module.urllib3, "HTTPSConnectionPool", Pool)

    assert module._http_rpc_call("https://rpc.example/custom", "eth_chainId", []) == "0x38"
    assert calls["pool"][0] == "203.0.113.10"
    assert calls["pool"][2]["assert_hostname"] == "rpc.example"
    assert calls["pool"][2]["server_hostname"] == "rpc.example"
    assert calls["request"][1] == "/custom"
    assert calls["request"][2]["headers"]["Host"] == "rpc.example"
    assert calls["request"][2]["redirect"] is False
    assert calls["request"][2]["retries"] is False
    assert calls["request"][2]["preload_content"] is False
    assert calls["read_amount"] == module.MAX_RPC_BODY_BYTES + 1
    assert calls["response_closed"] is True
    assert calls["closed"] is True


def _approved_payout(db, *, email: str, proxy: str, wallet: str, now: datetime) -> int:
    user_id = create_user(db, email, "password", status="active")
    proxy_id = add_proxy(db, user_id, proxy)
    set_wallet(db, user_id, wallet, now=now - timedelta(hours=49))
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
    return payout_id


def test_submit_transaction_requires_valid_unique_hash_and_moves_to_verifying(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        first = _approved_payout(db, email="verify-a@example.com", proxy="a.example:9000:u:p", wallet=WALLET, now=now)
        second = _approved_payout(
            db,
            email="verify-b@example.com",
            proxy="b.example:9000:u:p",
            wallet="0x3333333333333333333333333333333333333333",
            now=now,
        )
        with pytest.raises(ValueError):
            submit_payout_transaction(db, first, "0xshort", now=now)
        submit_payout_transaction(db, first, TX_HASH.upper().replace("0X", "0x"), now=now)
        with pytest.raises(ValueError):
            submit_payout_transaction(db, second, TX_HASH, now=now)
        row = db.execute("SELECT * FROM payouts WHERE id=?", (first,)).fetchone()

    assert row["status"] == "verifying"
    assert row["tx_hash"] == TX_HASH
    assert row["next_verification_at"] == now.isoformat()


def test_duplicate_transaction_hash_is_case_insensitive_and_never_leaks_sqlite_error(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        first = _approved_payout(
            db,
            email="case-duplicate-a@example.com",
            proxy="case-duplicate-a.example:9000:u:p",
            wallet=WALLET,
            now=now,
        )
        second = _approved_payout(
            db,
            email="case-duplicate-b@example.com",
            proxy="case-duplicate-b.example:9000:u:p",
            wallet="0x3333333333333333333333333333333333333333",
            now=now,
        )
        submit_payout_transaction(db, first, TX_HASH, now=now)
        db.execute("UPDATE payouts SET tx_hash=? WHERE id=?", (TX_HASH.upper().replace("0X", "0x"), first))
        db.commit()

        with pytest.raises(ValueError, match="already assigned"):
            submit_payout_transaction(db, second, TX_HASH, now=now)


def test_admin_can_replace_a_stuck_verifying_transaction(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    replacement = "0x" + "cd" * 32
    with app.app_context():
        db = get_db()
        payout_id = _approved_payout(
            db,
            email="replace-stuck@example.com",
            proxy="replace-stuck.example:9000:u:p",
            wallet=WALLET,
            now=now,
        )
        submit_payout_transaction(db, payout_id, TX_HASH, now=now)
        db.execute(
            "UPDATE payouts SET verification_claim_token='old-claim', verification_claimed_until=? WHERE id=?",
            ((now + timedelta(minutes=5)).isoformat(), payout_id),
        )
        db.commit()

        submit_payout_transaction(db, payout_id, replacement, now=now + timedelta(minutes=1))
        row = db.execute("SELECT * FROM payouts WHERE id=?", (payout_id,)).fetchone()

    assert row["status"] == "verifying"
    assert row["tx_hash"] == replacement
    assert row["verification_claim_token"] is None
    assert row["verification_claimed_until"] is None


def test_retrying_failed_payout_cannot_over_reserve_available_balance(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    replacement = "0x" + "cd" * 32
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "retry-reservation@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "retry-reservation.example:9000:u:p")
        set_wallet(db, user_id, WALLET, now=now - timedelta(hours=49))
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "VALUES(?,?,?, ?,?,'available',?)",
            (
                user_id,
                proxy_id,
                (now - timedelta(hours=3)).isoformat(),
                (now - timedelta(hours=2)).isoformat(),
                19_000_000,
                now.isoformat(),
            ),
        )
        db.commit()

        first = request_payout(db, user_id, 10_000_000, now=now)
        approve_payout(db, first, now=now)
        submit_payout_transaction(db, first, TX_HASH, now=now)
        apply_payout_verification(db, first, VerificationResult("failed", "wrong recipient"), now=now)

        second = request_payout(db, user_id, 10_000_000, now=now)
        with pytest.raises(ValueError, match="available balance"):
            submit_payout_transaction(db, first, replacement, now=now + timedelta(minutes=1))

        rows = db.execute("SELECT id, status FROM payouts WHERE user_id=? ORDER BY id", (user_id,)).fetchall()

    assert [(row["id"], row["status"]) for row in rows] == [(first, "failed"), (second, "requested")]


def test_apply_verification_result_is_the_only_path_to_confirmed_or_failed(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        payout_id = _approved_payout(
            db,
            email="state@example.com",
            proxy="state.example:9000:u:p",
            wallet=WALLET,
            now=now,
        )
        submit_payout_transaction(db, payout_id, TX_HASH, now=now)
        apply_payout_verification(
            db,
            payout_id,
            VerificationResult("confirmed", confirmations=12, block_number=100),
            now=now + timedelta(minutes=1),
        )
        row = db.execute("SELECT * FROM payouts WHERE id=?", (payout_id,)).fetchone()

    assert row["status"] == "confirmed"
    assert row["verified_at"]
    assert row["confirmations"] == 12


def test_stale_verifier_claim_cannot_apply_result(app):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        payout_id = _approved_payout(
            db,
            email="claim-race@example.com",
            proxy="claim-race.example:9000:u:p",
            wallet=WALLET,
            now=now,
        )
        submit_payout_transaction(db, payout_id, TX_HASH, now=now)
        db.execute(
            "UPDATE payouts SET verification_claim_token='new-worker' WHERE id=?",
            (payout_id,),
        )
        db.commit()

        with pytest.raises(LookupError):
            apply_payout_verification(
                db,
                payout_id,
                VerificationResult("confirmed", confirmations=12, block_number=100),
                claim_token="stale-worker",
                now=now + timedelta(minutes=1),
            )
        row = db.execute("SELECT status,verification_claim_token FROM payouts WHERE id=?", (payout_id,)).fetchone()

    assert row["status"] == "verifying"
    assert row["verification_claim_token"] == "new-worker"
