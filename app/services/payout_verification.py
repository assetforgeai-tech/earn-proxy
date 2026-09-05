from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import requests
import urllib3

from app.network_safety import resolve_public_proxy_host
from app.services.earnings import balances_for_user

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}\Z")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
EXPECTED_CHAIN_ID = 56
DEFAULT_RETRY_MINUTES = 5
MAX_RPC_BODY_BYTES = 1_000_000


@dataclass(frozen=True)
class VerificationResult:
    status: str
    error: str = ""
    confirmations: int = 0
    block_number: int | None = None


def normalize_tx_hash(value: str) -> str:
    text = str(value or "").strip().lower()
    if not TX_HASH_RE.fullmatch(text):
        raise ValueError("Transaction hash must be a 32-byte 0x-prefixed hexadecimal value")
    return text


def _normalize_address(value: str, *, label: str) -> str:
    text = str(value or "").strip().lower()
    if not ADDRESS_RE.fullmatch(text):
        raise ValueError(f"{label} must be a valid EVM address")
    return text


def _parse_quantity(value, *, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"RPC returned an invalid {label}")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise ValueError(f"RPC returned an invalid {label}") from exc
    if parsed < 0:
        raise ValueError(f"RPC returned an invalid {label}")
    return parsed


def _topic_to_address(value: str) -> str | None:
    text = str(value or "").lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}", text):
        return None
    address = "0x" + text[-40:]
    return address if ADDRESS_RE.fullmatch(address) else None


def _rpc_target(value: str) -> tuple[str, str, int, str, str]:
    parsed = urlparse(str(value or "").strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("BSC RPC URL must be an HTTPS endpoint without embedded credentials")
    if parsed.fragment:
        raise ValueError("BSC RPC URL must not contain a fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    port = parsed.port or 443
    try:
        pinned_address = resolve_public_proxy_host(hostname, port)
    except ValueError as exc:
        raise ValueError("BSC RPC URL must resolve only to public IP addresses") from exc
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port != 443:
        host_header = f"{host_header}:{port}"
    return pinned_address, hostname, port, path, host_header


def _validate_rpc_url(value: str) -> str:
    _rpc_target(value)
    return urlparse(str(value or "").strip()).geturl()


def _http_rpc_call(rpc_url: str, method: str, params: list, *, timeout: float = 8.0):
    pinned_address, hostname, port, path, host_header = _rpc_target(rpc_url)
    read_timeout = min(15.0, max(1.0, float(timeout)))
    pool = urllib3.HTTPSConnectionPool(
        pinned_address,
        port,
        assert_hostname=hostname,
        server_hostname=hostname,
        cert_reqs="CERT_REQUIRED",
        timeout=urllib3.Timeout(connect=3.0, read=read_timeout),
        maxsize=1,
        block=True,
    )
    response = None
    try:
        response = pool.urlopen(
            "POST",
            path,
            body=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Host": host_header,
            },
            redirect=False,
            retries=False,
            preload_content=False,
        )
        try:
            content_length = int(response.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            content_length = 0
        if content_length > MAX_RPC_BODY_BYTES:
            raise RuntimeError("RPC response is too large")
        if not 200 <= int(response.status) < 300:
            raise RuntimeError(f"RPC returned HTTP {int(response.status)}")
        if hasattr(response, "read"):
            content = response.read(MAX_RPC_BODY_BYTES + 1, decode_content=True)
        else:
            content = response.data
        if len(content) > MAX_RPC_BODY_BYTES:
            raise RuntimeError("RPC response is too large")
        try:
            payload = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("RPC returned invalid JSON") from exc
    finally:
        if response is not None:
            response.close()
        pool.close()
    if not isinstance(payload, dict) or payload.get("error") is not None or "result" not in payload:
        raise RuntimeError("RPC returned an error")
    return payload["result"]


def verify_bsc_payout(
    payout,
    *,
    rpc_url: str,
    token_contract: str,
    token_decimals: int,
    min_confirmations: int,
    rpc_call=None,
) -> VerificationResult:
    try:
        tx_hash = normalize_tx_hash(payout["tx_hash"])
        destination = _normalize_address(payout["wallet_address"], label="Payout wallet")
        contract = _normalize_address(token_contract, label="USDT contract")
        decimals = int(token_decimals)
        if decimals < 0 or decimals > 36:
            raise ValueError("Token decimals are outside the supported range")
        confirmations_required = max(1, min(1000, int(min_confirmations)))
        call = rpc_call or (lambda method, params: _http_rpc_call(rpc_url, method, params))
        chain_id = _parse_quantity(call("eth_chainId", []), label="chain id")
        if chain_id != EXPECTED_CHAIN_ID:
            return VerificationResult("pending", "RPC endpoint is not BNB Smart Chain")
        receipt = call("eth_getTransactionReceipt", [tx_hash])
        if receipt is None:
            return VerificationResult("pending", "Transaction receipt is not available yet")
        if not isinstance(receipt, dict):
            return VerificationResult("pending", "RPC returned an invalid receipt")
        status = _parse_quantity(receipt.get("status"), label="receipt status")
        block_number = _parse_quantity(receipt.get("blockNumber"), label="receipt block")
        current_block = _parse_quantity(call("eth_blockNumber", []), label="current block")
        confirmations = max(0, current_block - block_number + 1)
        if status != 1:
            return VerificationResult("failed", "Transaction reverted on-chain", confirmations, block_number)
        if confirmations < confirmations_required:
            return VerificationResult(
                "pending",
                f"Waiting for {confirmations_required} confirmations",
                confirmations,
                block_number,
            )
        try:
            transfer_micro_usd = int(payout["net_micro_usd"])
        except (KeyError, IndexError, TypeError, ValueError):
            transfer_micro_usd = int(payout["amount_micro_usd"])
        if transfer_micro_usd <= 0:
            transfer_micro_usd = int(payout["amount_micro_usd"])
        expected_units = transfer_micro_usd * (10**decimals) // 1_000_000
        matching_contract = False
        matching_recipient = False
        for log in receipt.get("logs") or []:
            if not isinstance(log, dict):
                continue
            topics = log.get("topics")
            try:
                log_contract = _normalize_address(log.get("address"), label="Log contract")
            except ValueError:
                continue
            if log_contract != contract:
                continue
            matching_contract = True
            if not isinstance(topics, list) or len(topics) < 3 or str(topics[0]).lower() != TRANSFER_TOPIC:
                continue
            recipient = _topic_to_address(topics[2])
            if recipient != destination:
                continue
            matching_recipient = True
            try:
                amount = _parse_quantity(log.get("data"), label="transfer amount")
            except ValueError:
                continue
            if amount == expected_units:
                return VerificationResult("confirmed", confirmations=confirmations, block_number=block_number)
        if not matching_contract:
            error = "Transaction has no transfer from the configured USDT contract"
        elif not matching_recipient:
            error = "USDT transfer recipient does not match the payout wallet"
        else:
            error = "USDT transfer amount does not match the approved payout"
        return VerificationResult("failed", error, confirmations, block_number)
    except (
        KeyError,
        TypeError,
        ValueError,
        requests.RequestException,
        urllib3.exceptions.HTTPError,
        RuntimeError,
    ) as exc:
        return VerificationResult("pending", str(exc)[:500])


def submit_payout_transaction(db, payout_id: int, tx_hash: str, *, now: datetime | None = None) -> None:
    value = normalize_tx_hash(tx_hash)
    current = now or datetime.now(UTC)
    owns_transaction = not db.in_transaction
    try:
        if owns_transaction:
            db.execute("BEGIN IMMEDIATE")
        payout = db.execute(
            "SELECT user_id, amount_micro_usd, status FROM payouts WHERE id=?",
            (int(payout_id),),
        ).fetchone()
        if payout is None:
            raise LookupError("Payout not found or not awaiting transaction verification")
        if str(payout["status"]) == "failed":
            available = balances_for_user(db, int(payout["user_id"])).available_micro_usd
            reserved = db.execute(
                "SELECT COALESCE(SUM(amount_micro_usd),0) AS total FROM payouts "
                "WHERE user_id=? AND id<>? AND status IN ('requested','approved','verifying','confirmed','sent')",
                (int(payout["user_id"]), int(payout_id)),
            ).fetchone()["total"]
            if int(payout["amount_micro_usd"]) > available - int(reserved):
                raise ValueError("Payout retry exceeds available balance")
        duplicate = db.execute(
            "SELECT id FROM payouts WHERE lower(tx_hash)=? AND id<>?",
            (value, int(payout_id)),
        ).fetchone()
        if duplicate is not None:
            raise ValueError("Transaction hash is already assigned to another payout")
        try:
            cursor = db.execute(
                """
                UPDATE payouts SET status='verifying', tx_hash=?, verification_error='',
                    verification_attempts=0, next_verification_at=?, verified_at=NULL,
                    confirmations=0, tx_block_number=NULL, verification_claimed_until=NULL,
                    verification_claim_token=NULL, updated_at=?
                    WHERE id=? AND status IN ('approved','failed','verifying')
                """,
                (value, current.isoformat(), current.isoformat(), int(payout_id)),
            )
        except sqlite3.IntegrityError as exc:
            if "payouts_tx_hash_uidx" in str(exc):
                raise ValueError("Transaction hash is already assigned to another payout") from None
            raise
        if cursor.rowcount != 1:
            raise LookupError("Payout not found or not awaiting transaction verification")
        if owns_transaction:
            db.commit()
    except Exception:
        if owns_transaction and db.in_transaction:
            db.rollback()
        raise


def apply_payout_verification(
    db,
    payout_id: int,
    result: VerificationResult,
    *,
    claim_token: str | None = None,
    now: datetime | None = None,
) -> None:
    current = now or datetime.now(UTC)
    status = str(result.status)
    if status not in {"pending", "confirmed", "failed"}:
        raise ValueError("Invalid payout verification status")
    next_at = (current + timedelta(minutes=DEFAULT_RETRY_MINUTES)).isoformat() if status == "pending" else None
    persisted_status = "verifying" if status == "pending" else status
    claim_filter = " AND verification_claim_token=?" if claim_token is not None else ""
    parameters = [
        persisted_status,
        str(result.error or "")[:500],
        next_at,
        current.isoformat() if status in {"confirmed", "failed"} else None,
        max(0, int(result.confirmations or 0)),
        result.block_number,
        current.isoformat(),
        int(payout_id),
    ]
    if claim_token is not None:
        parameters.append(str(claim_token))
    cursor = db.execute(
        f"""
        UPDATE payouts SET status=?, verification_error=?,
            verification_attempts=verification_attempts+1, next_verification_at=?,
            verified_at=?, confirmations=?, tx_block_number=?,
            verification_claimed_until=NULL, verification_claim_token=NULL, updated_at=?
        WHERE id=? AND status='verifying'{claim_filter}
        """,
        parameters,
    )
    if cursor.rowcount != 1:
        raise LookupError("Payout not found or no longer awaiting verification")
    db.commit()
