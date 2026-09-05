from __future__ import annotations

import re
from decimal import Decimal, DecimalException

from flask import Blueprint, current_app, g, request

from app.auth import login_required
from app.db import get_db
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.payouts import (
    DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER,
    MAX_MAX_OUTSTANDING_PAYOUTS_PER_USER,
    MAX_PAYOUT_MICRO_USD,
    PayoutQuotaExceeded,
    request_payout,
)
from app.services.wallets import WalletInUse, WalletLocked, set_wallet

bp = Blueprint("wallets", __name__)

MAX_PAYOUT_AMOUNT_CHARS = 32
PAYOUT_AMOUNT_PATTERN = re.compile(r"\d+(?:\.\d{1,6})?\Z")


@bp.post("/wallet")
@login_required
def update_wallet():
    try:
        wallet = set_wallet(get_db(), g.user["id"], request.form.get("address", ""))
    except (ValueError, WalletInUse, WalletLocked) as exc:
        return form_error(str(exc), 400, "dashboard.wallet", field="address", focus="address")
    return form_success(
        {"address": wallet.address, "locked_until": wallet.locked_until},
        endpoint="dashboard.wallet",
        message="Wallet saved. A 48-hour payout lock now applies.",
    )


def _requested_micro_usd() -> int:
    if not is_browser_form():
        raw_amount = str(request.form.get("amount_micro_usd") or "0").strip()
        if len(raw_amount) > MAX_PAYOUT_AMOUNT_CHARS or not raw_amount.isascii() or not raw_amount.isdecimal():
            raise ValueError("Payout amount must be a valid integer micro-USD value")
        value = int(raw_amount)
        if value > MAX_PAYOUT_MICRO_USD:
            raise ValueError("Payout amount is above the supported maximum")
        return value
    raw_amount = str(request.form.get("amount_usd") or "0").strip()
    if len(raw_amount) > MAX_PAYOUT_AMOUNT_CHARS or PAYOUT_AMOUNT_PATTERN.fullmatch(raw_amount) is None:
        raise ValueError("Payout amount must be a valid USD value")
    try:
        amount = Decimal(raw_amount)
    except DecimalException as exc:
        raise ValueError("Payout amount must be a valid USD value") from exc
    if not amount.is_finite():
        raise ValueError("Payout amount must be a valid USD value")
    try:
        scaled = amount * Decimal(1_000_000)
        if scaled != scaled.to_integral_value():
            raise ValueError("Payout amount supports at most 6 decimal places")
        value = int(scaled)
        if value > MAX_PAYOUT_MICRO_USD:
            raise ValueError("Payout amount is above the supported maximum")
        return value
    except (DecimalException, OverflowError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc) == "Payout amount supports at most 6 decimal places":
            raise
        raise ValueError("Payout amount must be a valid USD value") from exc


@bp.post("/payouts")
@login_required
def create_payout():
    try:
        try:
            max_outstanding = int(
                current_app.config.get("MAX_OUTSTANDING_PAYOUTS_PER_USER", DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER)
            )
        except (TypeError, ValueError):
            max_outstanding = DEFAULT_MAX_OUTSTANDING_PAYOUTS_PER_USER
        max_outstanding = max(1, min(MAX_MAX_OUTSTANDING_PAYOUTS_PER_USER, max_outstanding))
        payout_id = request_payout(
            get_db(),
            g.user["id"],
            _requested_micro_usd(),
            max_outstanding_payouts=max_outstanding,
        )
    except PayoutQuotaExceeded as exc:
        return form_error(str(exc), 429, "dashboard.wallet", field="amount_usd", focus="amount_usd")
    except (ValueError, TypeError) as exc:
        return form_error(str(exc), 400, "dashboard.wallet", field="amount_usd", focus="amount_usd")
    return form_success(
        {"id": payout_id, "status": "requested"},
        status=201,
        endpoint="dashboard.wallet",
        message="Payout request submitted for manual review.",
    )
