from __future__ import annotations

from decimal import Decimal, InvalidOperation

from flask import Blueprint, g, request

from app.auth import login_required
from app.db import get_db
from app.routes.forms import form_error, form_success, is_browser_form
from app.services.payouts import request_payout
from app.services.wallets import WalletInUse, WalletLocked, set_wallet

bp = Blueprint("wallets", __name__)


@bp.post("/wallet")
@login_required
def update_wallet():
    try:
        wallet = set_wallet(get_db(), g.user["id"], request.form.get("address", ""))
    except (ValueError, WalletInUse, WalletLocked) as exc:
        return form_error(str(exc), 400, "dashboard.dashboard", field="address", focus="address")
    return form_success(
        {"address": wallet.address, "locked_until": wallet.locked_until},
        endpoint="dashboard.dashboard",
        message="Wallet saved. A 48-hour payout lock now applies.",
    )


def _requested_micro_usd() -> int:
    if not is_browser_form():
        return int(request.form.get("amount_micro_usd", "0"))
    try:
        amount = Decimal(str(request.form.get("amount_usd") or "0"))
    except InvalidOperation as exc:
        raise ValueError("Payout amount must be a valid USD value") from exc
    if not amount.is_finite():
        raise ValueError("Payout amount must be a valid USD value")
    scaled = amount * Decimal(1_000_000)
    if scaled != scaled.to_integral_value():
        raise ValueError("Payout amount supports at most 6 decimal places")
    return int(scaled)


@bp.post("/payouts")
@login_required
def create_payout():
    try:
        payout_id = request_payout(get_db(), g.user["id"], _requested_micro_usd())
    except (ValueError, TypeError) as exc:
        return form_error(str(exc), 400, "dashboard.dashboard", field="amount_usd", focus="amount_usd")
    return form_success(
        {"id": payout_id, "status": "requested"},
        status=201,
        endpoint="dashboard.dashboard",
        message="Payout request submitted for manual review.",
    )
