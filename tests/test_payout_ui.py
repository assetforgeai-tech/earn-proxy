from __future__ import annotations

from datetime import UTC, datetime, timedelta

from conftest import login, login_admin, register

from app.db import get_db
from app.services.payout_verification import submit_payout_transaction
from app.services.payouts import approve_payout, request_payout
from app.services.proxies import add_proxy
from app.services.wallets import set_wallet


def _payout(app, client, *, status: str) -> int:
    register(client, "payout-ui@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        db = get_db()
        user_id = db.execute("SELECT id FROM users WHERE email='payout-ui@example.com'").fetchone()["id"]
        db.execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
        proxy_id = add_proxy(db, user_id, "payout-ui.example:9000:u:p")
        now = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)
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
        if status in {"approved", "verifying", "failed", "confirmed"}:
            approve_payout(db, payout_id, now=now)
        if status in {"verifying", "failed", "confirmed"}:
            submit_payout_transaction(db, payout_id, "0x" + "ab" * 32, now=now)
            db.execute(
                "UPDATE payouts SET status=?, verification_error=? WHERE id=?",
                (status, "Simulated verifier detail" if status == "failed" else "", payout_id),
            )
            db.commit()
    return payout_id


def test_admin_payout_ui_submits_for_verification_with_confirmation(app, client):
    _payout(app, client, status="approved")
    page = client.get("/admin/payouts").get_data(as_text=True)

    assert "Submit for verification" in page
    assert 'data-confirm-title="Submit transaction for verification?"' in page
    assert "Mark sent" not in page
    assert "32-byte transaction hash" in page
    assert 'action="/admin/payouts/' in page
    assert '/transaction"' in page


def test_user_dashboard_explains_fee_quote_and_whitelist_values(app, client):
    _active_user = _payout
    register(client, "fee-copy@example.com", "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='fee-copy@example.com'").fetchone()["id"]
        get_db().execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
        get_db().commit()
    client.post("/logout")
    login(client, "fee-copy@example.com", "member-password")

    page = client.get("/dashboard").get_data(as_text=True)

    assert "Minimum payout: $10.00" in page
    assert "10% fee for $10.00–$49.99" in page
    assert "2% fee from $50.00" in page
    assert "processed within 48 hours" in page
    assert "whitelist.proxy.acacondos.com" in page
    assert "42.96.12.142" in page
    assert "data-copy-target" in page


def test_verifying_payout_offers_guarded_transaction_replacement(app, client):
    _payout(app, client, status="verifying")
    page = client.get("/admin/payouts").get_data(as_text=True)

    assert "Replace transaction" in page
    assert 'data-confirm-title="Replace transaction under verification?"' in page
    assert "may already settle" in page


def test_verifying_and_failed_statuses_are_explained_to_admin_and_user(app, client):
    _payout(app, client, status="failed")
    admin_page = client.get("/admin/payouts").get_data(as_text=True)
    assert "Failed" in admin_page
    assert "Simulated verifier detail" in admin_page
    assert "Retry verification" in admin_page

    client.post("/logout")
    login(client, "payout-ui@example.com", "member-password")
    user_page = client.get("/dashboard").get_data(as_text=True)
    assert "Failed" in user_page
    assert "Payment verification failed; admin review is required." in user_page
    assert "Simulated verifier detail" not in user_page


def test_admin_payout_queue_shows_fee_net_and_processing_deadline(app, client):
    _payout(app, client, status="approved")
    page = client.get("/admin/payouts").get_data(as_text=True)

    assert "Gross" in page
    assert "Fee" in page
    assert "Net" in page
    assert "Processing deadline" in page
