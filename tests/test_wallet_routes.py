from conftest import login, login_admin, register

from app.db import get_db


def _active_user(app, client):
    register(client)
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email='member@example.com'").fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client)
    return user_id


def test_user_can_save_wallet_but_ui_never_shows_full_address(app, client):
    _active_user(app, client)
    address = "0x1111111111111111111111111111111111111111"
    assert client.post("/wallet", data={"address": address}).status_code == 200
    page = client.get("/dashboard").get_data(as_text=True)
    assert address not in page
    assert "0x1111…1111" in page


def test_payout_is_manual_and_admin_can_submit_transaction_for_verification(app, client):
    user_id = _active_user(app, client)
    address = "0x2222222222222222222222222222222222222222"
    client.post("/wallet", data={"address": address})
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE wallets SET locked_until=datetime('now','-1 hour') WHERE user_id=?",
            (user_id,),
        )
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "SELECT ?, id, datetime('now','-2 hour'), datetime('now','-1 hour'), 1000000, 'available', datetime('now') FROM proxies LIMIT 1",
            (user_id,),
        )
        if db.execute("SELECT changes()").fetchone()[0] == 0:
            from app.services.proxies import add_proxy

            proxy_id = add_proxy(db, user_id, "payout.example:9000:u:p")
            db.execute(
                "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) VALUES(?,?,datetime('now','-2 hour'),datetime('now','-1 hour'),1000000,'available',datetime('now'))",
                (user_id, proxy_id),
            )
        db.commit()
    response = client.post("/payouts", data={"amount_micro_usd": "500000"})
    assert response.status_code == 201
    payout_id = response.get_json()["id"]

    admin = app.test_client()
    login_admin(admin)
    approved = admin.post(f"/admin/payouts/{payout_id}/approve")
    assert approved.status_code == 200
    tx_hash = "0x" + "ab" * 32
    sent = admin.post(f"/admin/payouts/{payout_id}/sent", data={"tx_hash": tx_hash})
    assert sent.status_code == 200
    with app.app_context():
        payout = get_db().execute("SELECT status, tx_hash FROM payouts WHERE id=?", (payout_id,)).fetchone()
    assert (payout["status"], payout["tx_hash"]) == ("verifying", tx_hash)


def test_payout_queue_cap_returns_429_before_creating_another_row(app, client):
    app.config["MAX_OUTSTANDING_PAYOUTS_PER_USER"] = 1
    user_id = _active_user(app, client)
    client.post("/wallet", data={"address": "0x3333333333333333333333333333333333333333"})
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE wallets SET locked_until=datetime('now','-1 hour') WHERE user_id=?",
            (user_id,),
        )
        from app.services.proxies import add_proxy

        proxy_id = add_proxy(db, user_id, "payout-cap-route.example:9000:u:p")
        db.execute(
            "INSERT INTO earnings_ledger(user_id,proxy_id,started_at,ended_at,micro_usd,bucket,created_at) "
            "VALUES(?,?,datetime('now','-2 hour'),datetime('now','-1 hour'),2000000,'available',datetime('now'))",
            (user_id, proxy_id),
        )
        db.commit()

    first = client.post("/payouts", data={"amount_micro_usd": "500000"})
    second = client.post("/payouts", data={"amount_micro_usd": "500000"})

    assert first.status_code == 201
    assert second.status_code == 429
    assert "outstanding payout" in second.get_json()["error"].lower()
    with app.app_context():
        assert (
            get_db().execute("SELECT COUNT(*) AS count FROM payouts WHERE user_id=?", (user_id,)).fetchone()["count"]
            == 1
        )


def test_browser_payout_rejects_huge_decimal_without_server_error(app, client):
    user_id = _active_user(app, client)
    client.post("/wallet", data={"address": "0x4444444444444444444444444444444444444444"})
    with app.app_context():
        db = get_db()
        db.execute("UPDATE wallets SET locked_until=datetime('now','-1 hour') WHERE user_id=?", (user_id,))
        db.commit()

    response = client.post("/payouts", data={"amount_usd": "1e999999", "ui": "1"})

    assert response.status_code == 303
    with client.session_transaction() as session:
        assert any("valid USD" in message for _category, message in session.get("_flashes", []))


def test_browser_payout_rejects_oversized_amount_before_decimal_parsing(app, client, monkeypatch):
    _active_user(app, client)

    from app.routes import wallets as wallets_route

    def fail_if_decimal_called(*_args, **_kwargs):
        raise AssertionError("oversized payout input must be rejected before Decimal parsing")

    monkeypatch.setattr(wallets_route, "Decimal", fail_if_decimal_called)
    response = client.post("/payouts", data={"amount_usd": "9" * 60_000, "ui": "1"})

    assert response.status_code == 303
    with client.session_transaction() as session:
        assert any("valid USD" in message for _category, message in session.get("_flashes", []))


def test_direct_payout_rejects_extreme_micro_usd_without_server_error(app, client):
    _active_user(app, client)

    response = client.post("/payouts", data={"amount_micro_usd": "9" * 60_000})

    assert response.status_code == 400
    assert "valid integer micro-USD" in response.get_json()["error"]


def test_direct_payout_rejects_amount_above_supported_maximum(app, client):
    _active_user(app, client)

    response = client.post("/payouts", data={"amount_micro_usd": "1000000000000001"})

    assert response.status_code == 400
    assert "supported maximum" in response.get_json()["error"]
