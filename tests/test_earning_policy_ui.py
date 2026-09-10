from datetime import UTC, datetime, timedelta

from conftest import login, login_admin, register

from app.db import get_db
from app.services.earnings import accrue_eligible_time, earnings_for_proxies, monthly_rate_for
from app.services.proxies import add_proxy


def _activate_user(app, client, email: str) -> int:
    register(client, email, "member-password")
    login_admin(client)
    with app.app_context():
        user_id = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    client.post(f"/admin/users/{user_id}/approve")
    client.post("/logout")
    login(client, email, "member-password")
    return int(user_id)


def _mark_proxy_online(db, proxy_id: int, *, eligibility: str, country: str, exit_ip: str, at: datetime) -> None:
    db.execute(
        """
        UPDATE proxies SET status='online', eligibility=?, country_code=?, exit_ip=?,
            egress_attestation_source='https_quorum', egress_verified_at=?,
            online_since=?, last_success_at=?, accrual_cursor_at=?, probation_started_at=?
        WHERE id=?
        """,
        (
            eligibility,
            country,
            exit_ip,
            at.isoformat(),
            at.isoformat(),
            at.isoformat(),
            at.isoformat(),
            at.isoformat(),
            proxy_id,
        ),
    )


def test_monthly_rate_policy_exposes_allow_and_risk_rates():
    assert monthly_rate_for("allow", "US") == 1_000_000
    assert monthly_rate_for("allow", "VN") == 500_000
    assert monthly_rate_for("risk", "US") == 500_000
    assert monthly_rate_for("pending", "US") == 0


def test_risk_proxy_accrues_at_half_dollar_monthly_rate(app):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        user_id = __import__("app.services.users", fromlist=["create_user"]).create_user(
            db, "risk-earning@example.com", "password", status="active"
        )
        proxy_id = add_proxy(db, user_id, "risk-earning.example:9000:u:p")
        _mark_proxy_online(db, proxy_id, eligibility="risk", country="US", exit_ip="198.51.100.90", at=start)
        db.commit()

        accrue_eligible_time(db, now=start + timedelta(hours=1))
        amount = db.execute(
            "SELECT COALESCE(SUM(micro_usd), 0) AS amount FROM earnings_ledger WHERE proxy_id=?",
            (proxy_id,),
        ).fetchone()["amount"]

    assert amount == 500_000 // 720


def test_proxy_earnings_aggregate_returns_pending_and_available_totals(app):
    with app.app_context():
        db = get_db()
        user_id = __import__("app.services.users", fromlist=["create_user"]).create_user(
            db, "proxy-aggregate@example.com", "password", status="active"
        )
        proxy_id = add_proxy(db, user_id, "aggregate.example:9000:u:p")
        db.executemany(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, datetime('now'), datetime('now'), ?, ?, datetime('now'))",
            ((user_id, proxy_id, 125_000, "pending"), (user_id, proxy_id, 375_000, "available")),
        )
        db.commit()

        earnings = earnings_for_proxies(db, [proxy_id])[proxy_id]

    assert earnings.pending_micro_usd == 125_000
    assert earnings.available_micro_usd == 375_000
    assert earnings.total_micro_usd == 500_000


def test_admin_ui_uses_high_quality_label_without_earnapp_branding(client):
    login_admin(client)
    page = client.get("/admin").get_data(as_text=True)

    assert "High quality" in page
    assert "earnapp" not in page.lower()


def test_user_proxy_table_shows_rate_pending_explanation_and_allow_first(app, client):
    user_id = _activate_user(app, client, "earning-policy-ui@example.com")
    with app.app_context():
        db = get_db()
        pending = add_proxy(db, user_id, "pending-policy.example:9000:u:p")
        risk = add_proxy(db, user_id, "risk-policy.example:9001:u:p")
        allow = add_proxy(db, user_id, "allow-policy.example:9002:u:p")
        now = datetime(2026, 1, 1, tzinfo=UTC)
        _mark_proxy_online(db, risk, eligibility="risk", country="US", exit_ip="198.51.100.91", at=now)
        _mark_proxy_online(db, allow, eligibility="allow", country="US", exit_ip="198.51.100.92", at=now)
        db.execute("UPDATE proxies SET status='online', eligibility='pending' WHERE id=?", (pending,))
        db.execute(
            "INSERT INTO earnings_ledger(user_id, proxy_id, started_at, ended_at, micro_usd, bucket, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'available', ?)",
            (user_id, allow, now.isoformat(), (now + timedelta(hours=1)).isoformat(), 125_000, now.isoformat()),
        )
        db.commit()

    page = client.get("/dashboard/proxies").get_data(as_text=True)

    assert "Earn" in page
    assert "$1.00/month" in page
    assert "$0.50/month" in page
    assert "$0.00/month" in page
    assert "$0.125000" in page
    assert "High quality" in page
    assert "earnapp" not in page.lower()
    assert "sort=eligibility" in page
    assert "direction=asc" in page
    assert page.index("allow-policy.example:9002") < page.index("risk-policy.example:9001")
    assert page.index("risk-policy.example:9001") < page.index("pending-policy.example:9000")

    for path in ("/dashboard", "/dashboard/earnings", "/dashboard/wallet"):
        assert "earnapp" not in client.get(path).get_data(as_text=True).lower()
