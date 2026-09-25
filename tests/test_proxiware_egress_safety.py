from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.crypto import encrypt_secret
from app.db import get_db
from app.services.proxiware_qualification import _ensure_columns, _ip
from app.services.settings import set_setting


@pytest.mark.parametrize(
    "exit_ip",
    ("10.0.0.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1"),
)
def test_qualification_rejects_non_public_egress(exit_ip, app):
    with app.app_context():
        assert _ip(exit_ip) == ""
        assert _ip("198.51.100.80") == "198.51.100.80"


def test_internal_distribution_rejects_non_public_egress(app, client):
    with app.app_context():
        db = get_db()
        _ensure_columns(db)
        now = datetime.now(UTC).isoformat()
        db.execute(
            "INSERT INTO provider_subscriptions(provider,external_id,status,first_seen_at,last_seen_at,created_at,updated_at) "
            "VALUES('proxiware','egress-test','active',?,?,?,?)",
            (now, now, now, now),
        )
        subscription_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.execute(
            """
            INSERT INTO provider_assignments(
                subscription_id,provider,external_id,host,port,username_encrypted,password_encrypted,
                status,qualification,provider_eligible,live_status,exit_ip,assigned_at,last_seen_at,
                created_at,updated_at,protocol,last_checked_at,egress_verified_at,duplicate_egress,
                distribution_enabled
            ) VALUES(?, 'proxiware','egress-test-1','provider-feed.example',9000,?,?, 'active','allow',1,'live',?,?,?,?,?,'socks5',?,?,0,1)
            """,
            (
                subscription_id,
                encrypt_secret("provider-user"),
                encrypt_secret("provider-pass"),
                "10.0.0.1",
                now,
                now,
                now,
                now,
                now,
                now,
            ),
        )
        db.commit()
        set_setting(db, "proxiware_distribution_enabled", "1")

    response = client.get("/api/v1/proxy-raw", headers={"X-API-Key": "internal-test-key"})
    assert response.status_code == 200
    assert response.get_data(as_text=True) == ""
