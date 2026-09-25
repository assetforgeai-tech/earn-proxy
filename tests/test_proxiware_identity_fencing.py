from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime

from app.crypto import decrypt_secret, encrypt_secret
from app.db import get_db
from app.services.proxiware import sync_proxiware_inventory
from app.services.proxiware_qualification import qualify_proxiware_assignment
from app.services.settings import set_setting


class _ProviderClient:
    def __init__(self, *, host: str, port: int, username: str, password: str, **fields):
        self.proxy = {
            "id": 100,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "country": "US",
            **fields,
        }

    def list_subscriptions(self, network="isp"):
        return [{"id": 10, "network": network, "eligible": 900, "connections": 1}]

    def list_subscription_proxies(self, subscription_id):
        return [self.proxy]


def _trusted_assignment(db, now: datetime):
    row = db.execute("SELECT id FROM provider_assignments WHERE external_id='100'").fetchone()
    db.execute(
        "UPDATE provider_assignments SET live_status='live', qualification='allow', provider_eligible=1, "
        "protocol='http', exit_ip='8.8.8.8', egress_verified_at=?, last_checked_at=?, "
        "distribution_enabled=1, duplicate_egress=0 WHERE id=?",
        (now.isoformat(), now.isoformat(), row["id"]),
    )
    set_setting(db, "proxiware_distribution_enabled", "1")
    db.commit()
    return int(row["id"])


def test_sync_invalidates_trust_when_provider_identity_changes(app):
    now = datetime(2026, 9, 25, 1, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(
            db,
            _ProviderClient(host="verified.example", port=41000, username="old-user", password="old-pass"),
            now=now,
        )
        assignment_id = _trusted_assignment(db, now)

        sync_proxiware_inventory(
            db,
            _ProviderClient(
                host="replacement.example",
                port=42000,
                username="new-user",
                password="new-pass",
                # Provider metadata must never carry trust across an identity change.
                live_status="live",
                qualification="allow",
                provider_eligible=1,
                exit_ip="8.8.8.8",
            ),
            now=now.replace(hour=2),
        )
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()
        username = decrypt_secret(row["username_encrypted"])

    assert row["host"] == "replacement.example"
    assert username == "new-user"
    assert row["qualification"] == "pending"
    assert row["live_status"] == "pending"
    assert row["exit_ip"] is None
    assert row["egress_verified_at"] is None
    assert row["last_checked_at"] is None
    assert row["distribution_enabled"] == 0


def test_qualification_result_cannot_apply_after_identity_changes_during_probe(app):
    now = datetime(2026, 9, 25, 3, 0, tzinfo=UTC)
    with app.app_context():
        db = get_db()
        sync_proxiware_inventory(
            db,
            _ProviderClient(host="old.example", port=41000, username="old-user", password="old-pass"),
            now=now,
        )
        assignment_id = db.execute("SELECT id FROM provider_assignments WHERE external_id='100'").fetchone()["id"]
        db.execute(
            "UPDATE provider_assignments SET qualification_claim_token='claim', qualification_claimed_until=? WHERE id=?",
            (now.replace(minute=30).isoformat(), assignment_id),
        )
        db.commit()

        def probe(proxy):
            assert proxy["host"] == "old.example"
            db.execute(
                "UPDATE provider_assignments SET host=?, port=?, username_encrypted=?, password_encrypted=? WHERE id=?",
                (
                    "new.example",
                    42000,
                    encrypt_secret("new-user"),
                    encrypt_secret("new-pass"),
                    assignment_id,
                ),
            )
            db.commit()
            return {"status": "live", "protocol": "http", "exit_ip": "8.8.8.8", "egress_trusted": True}

        with suppress(LookupError, RuntimeError):
            qualify_proxiware_assignment(
                db,
                assignment_id,
                probe=probe,
                eligibility=lambda _proxy: {"verdict": "ALLOW", "reason": "ok"},
                now=now,
                claim_token="claim",
            )
        row = db.execute("SELECT * FROM provider_assignments WHERE id=?", (assignment_id,)).fetchone()
        username = decrypt_secret(row["username_encrypted"])

    assert row["host"] == "new.example"
    assert username == "new-user"
    assert row["qualification"] != "allow"
    assert row["live_status"] != "live"
    assert row["exit_ip"] is None
