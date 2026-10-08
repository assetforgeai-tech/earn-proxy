from __future__ import annotations

from datetime import UTC, datetime

from app.crypto import encrypt_secret
from app.db import get_db
from app.services.proxiware_swap import ensure_proxiware_swap_schema
from app.services.proxiware_transfer import load_proxiware_slots


def _subscription(db, external_id: str) -> int:
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT INTO provider_subscriptions(provider,external_id,status,created_at,updated_at) "
        "VALUES('proxiware',?,'active',?,?)",
        (external_id, now, now),
    )
    return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def _assignment(db, subscription_id: int, external_id: str, *, host: str) -> None:
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT INTO provider_assignments(subscription_id,provider,external_id,host,port,username_encrypted,"
        "password_encrypted,status,qualification,live_status,protocol,created_at,updated_at) "
        "VALUES(?,'proxiware',?,?,9000,?,?,'active','allow','live','socks5',?,?)",
        (
            subscription_id,
            external_id,
            host,
            encrypt_secret("provider-user"),
            encrypt_secret("provider-pass"),
            now,
            now,
        ),
    )


def _successful_swap(db, subscription_id: int, old_external_id: str, new_external_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT INTO swap_jobs(provider,subscription_id,state,reason,created_at,updated_at) "
        "VALUES('proxiware',?,'success','swapped',?,?)",
        (subscription_id, now, now),
    )
    job_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO swap_mappings(swap_job_id,old_assignment_external_id,new_assignment_external_id,"
        "success_at,created_at) VALUES(?,?,?,?,?)",
        (job_id, old_external_id, new_external_id, now, now),
    )


def test_transfer_slot_key_survives_one_and_multiple_confirmed_swaps(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "subscription-1")
        _assignment(db, subscription_id, "assignment-a", host="first.proxy.example")
        db.commit()
        first = load_proxiware_slots(db)[0]

        _successful_swap(db, subscription_id, "assignment-a", "assignment-b")
        db.execute("DELETE FROM provider_assignments WHERE external_id='assignment-a'")
        _assignment(db, subscription_id, "assignment-b", host="second.proxy.example")
        db.commit()
        second = load_proxiware_slots(db)[0]

        _successful_swap(db, subscription_id, "assignment-b", "assignment-c")
        db.execute("DELETE FROM provider_assignments WHERE external_id='assignment-b'")
        _assignment(db, subscription_id, "assignment-c", host="third.proxy.example")
        db.commit()
        third = load_proxiware_slots(db)[0]

    assert first["slot_key"] == second["slot_key"] == third["slot_key"]
    assert [first["external_id"], second["external_id"], third["external_id"]] == [
        "assignment-a",
        "assignment-b",
        "assignment-c",
    ]
    assert third["raw"] == "third.proxy.example:9000:provider-user:provider-pass"


def test_transfer_slots_are_scoped_to_subscription_and_current_inventory(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        first_subscription = _subscription(db, "subscription-one")
        second_subscription = _subscription(db, "subscription-two")
        _assignment(db, first_subscription, "same-id-one", host="one.proxy.example")
        _assignment(db, second_subscription, "same-id-two", host="two.proxy.example")
        db.commit()

        rows = load_proxiware_slots(db)

    assert len(rows) == 2
    assert len({row["slot_key"] for row in rows}) == 2


def test_transfer_feed_rejects_swap_lineage_cycles(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "cycle-subscription")
        _assignment(db, subscription_id, "cycle-a", host="cycle.proxy.example")
        _successful_swap(db, subscription_id, "cycle-a", "cycle-b")
        _successful_swap(db, subscription_id, "cycle-b", "cycle-a")
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "cycle" in str(error).lower()
        else:
            raise AssertionError("cyclic swap history must not assign a transfer slot")


def test_transfer_feed_rejects_multiple_current_assignments_for_one_slot(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "duplicate-lineage-subscription")
        _assignment(db, subscription_id, "lineage-root", host="root.proxy.example")
        _successful_swap(db, subscription_id, "lineage-root", "lineage-b")
        _successful_swap(db, subscription_id, "lineage-root", "lineage-c")
        db.execute("DELETE FROM provider_assignments WHERE external_id='lineage-root'")
        _assignment(db, subscription_id, "lineage-b", host="b.proxy.example")
        _assignment(db, subscription_id, "lineage-c", host="c.proxy.example")
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "one provider slot" in str(error).lower()
        else:
            raise AssertionError("one transfer slot cannot have multiple current assignments")


def test_transfer_feed_rejects_an_incomplete_active_assignment_instead_of_silently_omitting_it(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "incomplete-subscription")
        _assignment(db, subscription_id, "incomplete-assignment", host="")
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "incomplete" in str(error).lower()
        else:
            raise AssertionError("incomplete current assignments must not produce a partial feed")


def test_transfer_feed_rejects_current_inventory_without_subscription_identity(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "")
        _assignment(db, subscription_id, "identified-assignment", host="proxy.example")
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "incomplete" in str(error).lower()
        else:
            raise AssertionError("current assignments require a stable subscription identity")


def test_transfer_feed_rejects_private_proxy_endpoints(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "private-endpoint-subscription")
        _assignment(db, subscription_id, "private-endpoint-assignment", host="127.0.0.1")
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "invalid" in str(error).lower()
        else:
            raise AssertionError("private provider endpoints must not be transferred to Relay")


def test_transfer_feed_fails_closed_while_swap_reconciliation_is_pending(app):
    with app.app_context():
        db = get_db()
        ensure_proxiware_swap_schema(db)
        subscription_id = _subscription(db, "reconciliation-subscription")
        _assignment(db, subscription_id, "old-assignment", host="old.proxy.example")
        _assignment(db, subscription_id, "new-assignment", host="new.proxy.example")
        now = datetime.now(UTC).isoformat()
        db.execute(
            "INSERT INTO swap_jobs(provider,subscription_id,state,reason,mutation_new_assignment_external_id,created_at,updated_at) "
            "VALUES('proxiware',?,'reconciliation_required','swap',?,?,?)",
            (subscription_id, "new-assignment", now, now),
        )
        db.commit()

        try:
            load_proxiware_slots(db)
        except ValueError as error:
            assert "reconciliation" in str(error).lower()
        else:
            raise AssertionError("unresolved swaps must not publish an incomplete current snapshot")


def test_internal_transfer_feed_requires_loopback_key_and_never_splits_credentials(client, app, db):
    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "feed-subscription")
    _assignment(db, subscription_id, "feed-assignment", host="feed.proxy.example")
    db.commit()
    app.config["RELAY_FEED_KEY"] = "relay-shared-secret"

    denied = client.get(
        "/internal/api/v1/proxiware-transfer-feed",
        headers={"X-Relay-Feed-Key": "relay-shared-secret"},
        environ_base={"REMOTE_ADDR": "192.0.2.30"},
    )
    allowed = client.get(
        "/internal/api/v1/proxiware-transfer-feed",
        headers={"X-Relay-Feed-Key": "relay-shared-secret"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert denied.status_code == 403
    assert allowed.status_code == 200
    item = allowed.get_json()["items"][0]
    assert item["upstream"] == {
        "host": "feed.proxy.example",
        "port": 9000,
        "username": "provider-user",
        "password": "provider-pass",
    }
    assert item["qualification"] == "allow"
    assert "raw" not in item
    assert "username" not in item and "password" not in item
    assert "upstream_username" not in item and "upstream_password" not in item
    assert allowed.headers["Cache-Control"] == "no-store"


def test_internal_transfer_feed_requires_configured_shared_key(client, app):
    app.config["RELAY_FEED_KEY"] = ""

    response = client.get(
        "/internal/api/v1/proxiware-transfer-feed",
        headers={"X-Relay-Feed-Key": "anything"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    assert response.status_code == 503


def test_admin_inventory_offers_all_and_allow_exports_for_raw_and_transfer(client):
    from conftest import login_admin

    login_admin(client)
    page = client.get("/admin/providers/proxiware/inventory").get_data(as_text=True)

    for scope in ("all", "allow"):
        for kind in ("raw", "transfer"):
            assert f"/admin/providers/proxiware/inventory/export/{scope}/{kind}" in page


def test_empty_inventory_exports_header_only_without_requiring_relay_bindings(client):
    from conftest import login_admin

    login_admin(client)
    for scope in ("all", "allow"):
        for kind in ("raw", "transfer"):
            response = client.get(f"/admin/providers/proxiware/inventory/export/{scope}/{kind}")

            assert response.status_code == 200
            assert len(response.get_data(as_text=True).splitlines()) == 1
            assert response.headers["Cache-Control"] == "no-store"


def test_raw_inventory_exports_are_admin_only_and_all_or_allow_scoped(client, db):
    from conftest import login_admin

    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "csv-subscription")
    _assignment(db, subscription_id, "csv-allow", host="allow.proxy.example")
    _assignment(db, subscription_id, "csv-risk", host="risk.proxy.example")
    db.execute("UPDATE provider_assignments SET qualification='risk' WHERE external_id='csv-risk'")
    db.commit()

    denied = client.get("/admin/providers/proxiware/inventory/export/all/raw")
    login_admin(client)
    all_response = client.get("/admin/providers/proxiware/inventory/export/all/raw")
    allow_response = client.get("/admin/providers/proxiware/inventory/export/allow/raw")

    assert denied.status_code == 403
    assert all_response.status_code == allow_response.status_code == 200
    assert "allow.proxy.example:9000:provider-user:provider-pass" in all_response.get_data(as_text=True)
    assert "risk.proxy.example:9000:provider-user:provider-pass" in all_response.get_data(as_text=True)
    assert "allow.proxy.example:9000:provider-user:provider-pass" in allow_response.get_data(as_text=True)
    assert "risk.proxy.example" not in allow_response.get_data(as_text=True)
    assert all_response.headers["Cache-Control"] == "no-store"
    assert "attachment" in all_response.headers["Content-Disposition"]


def test_raw_export_neutralizes_formula_prefixes_in_provider_metadata(client, db):
    from conftest import login_admin

    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "=1+1")
    _assignment(db, subscription_id, "@SUM(1,2)", host="safe.proxy.example")
    db.commit()
    login_admin(client)

    response = client.get("/admin/providers/proxiware/inventory/export/all/raw")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "'=1+1" in body
    assert "'@SUM(1,2)" in body
    assert "safe.proxy.example:9000:provider-user:provider-pass" in body


def test_transfer_inventory_export_requires_exact_enabled_relay_binding(client, app, db, monkeypatch):
    from conftest import login_admin

    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "transfer-subscription")
    _assignment(db, subscription_id, "transfer-assignment", host="provider.proxy.example")
    db.commit()
    slot = load_proxiware_slots(db)[0]
    app.config.update(RELAY_FEED_KEY="relay-shared-secret")

    class FeedResponse:
        content = b"{}"

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "complete": True,
                "count": 1,
                "items": [
                    {
                        "slot_key": slot["slot_key"],
                        "relay_id": 1,
                        "proxy": "42.96.12.142:30001:client:relay-pass",
                        "enabled": 1,
                        "status": "live",
                        "protocol": "socks5",
                        "exit_ip": "198.51.100.42",
                    }
                ],
            }

    from app.routes import internal_api

    monkeypatch.setattr(internal_api.requests, "get", lambda *_args, **_kwargs: FeedResponse())
    login_admin(client)
    response = client.get("/admin/providers/proxiware/inventory/export/allow/transfer")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "42.96.12.142:30001:client:relay-pass" in body
    assert slot["slot_key"] in body
    assert response.headers["Cache-Control"] == "no-store"


def test_transfer_inventory_export_fails_closed_on_missing_or_duplicate_binding(client, app, db, monkeypatch):
    from conftest import login_admin

    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "unbound-subscription")
    _assignment(db, subscription_id, "unbound-assignment", host="unbound.proxy.example")
    db.commit()
    slot = load_proxiware_slots(db)[0]
    app.config.update(RELAY_FEED_KEY="relay-shared-secret")

    class FeedResponse:
        content = b"{}"

        def __init__(self, items):
            self.items = items

        def raise_for_status(self):
            return None

        def json(self):
            return {"complete": True, "count": len(self.items), "items": self.items}

    from app.routes import internal_api

    base = {
        "slot_key": slot["slot_key"],
        "relay_id": 1,
        "proxy": "42.96.12.142:20001:client:relay-pass",
        "enabled": 1,
        "status": "live",
        "protocol": "http",
        "exit_ip": "198.51.100.43",
    }
    monkeypatch.setattr(internal_api.requests, "get", lambda *_args, **_kwargs: FeedResponse([]))
    login_admin(client)
    missing = client.get("/admin/providers/proxiware/inventory/export/all/transfer")
    monkeypatch.setattr(internal_api.requests, "get", lambda *_args, **_kwargs: FeedResponse([base, base]))
    duplicate = client.get("/admin/providers/proxiware/inventory/export/all/transfer")

    assert missing.status_code == 409
    assert duplicate.status_code == 409
    assert "missing or ambiguous" in missing.get_data(as_text=True).lower()
    assert "missing or ambiguous" in duplicate.get_data(as_text=True).lower()


def test_allow_transfer_export_is_not_blocked_by_unmapped_risk_slots(client, app, db, monkeypatch):
    from conftest import login_admin

    ensure_proxiware_swap_schema(db)
    subscription_id = _subscription(db, "allow-only-subscription")
    _assignment(db, subscription_id, "allow-only-assignment", host="allowed.proxy.example")
    _assignment(db, subscription_id, "risk-only-assignment", host="risk.proxy.example")
    db.execute("UPDATE provider_assignments SET qualification='risk' WHERE external_id='risk-only-assignment'")
    db.commit()
    allow_slot = next(slot for slot in load_proxiware_slots(db) if slot["external_id"] == "allow-only-assignment")
    app.config.update(RELAY_FEED_KEY="relay-shared-secret")

    class FeedResponse:
        content = b"{}"

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "complete": True,
                "count": 1,
                "items": [
                    {
                        "slot_key": allow_slot["slot_key"],
                        "relay_id": 19,
                        "proxy": "42.96.12.142:30019:client:relay-pass",
                        "enabled": 1,
                        "status": "live",
                        "protocol": "socks5",
                        "exit_ip": "198.51.100.42",
                    }
                ],
            }

    from app.routes import internal_api

    monkeypatch.setattr(internal_api.requests, "get", lambda *_args, **_kwargs: FeedResponse())
    login_admin(client)

    allowed = client.get("/admin/providers/proxiware/inventory/export/allow/transfer")
    all_slots = client.get("/admin/providers/proxiware/inventory/export/all/transfer")

    assert allowed.status_code == 200
    assert "allowed.proxy.example" not in allowed.get_data(as_text=True)
    assert "42.96.12.142:30019:client:relay-pass" in allowed.get_data(as_text=True)
    assert all_slots.status_code == 409
