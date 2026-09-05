from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.services.proxies import add_proxy
from app.services.settings import set_setting
from app.services.users import create_user


def _online_proxy(db, user_id, raw, eligibility, exit_ip):
    proxy_id = add_proxy(db, user_id, raw)
    db.execute(
        "UPDATE proxies SET status='online', eligibility=?, exit_ip=?, egress_verified_at=?, "
        "egress_attestation_source='https_quorum', "
        "detected_protocol='socks5', last_success_at=? WHERE id=?",
        (eligibility, exit_ip, datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat(), proxy_id),
    )
    db.commit()
    return proxy_id


def test_internal_api_defaults_to_allow_and_risk_and_requires_key(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        _online_proxy(db, user_id, "allow.example:9001:u:allow-pass", "allow", "198.51.100.1")
        _online_proxy(db, user_id, "risk.example:9002:u:risk-pass", "risk", "198.51.100.2")

    assert client.get("/internal/api/v1/proxies").status_code == 401
    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.status_code == 200
    assert response.get_data(as_text=True).splitlines() == [
        "allow.example:9001:u:allow-pass",
        "risk.example:9002:u:risk-pass",
    ]


def test_admin_risk_toggle_applies_immediately_but_pause_earn_does_not_remove_proxy(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "one@example.com", "password", status="active")
        _online_proxy(db, user_id, "allow.example:9001:u:allow-pass", "allow", "198.51.100.1")
        _online_proxy(db, user_id, "risk.example:9002:u:risk-pass", "risk", "198.51.100.2")
        db.execute("UPDATE users SET earn_paused=1 WHERE id=?", (user_id,))
        set_setting(db, "api_include_risk", "0")

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["allow.example:9001:u:allow-pass"]


def test_api_excludes_blocked_user_offline_and_duplicate_proxy(app, client):
    with app.app_context():
        db = get_db()
        active = create_user(db, "active@example.com", "password", status="active")
        blocked = create_user(db, "blocked@example.com", "password", status="blocked")
        canonical = _online_proxy(db, active, "canonical.example:9001:u:p", "allow", "198.51.100.8")
        duplicate = _online_proxy(db, active, "duplicate.example:9002:u:p", "allow", "198.51.100.8")
        db.execute("UPDATE proxies SET duplicate_of=? WHERE id=?", (canonical, duplicate))
        offline = add_proxy(db, active, "offline.example:9003:u:p")
        db.execute(
            "UPDATE proxies SET status='offline', eligibility='allow' WHERE id=?",
            (offline,),
        )
        _online_proxy(db, blocked, "blocked.example:9004:u:p", "allow", "198.51.100.9")
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["canonical.example:9001:u:p"]


def test_api_excludes_stale_online_and_suspect_proxies(app, client):
    now = datetime.now(UTC)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "freshness@example.com", "password", status="active")
        fresh = _online_proxy(db, user_id, "fresh.example:9001:u:p", "allow", "198.51.100.31")
        stale = _online_proxy(db, user_id, "stale.example:9002:u:p", "allow", "198.51.100.32")
        suspect = _online_proxy(db, user_id, "suspect.example:9003:u:p", "allow", "198.51.100.33")
        db.execute(
            "UPDATE proxies SET last_success_at=? WHERE id=?", ((now - timedelta(minutes=30)).isoformat(), fresh)
        )
        db.execute(
            "UPDATE proxies SET last_success_at=? WHERE id=?", ((now - timedelta(minutes=121)).isoformat(), stale)
        )
        db.execute(
            "UPDATE proxies SET status='suspect', last_success_at=? WHERE id=?",
            ((now - timedelta(minutes=10)).isoformat(), suspect),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    assert response.get_data(as_text=True).splitlines() == ["fresh.example:9001:u:p"]


def test_api_excludes_online_rows_without_a_successful_health_observation(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "never-success@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "never-success.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', exit_ip=?, "
            "egress_verified_at=? WHERE id=?",
            ("198.51.100.40", datetime.now(UTC).isoformat(), proxy_id),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.get_data(as_text=True) == ""


def test_api_excludes_rows_without_a_canonical_egress(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "no-egress@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "no-egress.example:9001:u:p")
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', "
            "last_success_at=? WHERE id=?",
            (datetime.now(UTC).isoformat(), proxy_id),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.status_code == 200
    assert response.get_data(as_text=True) == ""


def test_api_excludes_legacy_egress_without_a_trusted_attestation_source(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "legacy-egress-api@example.com", "password", status="active")
        proxy_id = add_proxy(db, user_id, "legacy-egress-api.example:9001:u:p")
        now = datetime.now(UTC).isoformat()
        db.execute(
            "UPDATE proxies SET status='online', eligibility='allow', detected_protocol='socks5', "
            "exit_ip='198.51.100.44', egress_verified_at=?, last_success_at=? WHERE id=?",
            (now, now, proxy_id),
        )
        db.commit()

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.status_code == 200
    assert response.get_data(as_text=True) == ""


def test_api_uses_safe_freshness_default_when_setting_is_malformed(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "bad-setting@example.com", "password", status="active")
        _online_proxy(db, user_id, "fresh.example:9001:u:p", "allow", "198.51.100.41")
        set_setting(db, "health_stale_minutes", "not-a-number")

    response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})

    assert response.status_code == 200
    assert response.get_data(as_text=True).splitlines() == ["fresh.example:9001:u:p"]


def test_api_skips_corrupt_credentials_without_failing_the_distribution_batch(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "corrupt-api@example.com", "password", status="active")
        healthy = _online_proxy(db, user_id, "healthy.example:9001:u:good", "allow", "198.51.100.42")
        corrupt = _online_proxy(db, user_id, "corrupt.example:9002:u:bad", "allow", "198.51.100.43")
        db.execute("UPDATE proxies SET password_encrypted='not-fernet' WHERE id=?", (corrupt,))
        db.commit()

    text_response = client.get("/internal/api/v1/proxies", headers={"X-API-Key": "internal-test-key"})
    json_response = client.get(
        "/internal/api/v1/proxies?format=json",
        headers={"X-API-Key": "internal-test-key"},
    )

    assert text_response.status_code == 200
    assert text_response.get_data(as_text=True).splitlines() == ["healthy.example:9001:u:good"]
    assert json_response.status_code == 200
    assert [item["endpoint"] for item in json_response.get_json()] == ["healthy.example:9001"]
    assert healthy != corrupt


def test_canonical_api_alias_matches_legacy_endpoint(app, client):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "canonical-api@example.com", "password", status="active")
        _online_proxy(db, user_id, "canonical.example:9001:u:p", "allow", "198.51.100.50")

    headers = {"X-API-Key": "internal-test-key"}
    canonical = client.get("/api/v1/proxies?format=json", headers=headers)
    legacy = client.get("/internal/api/v1/proxies?format=json", headers=headers)

    assert canonical.status_code == 200
    assert canonical.get_json() == legacy.get_json()
    assert canonical.headers["Cache-Control"] == "no-store"


def test_canonical_api_alias_requires_the_same_key(client):
    response = client.get("/api/v1/proxies")
    assert response.status_code == 401


def test_legacy_api_alias_also_disables_caching(client):
    response = client.get(
        "/internal/api/v1/proxies",
        headers={"X-API-Key": "internal-test-key"},
    )
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_raw_and_transfer_api_paths_are_separate_and_typed(app, client, monkeypatch):
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "feed-split@example.com", "password", status="active")
        _online_proxy(db, user_id, "raw-split.example:9001:u:p", "allow", "198.51.100.60")

    class FeedResponse:
        status_code = 200
        content = b"[]"

        def raise_for_status(self):
            return None

        def json(self):
            return [
                {
                    "proxy": "proxy.acacondos.com:42001:relay-user:relay-pass",
                    "protocol": "socks5",
                    "exit_ip": "198.51.100.61",
                }
            ]

    from app.routes import internal_api

    monkeypatch.setattr(internal_api.requests, "get", lambda *args, **kwargs: FeedResponse())
    app.config.update(RELAY_FEED_KEY="test-relay-feed-key")
    headers = {"X-API-Key": "internal-test-key"}

    raw = client.get("/api/v1/proxy-raw?format=json", headers=headers)
    transfer = client.get("/api/v1/proxy-transfer?format=json", headers=headers)

    assert raw.status_code == 200
    assert raw.get_json()[0]["type"] == "raw"
    assert transfer.status_code == 200
    assert transfer.get_json() == [
        {
            "proxy": "proxy.acacondos.com:42001:relay-user:relay-pass",
            "type": "transfer",
            "protocol": "socks5",
            "exit_ip": "198.51.100.61",
        }
    ]
    assert transfer.headers["Cache-Control"] == "no-store"


def test_transfer_api_returns_service_unavailable_when_relay_feed_fails(client, monkeypatch):
    def fail(*_args, **_kwargs):
        raise TimeoutError("relay timeout")

    from app.routes import internal_api

    monkeypatch.setattr(internal_api.requests, "get", fail)
    response = client.get("/api/v1/proxy-transfer", headers={"X-API-Key": "internal-test-key"})

    assert response.status_code == 503
    assert response.get_json() == {"error": "Transfer feed is temporarily unavailable"}


def test_transfer_feed_limit_allows_the_full_fixed_listener_range():
    from app.routes.internal_api import MAX_TRANSFER_FEED_BYTES

    assert MAX_TRANSFER_FEED_BYTES >= 5_000_000
