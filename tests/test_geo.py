from datetime import UTC, datetime, timedelta

from app.db import get_db
from app.proxy_intelligence import (
    lookup_country,
    lookup_country_cached,
    merge_intelligence,
    normalize_ipwho_payload,
)


def test_geo_payload_is_normalized_without_exposing_provider_fields():
    country = normalize_ipwho_payload(
        {
            "success": True,
            "country_code": "us",
            "country": "United States",
            "latitude": 1,
        }
    )
    result = merge_intelligence(
        "198.51.100.4",
        country=country,
        quality={"is_datacenter": True, "secret": "hidden"},
    )
    assert result["country_code"] == "US"
    assert result["country_name"] == "United States"
    assert result["ip_type"] == "datacenter"
    assert "secret" not in result


def test_country_lookup_uses_public_egress_metadata():
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"success": True, "country_code": "us", "country": "United States"}

    def get(url, **kwargs):
        assert url == "https://ipwho.is/8.8.8.8"
        assert kwargs["timeout"] == 4.0
        assert kwargs["allow_redirects"] is False
        assert kwargs["proxies"] == {"http": None, "https": None}
        return Response()

    assert lookup_country("8.8.8.8", getter=get) == {
        "country_code": "US",
        "country_name": "United States",
        "geo_source": "ipwho.is",
        "geo_confidence": "verified",
    }


def test_country_lookup_is_best_effort_for_invalid_or_failed_requests():
    def fail(*_args, **_kwargs):
        raise RuntimeError("network unavailable")

    assert lookup_country("not-an-ip", getter=fail) == {}
    assert lookup_country("8.8.8.8", getter=fail) == {}


def test_country_cache_deduplicates_egress_lookups(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    calls = []

    def lookup(ip):
        calls.append(ip)
        return {"country_code": "US", "country_name": "United States", "geo_source": "test"}

    with app.app_context():
        db = get_db()
        first = lookup_country_cached(db, "8.8.8.8", now=now, lookup=lookup)
        second = lookup_country_cached(db, "8.8.8.8", now=now + timedelta(minutes=1), lookup=lookup)

    assert first["country_code"] == "US"
    assert second["country_code"] == "US"
    assert calls == ["8.8.8.8"]


def test_country_cache_rate_limits_failed_egress_lookups(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    calls = []

    def lookup(ip):
        calls.append(ip)
        return {}

    with app.app_context():
        db = get_db()
        assert lookup_country_cached(db, "1.1.1.1", now=now, lookup=lookup) == {}
        assert lookup_country_cached(db, "1.1.1.1", now=now + timedelta(minutes=1), lookup=lookup) == {}
        assert lookup_country_cached(db, "1.1.1.1", now=now + timedelta(minutes=16), lookup=lookup) == {}

    assert calls == ["1.1.1.1", "1.1.1.1"]


def test_country_cache_opens_provider_cooldown_after_lookup_failure(app):
    now = datetime(2026, 8, 29, 8, 0, tzinfo=UTC)
    calls = []

    def lookup(ip):
        calls.append(ip)
        if ip == "1.1.1.1":
            return {}
        return {"country_code": "US", "country_name": "United States", "geo_source": "test"}

    with app.app_context():
        db = get_db()
        assert lookup_country_cached(db, "1.1.1.1", now=now, lookup=lookup) == {}
        assert lookup_country_cached(db, "8.8.8.8", now=now + timedelta(minutes=1), lookup=lookup) == {}
        recovered = lookup_country_cached(db, "8.8.8.8", now=now + timedelta(minutes=16), lookup=lookup)

    assert recovered["country_code"] == "US"
    assert calls == ["1.1.1.1", "8.8.8.8"]
