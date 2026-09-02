"""Small, provider-agnostic normalization helpers for egress metadata."""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import requests

_IPWHO_URL = "https://ipwho.is/{ip}"
_PROVIDER_RETRY_SETTING = "country_lookup_retry_after"
COUNTRY_CACHE_TTL = timedelta(days=7)
COUNTRY_FAILURE_RETRY = timedelta(minutes=15)
_country_lookup_lock = threading.Lock()


def normalize_ipwho_payload(payload: Mapping | None) -> dict:
    data = dict(payload or {})
    if data.get("success") is not True:
        return {}
    return {
        "country_code": str(data.get("country_code") or "").strip().upper(),
        "country_name": str(data.get("country") or "").strip(),
        "geo_source": "ipwho.is",
        "geo_confidence": "verified",
    }


def lookup_country(exit_ip: str, *, timeout: float = 4.0, getter=requests.get) -> dict:
    """Resolve country metadata without making proxy health depend on the lookup."""
    value = str(exit_ip or "").strip()
    try:
        if not ipaddress.ip_address(value).is_global:
            return {}
        response = getter(
            _IPWHO_URL.format(ip=value),
            timeout=timeout,
            allow_redirects=False,
            proxies={"http": None, "https": None},
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            return {}
        return normalize_ipwho_payload(response.json())
    except Exception:  # noqa: BLE001 - metadata failure must never fail the qualification worker
        return {}


def _timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or ""))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _cached_country_payload(row) -> dict:
    code = str(row["country_code"] or "").strip().upper()
    if not code:
        return {}
    return {
        "country_code": code,
        "country_name": str(row["country_name"] or "").strip(),
        "geo_source": str(row["geo_source"] or "").strip(),
        "geo_confidence": str(row["geo_confidence"] or "unknown").strip(),
    }


def lookup_country_cached(
    db,
    exit_ip: str,
    *,
    now: datetime | None = None,
    lookup=lookup_country,
) -> dict:
    """Return cached egress country data and rate-limit repeated provider calls."""
    value = str(exit_ip or "").strip()
    try:
        if not ipaddress.ip_address(value).is_global:
            return {}
    except ValueError:
        return {}
    current = now or datetime.now(UTC)

    def read_fresh():
        row = db.execute("SELECT * FROM proxy_geo_cache WHERE exit_ip=?", (value,)).fetchone()
        if row is None:
            return None
        retry_after = _timestamp(row["retry_after"])
        checked_at = _timestamp(row["checked_at"])
        if retry_after and retry_after > current:
            return _cached_country_payload(row)
        if row["country_code"] and checked_at and current - checked_at < COUNTRY_CACHE_TTL:
            return _cached_country_payload(row)
        return None

    def provider_cooling_down() -> bool:
        row = db.execute("SELECT value FROM settings WHERE key=?", (_PROVIDER_RETRY_SETTING,)).fetchone()
        retry_after = _timestamp(row["value"]) if row is not None else None
        return bool(retry_after and retry_after > current)

    cached = read_fresh()
    if cached is not None:
        return cached
    if provider_cooling_down():
        return {}

    # The earnapp worker is separate from health checks, but two qualification
    # workers can still race during a restart. Serialize the small lookup gate.
    with _country_lookup_lock:
        cached = read_fresh()
        if cached is not None:
            return cached
        if provider_cooling_down():
            return {}
        result = dict(lookup(value) or {})
        code = str(result.get("country_code") or "").strip().upper()
        if len(code) != 2 or not code.isalpha():
            code = ""
        name = str(result.get("country_name") or "").strip() if code else ""
        source = str(result.get("geo_source") or "").strip() if code else ""
        confidence = str(result.get("geo_confidence") or "unknown").strip() if code else "unknown"
        retry_after = current + (COUNTRY_CACHE_TTL if code else COUNTRY_FAILURE_RETRY)
        provider_retry_after = "" if code else retry_after.isoformat()
        db.execute(
            """
            INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (_PROVIDER_RETRY_SETTING, provider_retry_after, current.isoformat()),
        )
        db.execute(
            """
            INSERT INTO proxy_geo_cache(exit_ip,country_code,country_name,geo_source,geo_confidence,checked_at,retry_after)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(exit_ip) DO UPDATE SET country_code=excluded.country_code,
                country_name=excluded.country_name, geo_source=excluded.geo_source,
                geo_confidence=excluded.geo_confidence, checked_at=excluded.checked_at,
                retry_after=excluded.retry_after
            """,
            (value, code, name, source, confidence, current.isoformat(), retry_after.isoformat()),
        )
        db.commit()
        if not code:
            return {}
        return {
            "country_code": code,
            "country_name": name,
            "geo_source": source,
            "geo_confidence": confidence,
        }


def merge_intelligence(exit_ip: str, *, country: Mapping | None = None, quality: Mapping | None = None) -> dict:
    country_data = dict(country or {})
    quality_data = dict(quality or {})
    if quality_data.get("is_vpn"):
        ip_type = "vpn"
    elif quality_data.get("is_proxy") or quality_data.get("is_tor"):
        ip_type = "proxy"
    elif quality_data.get("is_datacenter"):
        ip_type = "datacenter"
    elif quality_data.get("is_hosting"):
        ip_type = "hosting"
    elif quality_data:
        ip_type = "residential"
    else:
        ip_type = "unknown"
    country_code = str(country_data.get("country_code") or quality_data.get("country_code") or "").upper()
    country_name = str(country_data.get("country_name") or "").strip()
    return {
        "exit_ip": str(exit_ip or "").strip(),
        "country_code": country_code,
        "country_name": country_name,
        "location": country_name or country_code or "Unknown",
        "geo_source": str(country_data.get("geo_source") or ""),
        "geo_confidence": str(country_data.get("geo_confidence") or "unknown"),
        "ip_type": ip_type,
        "ip_type_source": str(quality_data.get("ip_type_source") or ""),
    }
