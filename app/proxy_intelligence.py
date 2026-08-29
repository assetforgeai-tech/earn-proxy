"""Small, provider-agnostic normalization helpers for egress metadata."""

from __future__ import annotations

from collections.abc import Mapping


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
