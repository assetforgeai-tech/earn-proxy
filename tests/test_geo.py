from app.proxy_intelligence import merge_intelligence, normalize_ipwho_payload


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
