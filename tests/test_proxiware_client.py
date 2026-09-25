from __future__ import annotations

import pytest

from app.services.proxiware import ProxiwareAPIError, ProxiwareClient, load_api_key_file


class FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses[url]


def test_client_sends_api_key_header_and_normalizes_list_payload():
    session = FakeSession(
        {
            "https://api.example/v1/static/networks/isp/subscriptions": FakeResponse(
                200, {"data": [{"id": 7, "network": "isp"}]}
            )
        }
    )
    client = ProxiwareClient("secret-key", base_url="https://api.example/v1", session=session)

    assert client.list_subscriptions() == [{"id": 7, "network": "isp"}]
    url, kwargs = session.calls[0]
    assert url == "https://api.example/v1/static/networks/isp/subscriptions"
    assert kwargs["headers"] == {"API-KEY": "secret-key", "Accept": "application/json"}
    assert kwargs["timeout"] == (5, 20)


def test_client_normalizes_account_and_proxy_list_payloads():
    session = FakeSession(
        {
            "https://api.example/v1/account": FakeResponse(200, {"id": 1, "email": "owner@example.com"}),
            "https://api.example/v1/static/subscriptions/7/proxies": FakeResponse(
                200, {"items": [{"id": 9, "host": "proxy.example"}]}
            ),
        }
    )
    client = ProxiwareClient("key", base_url="https://api.example/v1", session=session)

    assert client.get_account() == {"id": 1, "email": "owner@example.com"}
    assert client.list_subscription_proxies(7) == [{"id": 9, "host": "proxy.example"}]


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "bad_request"),
        (401, "authentication_error"),
        (403, "forbidden"),
        (404, "not_found"),
        (409, "conflict"),
        (429, "rate_limited"),
        (500, "provider_error"),
    ],
)
def test_client_maps_http_errors_to_safe_codes(status, code):
    session = FakeSession({"https://api.example/v1/account": FakeResponse(status, {"message": "secret-key"})})
    client = ProxiwareClient("secret-key", base_url="https://api.example/v1", session=session)

    with pytest.raises(ProxiwareAPIError) as raised:
        client.get_account()

    assert raised.value.code == code
    assert "secret-key" not in str(raised.value)
    assert raised.value.status_code == status


def test_client_rejects_malformed_json_payload():
    session = FakeSession({"https://api.example/v1/account": FakeResponse(200, ["not", "an", "account"])})
    client = ProxiwareClient("key", base_url="https://api.example/v1", session=session)

    with pytest.raises(ProxiwareAPIError) as raised:
        client.get_account()

    assert raised.value.code == "payload_error"


def test_api_key_file_accepts_raw_or_assignment_and_rejects_unsafe_values(tmp_path):
    raw = tmp_path / "raw.key"
    raw.write_text("  key-value-123  \n", encoding="utf-8")
    assignment = tmp_path / "assignment.env"
    assignment.write_text("PROXIWARE_API_KEY=key-value-456\n", encoding="utf-8")
    hyphen_assignment = tmp_path / "hyphen-assignment.env"
    hyphen_assignment.write_text("PROXIWARE-API-KEY=key-value-789\n", encoding="utf-8")
    multiline = tmp_path / "multiline.key"
    multiline.write_text("first\nsecond\n", encoding="utf-8")
    oversized = tmp_path / "oversized.key"
    oversized.write_text("x" * 513, encoding="utf-8")

    assert load_api_key_file(raw) == "key-value-123"
    assert load_api_key_file(assignment) == "key-value-456"
    assert load_api_key_file(hyphen_assignment) == "key-value-789"
    with pytest.raises(ValueError):
        load_api_key_file(multiline)
    with pytest.raises(ValueError):
        load_api_key_file(oversized)


def test_client_rejects_oversized_api_key():
    with pytest.raises(ValueError):
        ProxiwareClient("x" * 513)
