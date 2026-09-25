from __future__ import annotations

import pytest

from app.services.proxiware_browser import (
    BrowserAdapterUnavailable,
    BrowserProviderResponseError,
    CdpProxiwareBrowser,
    DryRunProxiwareBrowser,
    UnavailableProxiwareBrowser,
    _dashboard_page_matches,
    build_browser_adapter,
)


def test_default_browser_adapter_fails_closed_without_provider_mutation():
    adapter = build_browser_adapter()

    assert isinstance(adapter, UnavailableProxiwareBrowser)
    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.swap({"id": 1})
    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.renew(email="owner@example.com", password="secret", captcha_token="token")


def test_dry_run_browser_adapter_records_intent_without_network_calls():
    adapter = DryRunProxiwareBrowser()

    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.swap({"id": 7})
    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.renew(email="owner@example.com", password="secret", captcha_token="token")

    assert adapter.operations == [{"action": "swap", "job_id": 7}, {"action": "renew_session"}]


def test_browser_adapter_rejects_non_loopback_cdp_endpoint():
    with pytest.raises(ValueError, match="loopback"):
        build_browser_adapter(enabled=True, cdp_url="https://public.example/cdp")


def test_browser_adapter_rejects_untrusted_dashboard_origin():
    with pytest.raises(ValueError, match="dashboard origin"):
        CdpProxiwareBrowser(
            "http://127.0.0.1:9222",
            dashboard_url="https://evil.example/static/proxy/isp",
        )


def test_browser_adapter_exposes_read_only_observation_separately_from_mutation():
    adapter = build_browser_adapter()

    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.observe_dashboard(subscription_id="sub-1")
    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.swap_assignment({"id": 1})


def test_dry_run_observation_records_intent_without_network_calls():
    adapter = DryRunProxiwareBrowser()

    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.observe_dashboard(subscription_id="sub-9")

    assert adapter.operations == [{"action": "observe_dashboard", "subscription_id": "sub-9"}]


class FakeCdp:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def evaluate(self, expression, arg=None):
        self.calls.append(("evaluate", expression, arg))
        return self.result

    def close(self):
        self.calls.append(("close",))


def test_enabled_loopback_browser_observes_typed_dashboard_rows_without_secrets():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies",
            "payload": {
                "proxies": [
                    {
                        "assignment_id": 141943,
                        "subscription_id": 39277,
                        "addr": "51.194.85.8:1337",
                        "eligible": True,
                        "connections": 5,
                        "username": "must-not-leak",
                        "password": "must-not-leak",
                    }
                ]
            },
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
    )

    rows = adapter.observe_dashboard(subscription_id="39277")
    adapter.close()

    assert len(rows) == 1
    assert rows[0].assignment_id == "141943"
    assert rows[0].subscription_id == "39277"
    assert rows[0].address == "51.194.85.8:1337"
    assert rows[0].eligible is True
    assert rows[0].connections == 5
    assert "must-not-leak" not in repr(rows)
    assert [call[0] for call in client.calls] == ["evaluate", "close"]
    assert "POST" not in str(client.calls)


def test_cdp_browser_reuses_session_context_after_restore():
    clients = []

    class SessionClient(FakeCdp):
        def __init__(self):
            super().__init__(
                {
                    "status": 200,
                    "origin": "https://app.proxiware.com",
                    "response_origin": "https://app.proxiware.com",
                    "path": "/static/proxy/isp",
                    "response_path": "/api/static/networks/isp/proxies",
                    "payload": {
                        "proxies": [
                            {
                                "assignment_id": "dashboard-1",
                                "subscription_id": "39277",
                                "addr": "51.194.85.8:1337",
                                "eligible": True,
                                "connections": 1,
                            }
                        ]
                    },
                }
            )
            self.cookies = None
            clients.append(self)

        def add_cookies(self, cookies):
            self.cookies = cookies

        @property
        def url(self):
            return "https://app.proxiware.com/static/proxy/isp"

        def navigate(self, _url):
            return None

    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=SessionClient,
    )

    adapter.restore_session([{"name": "session", "value": "opaque"}])
    rows = adapter.observe_dashboard(subscription_id="39277")
    adapter.close()

    assert len(clients) == 1
    assert clients[0].cookies == [
        {
            "name": "session",
            "value": "opaque",
            "url": "https://app.proxiware.com/static/proxy/isp",
        }
    ]
    assert rows[0].assignment_id == "dashboard-1"


def test_cdp_page_selection_ignores_unrelated_tabs():
    assert _dashboard_page_matches(
        "https://app.proxiware.com/static/proxy/isp",
        "https://app.proxiware.com/static/proxy/isp",
    )
    assert not _dashboard_page_matches(
        "https://cashpilot.example/dashboard",
        "https://app.proxiware.com/static/proxy/isp",
    )
    assert not _dashboard_page_matches(
        "https://app.proxiware.com/login",
        "https://app.proxiware.com/static/proxy/isp",
    )


def test_cdp_browser_rejects_wrong_origin_and_mutation_by_default():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://evil.example",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies",
            "payload": {"proxies": []},
        }
    )
    adapter = CdpProxiwareBrowser("http://127.0.0.1:9222", client_factory=lambda: client)

    with pytest.raises(BrowserAdapterUnavailable, match="origin"):
        adapter.observe_dashboard(subscription_id="39277")
    with pytest.raises(BrowserAdapterUnavailable, match="manual_action_required"):
        adapter.swap_assignment({"id": 1})


def test_cdp_browser_rejects_wrong_provider_api_path():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/not-proxies",
            "payload": {"proxies": []},
        }
    )
    adapter = CdpProxiwareBrowser("http://127.0.0.1:9222", client_factory=lambda: client)

    with pytest.raises(BrowserAdapterUnavailable, match="endpoint"):
        adapter.observe_dashboard(subscription_id="39277")


def test_cdp_browser_rejects_cross_origin_api_redirect():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://evil.example",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies",
            "payload": {"proxies": []},
        }
    )
    adapter = CdpProxiwareBrowser("http://127.0.0.1:9222", client_factory=lambda: client)

    with pytest.raises(BrowserAdapterUnavailable, match="origin"):
        adapter.observe_dashboard(subscription_id="39277")


def test_enabled_builder_requires_loopback_and_returns_cdp_adapter():
    adapter = build_browser_adapter(enabled=True, cdp_url="http://127.0.0.1:9222")

    assert isinstance(adapter, CdpProxiwareBrowser)


def test_cdp_swap_returns_provider_address_evidence_without_inventing_external_id():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {
                "swaps": [
                    {
                        "assignment_id": 141943,
                        "new_addr": "51.194.85.9",
                    }
                ]
            },
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    result = adapter.swap_assignment(
        {
            "dashboard_assignment_id": "141943",
            "old_assignment_external_id": "old-external-id",
        }
    )

    assert result == {
        "old_assignment_external_id": "old-external-id",
        "new_assignment_address": "51.194.85.9",
    }
    assert "assignment_ids" in str(client.calls)


def test_cdp_observation_maps_auth_failure_to_session_expiry():
    client = FakeCdp(
        {
            "status": 401,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies",
            "payload": {},
        }
    )
    adapter = CdpProxiwareBrowser("http://127.0.0.1:9222", client_factory=lambda: client)

    with pytest.raises(BrowserAdapterUnavailable, match="session_expired"):
        adapter.observe_dashboard(subscription_id="39277")


def test_cdp_swap_rejects_provider_error_without_claiming_success():
    client = FakeCdp(
        {
            "status": 503,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {},
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    with pytest.raises(BrowserProviderResponseError, match="provider_mutation_rejected"):
        adapter.swap_assignment({"dashboard_assignment_id": "141943", "old_assignment_external_id": "old"})
