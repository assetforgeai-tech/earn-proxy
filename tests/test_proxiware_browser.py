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


class ScopedSwapCdp(FakeCdp):
    def evaluate(self, expression, arg=None):
        self.calls.append(("evaluate", expression, arg))
        if arg["path"] == "/api/static/networks/isp/proxies":
            return {
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
                            "connections": 2,
                        }
                    ]
                },
            }
        return self.result


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
    client = ScopedSwapCdp(
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
            "subscription_external_id": "39277",
        }
    )

    assert result == {
        "old_assignment_external_id": "old-external-id",
        "new_assignment_address": "51.194.85.9",
    }
    assert "assignment_ids" in str(client.calls)


def test_cdp_swap_request_uses_provider_xhr_header():
    client = ScopedSwapCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {"swaps": [{"assignment_id": 141943, "new_addr": "51.194.85.9"}]},
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    adapter.swap_assignment(
        {
            "dashboard_assignment_id": "141943",
            "old_assignment_external_id": "old-external-id",
            "subscription_external_id": "39277",
        }
    )

    expression = client.calls[0][1]
    assert "X-Requested-With" in expression
    assert "XMLHttpRequest" in expression


def test_cdp_swap_request_matches_selected_dashboard_row_payload():
    client = ScopedSwapCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {"swaps": [{"assignment_id": 141943, "new_addr": "51.194.85.9"}]},
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    adapter.swap_assignment(
        {
            "dashboard_assignment_id": "141943",
            "old_assignment_external_id": "old-external-id",
            "subscription_external_id": "39277",
        }
    )

    request = client.calls[1][2]
    assert request["body"]["assignment_ids"] == [141943]


def test_cdp_swap_native_timeout_is_passed_to_provider_fetch():
    client = ScopedSwapCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {"swaps": [{"assignment_id": 141943, "new_addr": "51.194.85.9"}]},
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    adapter.swap_with_timeout(
        {
            "dashboard_assignment_id": "141943",
            "old_assignment_external_id": "old-external-id",
            "subscription_external_id": "39277",
        },
        timeout_seconds=7,
    )

    request = client.calls[1][2]
    assert request["timeout_ms"] == 7000


def test_cdp_swap_rejects_non_numeric_dashboard_assignment_id_before_provider_call():
    client = FakeCdp({})
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    with pytest.raises(BrowserAdapterUnavailable, match="swap_identity_missing"):
        adapter.swap_assignment(
            {"dashboard_assignment_id": "ip:not-an-id", "old_assignment_external_id": "old-external-id"}
        )

    assert client.calls == []


def test_cdp_swap_requires_frozen_subscription_scope_before_provider_call():
    client = FakeCdp(
        {
            "status": 200,
            "origin": "https://app.proxiware.com",
            "response_origin": "https://app.proxiware.com",
            "path": "/static/proxy/isp",
            "response_path": "/api/static/networks/isp/proxies/swap",
            "payload": {"swaps": [{"assignment_id": 141943, "new_addr": "51.194.85.9"}]},
        }
    )
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    with pytest.raises(BrowserAdapterUnavailable, match="subscription_scope_missing"):
        adapter.swap_assignment({"dashboard_assignment_id": "141943", "old_assignment_external_id": "old-external-id"})

    assert client.calls == []


def test_cdp_swap_rejects_assignment_outside_frozen_subscription_scope_before_post():
    class ScopeClient(FakeCdp):
        def evaluate(self, expression, arg=None):
            self.calls.append(("evaluate", expression, arg))
            if arg["path"] == "/api/static/networks/isp/proxies":
                return {
                    "status": 200,
                    "origin": "https://app.proxiware.com",
                    "response_origin": "https://app.proxiware.com",
                    "path": "/static/proxy/isp",
                    "response_path": "/api/static/networks/isp/proxies",
                    "payload": {
                        "proxies": [
                            {
                                "assignment_id": 141943,
                                "subscription_id": 99999,
                                "addr": "51.194.85.8:1337",
                                "eligible": True,
                                "connections": 2,
                            }
                        ]
                    },
                }
            return {
                "status": 200,
                "origin": "https://app.proxiware.com",
                "response_origin": "https://app.proxiware.com",
                "path": "/static/proxy/isp",
                "response_path": "/api/static/networks/isp/proxies/swap",
                "payload": {"swaps": [{"assignment_id": 141943, "new_addr": "51.194.85.9"}]},
            }

    client = ScopeClient({})
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        allow_mutation=True,
    )

    with pytest.raises(BrowserAdapterUnavailable, match="subscription_scope_mismatch"):
        adapter.swap_assignment(
            {
                "dashboard_assignment_id": "141943",
                "old_assignment_external_id": "old-external-id",
                "subscription_external_id": "39277",
            }
        )

    assert [call[2]["path"] for call in client.calls] == ["/api/static/networks/isp/proxies"]


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
    client = ScopedSwapCdp(
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
        adapter.swap_assignment(
            {
                "dashboard_assignment_id": "141943",
                "old_assignment_external_id": "old",
                "subscription_external_id": "39277",
            }
        )


def test_cdp_browser_renews_login_with_fingerprint_and_cookies():
    class RenewClient(FakeCdp):
        def __init__(self):
            super().__init__(None)
            self.navigated = []

        def navigate(self, url):
            self.navigated.append(url)

        @property
        def url(self):
            return "https://app.proxiware.com/auth/login"

        def cookies(self):
            return [{"name": "session", "value": "opaque", "domain": "app.proxiware.com", "path": "/"}]

        def evaluate(self, expression, arg=None):
            self.calls.append(("evaluate", expression, arg))
            if "fp.proxiware.com" in expression:
                return {"visitor_id": "visitor", "event_id": "event"}
            assert arg["path"] == "/api/auth/login"
            assert arg["body"] == {
                "email": "owner@example.com",
                "password": "provider-password",
                "token": "captcha-token",
                "fp": "visitor",
                "fpr": "event",
            }
            return {
                "status": 200,
                "origin": "https://app.proxiware.com",
                "response_origin": "https://app.proxiware.com",
                "path": "/api/auth/login",
                "response_path": "/api/auth/login",
                "payload": {"success": True},
            }

    client = RenewClient()
    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: client,
        login_url="https://app.proxiware.com/auth/login?redirect=%2F",
        fingerprint_public_key="public-key",
    )

    result = adapter.renew(email="owner@example.com", password="provider-password", captcha_token="captcha-token")

    assert result["fingerprint_observed"] is True
    assert result["cookies"] == [
        {"name": "session", "value": "opaque", "domain": "app.proxiware.com", "path": "/"}
    ]
    assert client.navigated == ["https://app.proxiware.com/auth/login?redirect=%2F"]


def test_cdp_browser_clears_existing_provider_session_before_login():
    class RenewClient(FakeCdp):
        def __init__(self):
            super().__init__(None)
            self.cleared = False

        def clear_provider_session(self):
            self.cleared = True

        def navigate(self, _url):
            return None

        @property
        def url(self):
            return (
                "https://app.proxiware.com/auth/login"
                if self.cleared
                else "https://app.proxiware.com/static/proxy/isp"
            )

        def cookies(self):
            return [{"name": "session", "value": "fresh", "domain": "app.proxiware.com", "path": "/"}]

        def evaluate(self, expression, arg=None):
            self.calls.append(("evaluate", expression, arg))
            if "fp.proxiware.com" in expression:
                return {"visitor_id": "visitor", "event_id": "event"}
            assert arg["path"] == "/api/auth/login"
            return {
                "status": 200,
                "origin": "https://app.proxiware.com",
                "response_origin": "https://app.proxiware.com",
                "path": "/auth/login",
                "response_path": "/api/auth/login",
                "payload": {"success": True},
            }

    client = RenewClient()
    adapter = CdpProxiwareBrowser("http://127.0.0.1:9222", client_factory=lambda: client)

    result = adapter.renew(email="owner@example.com", password="provider-password", captcha_token="captcha-token")

    assert result["fingerprint_observed"] is True
    assert client.cleared is True


def test_cdp_browser_posts_legacy_login_page_to_auth_endpoint():
    class RenewClient(FakeCdp):
        def navigate(self, _url):
            return None

        @property
        def url(self):
            return "https://app.proxiware.com/login"

        def cookies(self):
            return [{"name": "session", "value": "opaque", "domain": "app.proxiware.com", "path": "/"}]

        def evaluate(self, expression, arg=None):
            self.calls.append(("evaluate", expression, arg))
            if "fp.proxiware.com" in expression:
                return {"visitor_id": "visitor", "event_id": "event"}
            assert arg["path"] == "/api/auth/login"
            return {
                "status": 200,
                "origin": "https://app.proxiware.com",
                "response_origin": "https://app.proxiware.com",
                "path": "/login",
                "response_path": "/api/auth/login",
                "payload": {"success": True},
            }

    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: RenewClient(None),
        login_url="https://app.proxiware.com/login",
    )

    result = adapter.renew(email="owner@example.com", password="provider-password", captcha_token="captcha-token")

    assert result["fingerprint_observed"] is True


def test_cdp_browser_site_key_discovery_checks_hcaptcha_iframe_url():
    class SiteKeyClient(FakeCdp):
        def navigate(self, _url):
            return None

        @property
        def url(self):
            return "https://app.proxiware.com/auth/login"

        def evaluate(self, expression, arg=None):
            self.calls.append(("evaluate", expression, arg))
            assert "iframe" in expression
            assert "sitekey" in expression
            return "iframe-site-key"

    adapter = CdpProxiwareBrowser(
        "http://127.0.0.1:9222",
        client_factory=lambda: SiteKeyClient(None),
    )

    assert adapter.discover_hcaptcha_site_key() == "iframe-site-key"
