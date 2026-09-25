from __future__ import annotations

import pytest

from app.services.proxiware_browser import (
    BrowserAdapterUnavailable,
    DryRunProxiwareBrowser,
    UnavailableProxiwareBrowser,
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
