"""Fail-closed boundary for Proxiware browser/session operations.

The official API does not expose swap operations.  This module deliberately
keeps browser automation behind an injected adapter so a missing or
unreviewed browser implementation cannot turn a queue job into an accidental
provider mutation.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from app.services.proxiware_dashboard import ProxiwareDashboardObserver, normalize_dashboard_address


class BrowserAdapterUnavailable(RuntimeError):
    """Raised when no approved browser adapter is configured."""

    error_code = "manual_action_required"

    def __init__(self, code: str = "manual_action_required") -> None:
        safe = str(code or "manual_action_required").strip().lower()
        self.error_code = (
            safe
            if safe
            in {
                "browser_dependency_missing",
                "browser_session_missing",
                "browser_transport_missing",
                "endpoint_mismatch",
                "invalid_session",
                "manual_action_required",
                "origin_mismatch",
                "session_expired",
                "subscription_scope_missing",
                "swap_identity_missing",
            }
            else "manual_action_required"
        )
        super().__init__(self.error_code)


class BrowserProviderResponseError(RuntimeError):
    """Raised when the browser response cannot prove a provider action."""

    error_code = "provider_error"

    def __init__(self, code: str = "provider_error") -> None:
        safe = str(code or "provider_error").strip().lower()
        self.error_code = (
            safe
            if safe
            in {
                "provider_error",
                "provider_mutation_rejected",
                "provider_read_failed",
                "provider_response_invalid",
                "provider_response_unconfirmed",
            }
            else "provider_error"
        )
        super().__init__(self.error_code)


def _validate_cdp_url(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    parsed = urlparse(str(value).strip())
    if parsed.scheme not in {"http", "https", "ws", "wss"} or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ValueError("CDP endpoint must be loopback")
    return str(value).strip()


def _safe_cookie_list(cookies: Any, *, url: str) -> list[dict[str, Any]]:
    """Keep only browser cookie fields accepted by Playwright."""

    rows = cookies if isinstance(cookies, list) else [cookies] if isinstance(cookies, dict) else []
    expected = urlparse(url)
    expected_origin = f"{expected.scheme}://{expected.netloc}".rstrip("/").lower()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("name") or "").strip():
            raise BrowserAdapterUnavailable("invalid_session")
        if "value" not in row:
            raise BrowserAdapterUnavailable("invalid_session")
        item: dict[str, Any] = {
            "name": str(row["name"]),
            "value": str(row["value"]),
        }
        cookie_url = str(row.get("url") or "").strip()
        cookie_domain = str(row.get("domain") or "").strip().lower().lstrip(".")
        if cookie_url:
            parsed_cookie_url = urlparse(cookie_url)
            if f"{parsed_cookie_url.scheme}://{parsed_cookie_url.netloc}".rstrip("/").lower() != expected_origin:
                raise BrowserAdapterUnavailable("invalid_session")
            item["url"] = cookie_url
        elif cookie_domain:
            if expected.hostname != cookie_domain and not str(expected.hostname or "").endswith(f".{cookie_domain}"):
                raise BrowserAdapterUnavailable("invalid_session")
            item["domain"] = str(row["domain"])
            item["path"] = str(row.get("path") or "/")
        else:
            item["url"] = url
        for key in ("expires", "httpOnly", "secure", "sameSite"):
            if key in row and row[key] is not None:
                item[key] = row[key]
        normalized.append(item)
    if not normalized:
        raise BrowserAdapterUnavailable("invalid_session")
    return normalized


class _PlaywrightCdpClient:
    """Small adapter around an already-running, loopback-only Chrome CDP."""

    def __init__(self, cdp_url: str, *, dashboard_url: str):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - deployment dependency
            raise BrowserAdapterUnavailable("browser_dependency_missing") from exc
        self._playwright = sync_playwright().start()
        try:
            self._browser = self._playwright.chromium.connect_over_cdp(cdp_url)
            contexts = self._browser.contexts
            self._context = contexts[0] if contexts else self._browser.new_context()
            pages = self._context.pages
            self._page = pages[0] if pages else self._context.new_page()
            self._dashboard_url = dashboard_url
        except Exception:
            self._playwright.stop()
            raise

    def navigate(self, url: str) -> None:
        self._page.goto(url, wait_until="domcontentloaded", timeout=20_000)

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._context.add_cookies(cookies)

    @property
    def url(self) -> str:
        return str(self._page.url)

    def evaluate(self, expression: str, arg: Any = None) -> Any:
        return self._page.evaluate(expression, arg)

    def close(self) -> None:
        # Disconnect the CDP client without closing the operator's browser.
        self._playwright.stop()


class _PayloadTransport:
    def __init__(self, payload: Any):
        self.payload = payload

    def request_json(self, method: str, path: str, *, body: Any = None) -> Any:
        del method, path, body
        return self.payload


@dataclass
class CdpProxiwareBrowser:
    """Verified read-only dashboard adapter with an explicit mutation fence."""

    cdp_url: str
    dashboard_url: str = "https://app.proxiware.com/static/proxy/isp"
    client_factory: Callable[[], Any] | None = None
    allow_mutation: bool = False

    def __post_init__(self) -> None:
        parsed = urlparse(self.dashboard_url)
        if parsed.scheme != "https" or parsed.netloc.lower() != "app.proxiware.com":
            raise ValueError("dashboard origin must be https://app.proxiware.com")
        if parsed.path.rstrip("/") != "/static/proxy/isp":
            raise ValueError("dashboard path is invalid")

    @property
    def _origin(self) -> str:
        return str(urlparse(self.dashboard_url).scheme + "://" + (urlparse(self.dashboard_url).netloc)).rstrip("/")

    @contextmanager
    def _client(self) -> Iterator[Any]:
        factory = self.client_factory or (lambda: _PlaywrightCdpClient(self.cdp_url, dashboard_url=self.dashboard_url))
        client = factory()
        try:
            yield client
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()

    def _navigate(self, client: Any) -> None:
        navigate = getattr(client, "navigate", None)
        if callable(navigate):
            navigate(self.dashboard_url)
        current_url = str(getattr(client, "url", self.dashboard_url) or self.dashboard_url)
        parsed = urlparse(current_url)
        if f"{parsed.scheme}://{parsed.netloc}".rstrip("/") != self._origin:
            raise BrowserAdapterUnavailable("origin_mismatch")
        expected_path = urlparse(self.dashboard_url).path.rstrip("/") or "/"
        if parsed.path.rstrip("/") != expected_path:
            raise BrowserAdapterUnavailable("session_expired")

    @staticmethod
    def _fetch_expression(_arg: Any) -> str:
        return """async ({path, method, body}) => {
          const headers = {Accept: 'application/json'};
          if (body !== null) {
            headers['Content-Type'] = 'application/json';
            const csrf = document.cookie.match(/(?:^|;\\s*)csrf=([^;]*)/);
            if (csrf) headers['X-CSRF-Token'] = decodeURIComponent(csrf[1]);
          }
          const response = await fetch(path, {
            method, credentials: 'include', headers,
            body: body === null ? undefined : JSON.stringify(body)
          });
          let payload = null;
          try { payload = await response.json(); } catch (_) {}
          const responseUrl = new URL(response.url);
          return {status: response.status, origin: location.origin,
                  response_origin: responseUrl.origin, path: location.pathname,
                  response_path: responseUrl.pathname, payload};
        }"""

    def _fetch(self, client: Any, *, path: str, method: str = "GET", body: Any = None) -> dict[str, Any]:
        evaluate = getattr(client, "evaluate", None)
        if not callable(evaluate):
            raise BrowserAdapterUnavailable("browser_transport_missing")
        result = evaluate(
            self._fetch_expression(None),
            {"path": path, "method": method, "body": body},
        )
        if not isinstance(result, dict):
            raise BrowserProviderResponseError("provider_response_invalid")
        if str(result.get("origin") or "").rstrip("/") != self._origin:
            raise BrowserAdapterUnavailable("origin_mismatch")
        if str(result.get("response_origin") or "").rstrip("/") != self._origin:
            raise BrowserAdapterUnavailable("origin_mismatch")
        if str(result.get("response_path") or "") != path:
            raise BrowserAdapterUnavailable("endpoint_mismatch")
        return result

    def restore_session(self, cookies: Any) -> None:
        with self._client() as client:
            add_cookies = getattr(client, "add_cookies", None)
            if not callable(add_cookies):
                raise BrowserAdapterUnavailable("browser_session_missing")
            add_cookies(_safe_cookie_list(cookies, url=self.dashboard_url))
            self._navigate(client)

    def observe_dashboard(self, *, subscription_id: str) -> list[Any]:
        requested = str(subscription_id or "").strip()
        if not requested:
            raise BrowserAdapterUnavailable("subscription_scope_missing")
        with self._client() as client:
            self._navigate(client)
            result = self._fetch(client, path="/api/static/networks/isp/proxies")
            status = int(result.get("status") or 0)
            if status in {401, 403}:
                raise BrowserAdapterUnavailable("session_expired")
            if status != 200:
                raise BrowserProviderResponseError("provider_read_failed")
            observed_at = datetime.now(UTC)
            rows = ProxiwareDashboardObserver(
                _PayloadTransport(result.get("payload")), now=lambda: observed_at
            ).observe(subscription_id=requested)
            return rows

    def swap_assignment(self, job: Any) -> dict[str, Any]:
        if not self.allow_mutation:
            raise BrowserAdapterUnavailable("manual_action_required")
        if not isinstance(job, dict):
            job = dict(job)
        assignment_id = str(job.get("dashboard_assignment_id") or "").strip()
        old_external = str(job.get("old_assignment_external_id") or "").strip()
        if not assignment_id or not old_external:
            raise BrowserAdapterUnavailable("swap_identity_missing")
        with self._client() as client:
            self._navigate(client)
            result = self._fetch(
                client,
                path="/api/static/networks/isp/proxies/swap",
                method="POST",
                body={"assignment_ids": [assignment_id]},
            )
            if int(result.get("status") or 0) not in {200, 201, 202}:
                raise BrowserProviderResponseError("provider_mutation_rejected")
            payload = result.get("payload")
            swaps = payload.get("swaps") if isinstance(payload, dict) else None
            if not isinstance(swaps, list) or len(swaps) != 1 or not isinstance(swaps[0], dict):
                raise BrowserProviderResponseError("provider_response_unconfirmed")
            swap = swaps[0]
            returned_id = str(swap.get("assignment_id") or "").strip()
            try:
                new_address = normalize_dashboard_address(swap.get("new_addr"))
            except (TypeError, ValueError):
                raise BrowserProviderResponseError("provider_response_unconfirmed") from None
            # The dashboard response exposes the replacement address, not a
            # durable inventory ID.  Never manufacture an ID from that value;
            # official read-only sync resolves the ID during reconciliation.
            if returned_id != assignment_id or not new_address:
                raise BrowserProviderResponseError("provider_response_unconfirmed")
            evidence = {
                "old_assignment_external_id": old_external,
                "new_assignment_address": new_address,
            }
            explicit_external = str(swap.get("new_assignment_external_id") or "").strip()
            if explicit_external:
                evidence["new_assignment_external_id"] = explicit_external
            return evidence

    def swap(self, job: Any) -> dict[str, Any]:
        return self.swap_assignment(job)


@dataclass
class UnavailableProxiwareBrowser:
    """Placeholder used until an explicitly reviewed adapter is installed."""

    cdp_url: str | None = None

    def _fail(self) -> None:
        raise BrowserAdapterUnavailable("manual_action_required")

    def renew(self, *, email: str, password: str, captcha_token: str) -> dict[str, Any]:
        del email, password, captcha_token
        self._fail()
        return {}

    def restore_session(self, cookies: Any) -> None:
        del cookies
        self._fail()

    def observe_dashboard(self, *, subscription_id: str) -> list[Any]:
        del subscription_id
        self._fail()
        return []

    def swap_assignment(self, job: Any) -> dict[str, Any]:
        del job
        self._fail()
        return {}

    def swap(self, job: Any) -> dict[str, Any]:
        return self.swap_assignment(job)


@dataclass
class DryRunProxiwareBrowser(UnavailableProxiwareBrowser):
    """Record intended operations, then fail closed without network I/O."""

    operations: list[dict[str, Any]] = field(default_factory=list)

    def renew(self, *, email: str, password: str, captcha_token: str) -> dict[str, Any]:
        del email, password, captcha_token
        self.operations.append({"action": "renew_session"})
        self._fail()
        return {}

    def restore_session(self, cookies: Any) -> None:
        del cookies
        self.operations.append({"action": "restore_session"})
        self._fail()

    def observe_dashboard(self, *, subscription_id: str) -> list[Any]:
        self.operations.append({"action": "observe_dashboard", "subscription_id": str(subscription_id)})
        self._fail()
        return []

    def swap_assignment(self, job: Any) -> dict[str, Any]:
        job_id = job.get("id") if isinstance(job, dict) else None
        self.operations.append({"action": "swap", "job_id": int(job_id) if job_id is not None else None})
        self._fail()
        return {}


def build_browser_adapter(
    *,
    enabled: bool = False,
    cdp_url: str | None = None,
    dry_run: bool = False,
    dashboard_url: str = "https://app.proxiware.com/static/proxy/isp",
    allow_mutation: bool = False,
) -> UnavailableProxiwareBrowser | DryRunProxiwareBrowser | CdpProxiwareBrowser:
    """Build only the explicitly enabled adapter; default is fail-closed."""

    endpoint = _validate_cdp_url(cdp_url)
    if dry_run:
        return DryRunProxiwareBrowser(endpoint)
    if enabled and endpoint:
        return CdpProxiwareBrowser(
            endpoint,
            dashboard_url=dashboard_url,
            allow_mutation=bool(allow_mutation),
        )
    return UnavailableProxiwareBrowser(endpoint)


__all__ = [
    "BrowserAdapterUnavailable",
    "BrowserProviderResponseError",
    "CdpProxiwareBrowser",
    "DryRunProxiwareBrowser",
    "UnavailableProxiwareBrowser",
    "build_browser_adapter",
]
