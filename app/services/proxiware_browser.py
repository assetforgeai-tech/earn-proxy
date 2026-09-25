"""Fail-closed boundary for Proxiware browser/session operations.

The official API does not expose swap operations.  This module deliberately
keeps browser automation behind an injected adapter so a missing or
unreviewed browser implementation cannot turn a queue job into an accidental
provider mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


class BrowserAdapterUnavailable(RuntimeError):
    """Raised when no approved browser adapter is configured."""

    error_code = "manual_action_required"


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

    def swap(self, job: Any) -> dict[str, Any]:
        del job
        self._fail()
        return {}


@dataclass
class DryRunProxiwareBrowser(UnavailableProxiwareBrowser):
    """Record intended operations, then fail closed without network I/O."""

    operations: list[dict[str, Any]] = field(default_factory=list)

    def renew(self, *, email: str, password: str, captcha_token: str) -> dict[str, Any]:
        del email, password, captcha_token
        self.operations.append({"action": "renew_session"})
        self._fail()
        return {}

    def swap(self, job: Any) -> dict[str, Any]:
        job_id = job.get("id") if isinstance(job, dict) else None
        self.operations.append({"action": "swap", "job_id": int(job_id) if job_id is not None else None})
        self._fail()
        return {}


def build_browser_adapter(
    *,
    enabled: bool = False,
    cdp_url: str | None = None,
    dry_run: bool = False,
) -> UnavailableProxiwareBrowser | DryRunProxiwareBrowser:
    """Build only the explicitly enabled adapter; default is fail-closed."""

    endpoint = _validate_cdp_url(cdp_url)
    if dry_run:
        return DryRunProxiwareBrowser(endpoint)
    # A production adapter must be injected after provider flow review and
    # explicit deployment approval.  Never silently automate an undocumented
    # mutation endpoint from a default configuration.
    del enabled
    return UnavailableProxiwareBrowser(endpoint)


__all__ = [
    "BrowserAdapterUnavailable",
    "DryRunProxiwareBrowser",
    "UnavailableProxiwareBrowser",
    "build_browser_adapter",
]
