"""Bounded 2Captcha hCaptcha client.

Only typed status/errors leave this module.  API keys and solved tokens never
enter logs, audit rows, or exception messages.
"""

from __future__ import annotations

import time
from time import monotonic
from typing import Any, Callable

import requests


class CaptchaProviderError(RuntimeError):
    """Safe error raised by the CAPTCHA provider boundary."""

    def __init__(self, code: str = "captcha_provider_error") -> None:
        self.code = str(code or "captcha_provider_error").strip().lower()
        super().__init__(self.code)


class TwoCaptchaAdapter:
    """Small JSON API adapter for one authorized 2Captcha account."""

    def __init__(
        self,
        api_key: str,
        *,
        session: requests.Session | None = None,
        base_url: str = "https://api.2captcha.com",
        timeout_seconds: float = 15.0,
        max_wait_seconds: float = 180.0,
        poll_interval_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        value = str(api_key or "").strip()
        if not value or "\r" in value or "\n" in value or len(value) > 512:
            raise ValueError("A single-line 2Captcha API key is required")
        self._api_key = value
        self._session = session or requests.Session()
        self._base_url = str(base_url or "").strip().rstrip("/")
        if not self._base_url:
            raise ValueError("2Captcha API base URL is required")
        self._timeout = max(0.1, float(timeout_seconds))
        self._max_wait = max(0.0, float(max_wait_seconds))
        self._poll_interval = max(0.0, float(poll_interval_seconds))
        self._sleep = sleep
        self._clock = clock

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._session.post(
                f"{self._base_url}/{path.lstrip('/')}",
                json=payload,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise CaptchaProviderError("captcha_timeout") from exc
        except requests.RequestException as exc:
            raise CaptchaProviderError("captcha_provider_error") from exc
        if int(getattr(response, "status_code", 0) or 0) < 200 or int(getattr(response, "status_code", 0) or 0) >= 300:
            raise CaptchaProviderError("captcha_provider_error")
        try:
            result = response.json()
        except (TypeError, ValueError) as exc:
            raise CaptchaProviderError("captcha_provider_error") from exc
        if not isinstance(result, dict):
            raise CaptchaProviderError("captcha_provider_error")
        if int(result.get("errorId") or 0) != 0:
            raise CaptchaProviderError("captcha_provider_error")
        return result

    def solve_hcaptcha(self, *, site_key: str, page_url: str) -> str:
        site = str(site_key or "").strip()
        page = str(page_url or "").strip()
        if not site or not page:
            raise CaptchaProviderError("captcha_provider_error")
        created = self._post(
            "/createTask",
            {
                "clientKey": self._api_key,
                "task": {
                    "type": "HCaptchaTaskProxyless",
                    "websiteURL": page,
                    "websiteKey": site,
                },
            },
        )
        task_id = str(created.get("taskId") or "").strip()
        if not task_id:
            raise CaptchaProviderError("captcha_provider_error")
        deadline = self._clock() + self._max_wait
        while True:
            if self._clock() > deadline:
                raise CaptchaProviderError("captcha_timeout")
            result = self._post(
                "/getTaskResult",
                {"clientKey": self._api_key, "taskId": task_id},
            )
            status = str(result.get("status") or "").strip().lower()
            if status == "ready":
                solution = result.get("solution")
                token = solution.get("gRecaptchaResponse") if isinstance(solution, dict) else None
                token = token or (solution.get("token") if isinstance(solution, dict) else None)
                if not isinstance(token, str) or not token.strip():
                    raise CaptchaProviderError("captcha_provider_error")
                return token.strip()
            if status != "processing":
                raise CaptchaProviderError("captcha_provider_error")
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise CaptchaProviderError("captcha_timeout")
            self._sleep(min(self._poll_interval, remaining))

    def get_balance(self) -> float:
        result = self._post("/getBalance", {"clientKey": self._api_key})
        try:
            balance = float(result.get("balance"))
        except (TypeError, ValueError) as exc:
            raise CaptchaProviderError("captcha_provider_error") from exc
        if balance < 0:
            raise CaptchaProviderError("captcha_provider_error")
        return balance


__all__ = ["CaptchaProviderError", "TwoCaptchaAdapter"]
