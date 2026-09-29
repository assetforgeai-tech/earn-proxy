from __future__ import annotations

import pytest

from app.services.proxiware_captcha import CaptchaProviderError, TwoCaptchaAdapter


class Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_hcaptcha_adapter_polls_until_token_without_logging_secret():
    session = Session(
        [
            Response({"errorId": 0, "taskId": "task-1"}),
            Response({"errorId": 0, "status": "processing"}),
            Response({"errorId": 0, "status": "ready", "solution": {"token": "solved-token"}}),
        ]
    )
    adapter = TwoCaptchaAdapter(
        "secret-api-key",
        session=session,
        poll_interval_seconds=0,
        max_wait_seconds=1,
    )

    assert (
        adapter.solve_hcaptcha(site_key="site-key", page_url="https://app.proxiware.com/auth/login") == "solved-token"
    )
    assert session.calls[0][1]["json"]["task"]["websiteKey"] == "site-key"


def test_hcaptcha_adapter_times_out_on_processing_task():
    session = Session(
        [
            Response({"errorId": 0, "taskId": "task-1"}),
            Response({"errorId": 0, "status": "processing"}),
        ]
    )
    adapter = TwoCaptchaAdapter("secret-api-key", session=session, poll_interval_seconds=0, max_wait_seconds=0)

    with pytest.raises(CaptchaProviderError) as exc_info:
        adapter.solve_hcaptcha(site_key="site-key", page_url="https://app.proxiware.com/auth/login")

    assert exc_info.value.code == "captcha_timeout"
    assert "secret-api-key" not in str(exc_info.value)


def test_hcaptcha_adapter_rejects_malformed_success_payload():
    session = Session(
        [
            Response({"errorId": 0, "taskId": "task-1"}),
            Response({"errorId": 0, "status": "ready", "solution": {}}),
        ]
    )
    adapter = TwoCaptchaAdapter("secret-api-key", session=session, poll_interval_seconds=0, max_wait_seconds=1)

    with pytest.raises(CaptchaProviderError) as exc_info:
        adapter.solve_hcaptcha(site_key="site-key", page_url="https://app.proxiware.com/auth/login")

    assert exc_info.value.code == "captcha_provider_error"
