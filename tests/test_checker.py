from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from app.checker import PROBE_URLS, check_proxy, parse_exit_ip

PROXY = {
    "host": "upstream",
    "port": 1080,
    "username": "u",
    "password": "p",
    "protocol": "socks5",
}


def curl_response(
    probe,
    ip="203.0.113.8",
    code="200",
    effective_url=None,
    returncode=0,
    ssl_result="0",
):
    effective_url = effective_url or probe
    body = (ip + "\n") if ip else ""
    return SimpleNamespace(
        returncode=returncode,
        stdout=f"{body}__PROBE_META__:{code}|{effective_url}|{ssl_result}\n",
        stderr="",
    )


def test_exit_ip_parser_accepts_ip_literals_and_rejects_markup():
    assert parse_exit_ip("203.0.113.8\n") == "203.0.113.8"
    assert parse_exit_ip("2001:db8::8\n") == "2001:db8::8"
    assert parse_exit_ip("<!doctype html>") == ""


def test_verified_quorum_requires_two_independent_https_hosts():
    ips = {
        PROBE_URLS[0]: "203.0.113.10",
        PROBE_URLS[1]: "203.0.113.11",
        PROBE_URLS[2]: "203.0.113.10",
    }

    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], ip=ips[cmd[-1]])

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live"
    assert result["protocol"] == "socks5"
    assert result["exit_ip"] == "203.0.113.10"


def test_checker_falls_back_to_plain_http_when_tls_is_unavailable():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if probe.startswith("https://"):
            return SimpleNamespace(returncode=28, stdout="", stderr="timeout")
        return curl_response(probe, ip="203.0.113.25")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live"
    assert result["exit_ip"] == "203.0.113.25"


def test_auto_detection_prefers_socks5_and_does_not_open_http_after_success():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return curl_response(cmd[-1], ip="203.0.113.22")

    result = check_proxy({**PROXY, "protocol": "auto"}, runner=runner)
    assert result["protocol"] == "socks5"
    assert calls[0][calls[0].index("--proxy") + 1].startswith("socks5h://")
    assert not any(cmd[cmd.index("--proxy") + 1].startswith("http://") for cmd in calls)


def test_verified_tls_quorum_skips_plain_http_fallback_probes():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd[-1])
        return curl_response(cmd[-1], ip="203.0.113.30")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live"
    assert not any(url.startswith("http://") for url in calls)


def test_auto_detection_falls_back_to_http_after_socks_timeout():
    def runner(cmd, **kwargs):
        proxy_url = cmd[cmd.index("--proxy") + 1]
        if proxy_url.startswith("socks5h://"):
            return SimpleNamespace(returncode=28, stdout="", stderr="timeout")
        return curl_response(cmd[-1], ip="203.0.113.23")

    result = check_proxy({**PROXY, "protocol": "auto"}, runner=runner)
    assert result["status"] == "live"
    assert result["protocol"] == "http"


def test_captive_portal_is_blocked_even_if_other_probe_succeeds():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if probe == PROBE_URLS[-1]:
            return SimpleNamespace(
                returncode=0,
                stdout="<!doctype html><link href='/internet/logo.svg'>\n"
                "__PROBE_META__:200|https://giahan.vnpt.com.vn/internet/|19\n",
                stderr="",
            )
        return curl_response(probe, ip="203.0.113.21")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "blocked"
    assert "giahan.vnpt.com.vn" in result["error"]


def test_repeated_timeouts_are_inconclusive_not_dead():
    calls = Counter()

    def runner(cmd, **kwargs):
        calls[cmd[-1]] += 1
        return SimpleNamespace(returncode=28, stdout="", stderr="timeout")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "inconclusive"
    assert len(calls) >= len(PROBE_URLS)


def test_tls_certificate_error_can_be_live_unverified_with_matching_quorum():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if "--insecure" in cmd:
            return curl_response(probe, ip="203.0.113.17", ssl_result="19")
        return SimpleNamespace(returncode=60, stdout="", stderr="certificate error")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live_unverified"
    assert result["exit_ip"] == "203.0.113.17"
