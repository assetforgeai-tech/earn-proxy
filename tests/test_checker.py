from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from app.checker import (
    MAX_PROBE_OUTPUT_BYTES,
    PROBE_URLS,
    PROXIO_MIN_INTERVAL_SECONDS,
    PROXIO_WHOAMI_URL,
    _bounded_subprocess_run,
    _wait_for_probe_slot,
    check_proxy,
    check_proxy_fast,
    check_proxy_strong,
    parse_exit_ip,
    parse_probe_exit_ip,
)

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


def test_proxio_probe_parser_accepts_only_the_json_ip_field():
    body = '{"ip":"203.0.113.81","http":{"remote_ip":"198.51.100.9"}}'

    assert parse_probe_exit_ip(PROXIO_WHOAMI_URL, body) == "203.0.113.81"
    assert parse_probe_exit_ip(PROXIO_WHOAMI_URL, '{"remote_ip":"198.51.100.9"}') == ""
    assert parse_probe_exit_ip(PROXIO_WHOAMI_URL, "not-json") == ""
    assert parse_probe_exit_ip(PROBE_URLS[0], "203.0.113.82\n") == "203.0.113.82"


def test_proxio_probe_rate_limiter_caps_sustained_calls(monkeypatch):
    clock = {"now": 100.0}
    sleeps = []
    monkeypatch.setattr("app.checker._proxio_next_request_at", 0.0)

    def monotonic():
        return clock["now"]

    def sleeper(seconds):
        sleeps.append(seconds)
        clock["now"] += seconds

    _wait_for_probe_slot(PROXIO_WHOAMI_URL, clock=monotonic, sleeper=sleeper)
    _wait_for_probe_slot(PROXIO_WHOAMI_URL, clock=monotonic, sleeper=sleeper)
    _wait_for_probe_slot(PROBE_URLS[0], clock=monotonic, sleeper=sleeper)

    assert len(sleeps) == 1
    assert round(sleeps[0], 3) == PROXIO_MIN_INTERVAL_SECONDS


def test_verified_quorum_accepts_proxio_as_one_independent_json_source():
    other_probe = next(probe for probe in PROBE_URLS if probe != PROXIO_WHOAMI_URL)

    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if probe == PROXIO_WHOAMI_URL:
            response = curl_response(probe, ip="")
            response.stdout = (
                f'{{"ip":"203.0.113.83","http":{{"remote_ip":"198.51.100.9"}}}}__PROBE_META__:200|{probe}|0\n'
            )
            return response
        if probe == other_probe:
            return curl_response(probe, ip="203.0.113.83")
        return curl_response(probe, ip="203.0.113.84")

    result = check_proxy(PROXY, runner=runner)

    assert result["status"] == "live"
    assert result["exit_ip"] == "203.0.113.83"
    assert result["egress_trusted"] is True


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
    assert result["egress_trusted"] is True


def test_checker_falls_back_to_plain_http_when_tls_is_unavailable():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if probe.startswith("https://"):
            return SimpleNamespace(returncode=28, stdout="", stderr="timeout")
        return curl_response(probe, ip="203.0.113.25")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live_unverified"
    assert result["exit_ip"] == "203.0.113.25"
    assert result["egress_trusted"] is False


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


def test_probe_endpoint_outage_is_inconclusive_not_dead():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], code="503", ip="")

    result = check_proxy(PROXY, runner=runner)

    assert result["status"] == "inconclusive"
    assert result["failure_kind"] == "probe_endpoint"


def test_proxio_rate_limit_is_inconclusive_not_proxy_death():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        return curl_response(probe, code="429" if probe == PROXIO_WHOAMI_URL else "503", ip="")

    result = check_proxy(PROXY, runner=runner)

    assert result["status"] == "inconclusive"
    assert result["failure_kind"] == "probe_endpoint"


def test_consistent_proxy_connection_failures_are_confirmed_dead():
    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=7, stdout="", stderr="connection refused")

    result = check_proxy(PROXY, runner=runner)

    assert result["status"] == "dead"
    assert result["failure_kind"] == "proxy"


def test_proxy_authentication_failures_are_not_misclassified_as_probe_outages():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], code="407", ip="")

    fast = check_proxy_fast(PROXY, runner=runner)
    strong = check_proxy_strong(PROXY, runner=runner)

    assert fast["status"] == "needs_confirmation"
    assert fast["failure_kind"] == "proxy"
    assert strong["status"] == "dead"
    assert strong["failure_kind"] == "proxy"


def test_socks_proxy_handshake_failure_code_is_confirmed_proxy_failure():
    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=97, stdout="", stderr="proxy handshake error")

    result = check_proxy_strong(PROXY, runner=runner)

    assert result["status"] == "dead"
    assert result["failure_kind"] == "proxy"


def test_tls_certificate_error_can_be_live_unverified_with_matching_quorum():
    def runner(cmd, **kwargs):
        probe = cmd[-1]
        if "--insecure" in cmd:
            return curl_response(probe, ip="203.0.113.17", ssl_result="19")
        return SimpleNamespace(returncode=60, stdout="", stderr="certificate error")

    result = check_proxy(PROXY, runner=runner)
    assert result["status"] == "live_unverified"
    assert result["exit_ip"] == "203.0.113.17"
    assert result["egress_trusted"] is False


def test_fast_check_uses_one_rotating_endpoint_and_detected_protocol():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return curl_response(cmd[-1], ip="203.0.113.40")

    result = check_proxy_fast(PROXY, probe_index=1, runner=runner)

    assert result["status"] == "live"
    assert result["exit_ip"] == "203.0.113.40"
    assert result["probe_endpoint"] == PROBE_URLS[1]
    assert result["next_probe_index"] == 2
    assert result["failure_kind"] == ""
    assert result["egress_trusted"] is False
    assert len(calls) == 1
    assert calls[0][calls[0].index("--proxy") + 1].startswith("socks5h://")


def test_proxy_credentials_are_passed_over_stdin_not_exposed_in_process_arguments():
    captured = {}

    def runner(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input", "")
        return curl_response(cmd[-1], ip="203.0.113.40")

    check_proxy_fast(
        {
            **PROXY,
            "username": "visible-user",
            "password": "very-secret-password",
        },
        runner=runner,
    )

    arguments = " ".join(captured["cmd"])
    assert "visible-user" not in arguments
    assert "very-secret-password" not in arguments
    assert 'proxy = "socks5h://upstream:1080"' in captured["input"]
    assert 'proxy-user = "visible-user:very-secret-password"' in captured["input"]


def test_probe_caps_response_size_and_reads_curl_metadata_from_the_final_marker():
    captured = {}

    def runner(cmd, **kwargs):
        captured["cmd"] = cmd
        stdout = (
            "198.51.100.77\n"
            "__PROBE_META__:200|https://ifconfig.me/ip|0\n"
            "attacker-controlled-body\n"
            "__PROBE_META__:503|https://ifconfig.me/ip|0\n"
        )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    result = check_proxy_fast(PROXY, runner=runner)

    assert "--max-filesize" in captured["cmd"]
    assert result["status"] == "inconclusive"
    assert result["exit_ip"] == ""


def test_bounded_subprocess_stops_and_truncates_stdout_overflow():
    command = [
        __import__("sys").executable,
        "-c",
        f"import sys,time; sys.stdout.buffer.write(b'x'*{MAX_PROBE_OUTPUT_BYTES + 8192}); "
        "sys.stdout.flush(); time.sleep(10)",
    ]

    result = _bounded_subprocess_run(command, "", timeout=5)

    assert result.returncode == 125
    assert len(result.stdout.encode("utf-8")) == MAX_PROBE_OUTPUT_BYTES
    assert "probe output exceeded the safety limit" in result.stderr


def test_checker_pins_the_runtime_validated_public_proxy_address(monkeypatch):
    captured = {}

    def runner(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs["input"]
        return curl_response(cmd[-1], ip="203.0.113.40")

    result = check_proxy_fast(PROXY, runner=runner, resolver=lambda host, port: "8.8.8.8")

    assert result["status"] == "live"
    proxy_args = [captured["cmd"][index + 1] for index, value in enumerate(captured["cmd"]) if value == "--proxy"]
    assert any("8.8.8.8:1080" in value for value in proxy_args)
    assert 'proxy = "socks5h://8.8.8.8:1080"' in captured["input"]


def test_checker_rejects_unsafe_runtime_target_before_starting_curl(monkeypatch):
    calls = []

    def reject(*_args, **_kwargs):
        from app.network_safety import UnsafeProxyTarget

        raise UnsafeProxyTarget("private proxy target")

    result = check_proxy_fast(
        PROXY,
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        resolver=reject,
    )

    assert calls == []
    assert result["status"] == "needs_confirmation"
    assert result["failure_kind"] == "unsafe_target"


def test_checker_formats_a_pinned_ipv6_proxy_target(monkeypatch):
    captured = {}

    def runner(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs["input"]
        return curl_response(cmd[-1], ip="203.0.113.43")

    result = check_proxy_fast(
        {**PROXY, "host": "proxy.example"},
        runner=runner,
        resolver=lambda host, port: "2001:4860:4860::8888",
    )

    assert result["status"] == "live"
    proxy_arg = captured["cmd"][captured["cmd"].index("--proxy") + 1]
    assert proxy_arg == "socks5h://[2001:4860:4860::8888]:1080"
    assert 'proxy = "socks5h://[2001:4860:4860::8888]:1080"' in captured["input"]


def test_fast_check_skips_an_open_probe_endpoint_circuit():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd[-1])
        return curl_response(cmd[-1], ip="203.0.113.41")

    result = check_proxy_fast(
        PROXY,
        probe_index=0,
        unavailable_endpoints={PROBE_URLS[0]},
        runner=runner,
    )

    assert calls == [PROBE_URLS[1]]
    assert result["probe_endpoint"] == PROBE_URLS[1]
    assert result["next_probe_index"] == 2


def test_fast_check_never_auto_detects_a_second_protocol():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=28, stdout="", stderr="timeout")

    result = check_proxy_fast({**PROXY, "protocol": "auto"}, runner=runner)

    assert result["status"] == "needs_confirmation"
    assert result["failure_kind"] == "transient"
    assert len(calls) == 1
    assert calls[0][calls[0].index("--proxy") + 1].startswith("socks5h://")


def test_fast_check_requests_confirmation_when_exit_ip_changes():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], ip="203.0.113.42")

    result = check_proxy_fast(PROXY, expected_exit_ip="203.0.113.41", runner=runner)

    assert result["status"] == "needs_confirmation"
    assert result["failure_kind"] == "egress_changed"
    assert result["exit_ip"] == "203.0.113.42"


def test_fast_check_classifies_third_party_endpoint_failure_separately():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], code="503", ip="")

    result = check_proxy_fast(PROXY, runner=runner)

    assert result["status"] == "inconclusive"
    assert result["failure_kind"] == "probe_endpoint"


def test_fast_check_treats_proxy_host_dns_failure_as_inconclusive():
    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=5, stdout="", stderr="Could not resolve proxy")

    result = check_proxy_fast(PROXY, runner=runner)

    assert result["status"] == "inconclusive"
    assert result["failure_kind"] == "proxy_dns"


def test_strong_check_exposes_probe_metadata_and_compatibility_alias():
    def runner(cmd, **kwargs):
        return curl_response(cmd[-1], ip="203.0.113.50")

    strong = check_proxy_strong(PROXY, runner=runner)
    compatible = check_proxy(PROXY, runner=runner)

    assert strong["status"] == compatible["status"] == "live"
    assert strong["failure_kind"] == ""
    assert strong["probe_endpoint"]


def test_strong_check_skips_open_probe_endpoint_circuits():
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd[-1])
        return curl_response(cmd[-1], ip="203.0.113.51")

    result = check_proxy_strong(
        PROXY,
        unavailable_endpoints={PROBE_URLS[0]},
        runner=runner,
    )

    assert result["status"] == "live"
    assert PROBE_URLS[0] not in calls


def test_auto_detection_reserves_timeout_budget_for_http_protocol(monkeypatch):
    clock = {"now": 0.0}
    protocols = []

    monkeypatch.setattr("app.checker.time.monotonic", lambda: clock["now"])

    def runner(cmd, **kwargs):
        proxy_url = cmd[cmd.index("--proxy") + 1]
        protocols.append(proxy_url.split(":", 1)[0])
        if proxy_url.startswith("socks5h://"):
            clock["now"] += float(cmd[cmd.index("--max-time") + 1])
            return SimpleNamespace(returncode=28, stdout="", stderr="timeout")
        return curl_response(cmd[-1], ip="203.0.113.60")

    result = check_proxy_strong({**PROXY, "protocol": "auto"}, runner=runner)

    assert result["status"] == "live"
    assert result["protocol"] == "http"
    assert "socks5h" in protocols
    assert "http" in protocols
