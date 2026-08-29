from __future__ import annotations

import ipaddress
import re
import subprocess
import time
from collections import Counter
from urllib.parse import quote, urlsplit

HTTP_PROBE_URLS = ("http://ifconfig.me/ip", "http://icanhazip.com")
PROBE_URLS = (
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)
PROXY_DEADLINE = 36
PROBE_ATTEMPTS = 2
PROBE_META = "__PROBE_META__:"
CAPTIVE_HOSTS = {"giahan.vnpt.com.vn"}
CAPTIVE_MARKERS = ("giahan.vnpt.com.vn", "/internet/logo.svg", "provider_blocked")


def parse_exit_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _captive_error(body: str, meta: str = "") -> str:
    text = str(body or "").lower()
    fields = str(meta or "").strip().split("|")
    effective_url = fields[1] if len(fields) > 1 else ""
    host = (urlsplit(effective_url).hostname or "").lower()
    if host in CAPTIVE_HOSTS or any(marker in text for marker in CAPTIVE_MARKERS):
        return f"provider_blocked: captive portal redirected to {host or 'provider portal'}"
    ssl_result = fields[2] if len(fields) > 2 else "0"
    if ssl_result not in {"", "0"} and re.search(r"<(?:!doctype|html|head|body)\b", text):
        return "provider_blocked: intercepted HTTPS response with an untrusted certificate"
    return ""


def _meta_valid(meta: str, probe: str, *, require_tls: bool = False) -> bool:
    fields = str(meta or "").strip().split("|")
    code = fields[0] if fields else ""
    effective_url = fields[1] if len(fields) > 1 else ""
    ssl_result = fields[2] if len(fields) > 2 else "0"
    return (
        code.isdigit()
        and 200 <= int(code) < 300
        and (urlsplit(effective_url).hostname or "").lower() == (urlsplit(probe).hostname or "").lower()
        and (not require_tls or ssl_result == "0")
    )


def _probe_once(proxy_url: str, probe: str, insecure: bool, timeout: float, runner):
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--connect-timeout",
        str(round(min(5, timeout), 1)),
        "--max-time",
        str(round(min(8, timeout), 1)),
        "--proxy",
        proxy_url,
    ]
    if insecure:
        command.append("--insecure")
    command.extend(
        [
            "--write-out",
            f"\n{PROBE_META}%{{http_code}}|%{{url_effective}}|%{{ssl_verify_result}}\n",
            probe,
        ]
    )
    try:
        result = runner(command, capture_output=True, text=True, timeout=timeout + 1, check=False)
    except Exception as exc:  # noqa: BLE001 - subprocess runner is injectable and failure-safe
        return None, str(exc)
    parts = str(result.stdout or "").split(PROBE_META, 1)
    return {
        "returncode": result.returncode,
        "body": parts[0],
        "meta": parts[1] if len(parts) > 1 else "",
        "stderr": str(result.stderr or "").strip(),
    }, ""


def _quorum(results: dict, *, require_tls: bool) -> str:
    values = []
    for probe, response in results.items():
        if (
            not response
            or response["returncode"] != 0
            or not _meta_valid(response["meta"], probe, require_tls=require_tls)
        ):
            continue
        value = parse_exit_ip(response["body"])
        if value:
            values.append(value)
    counts = Counter(values)
    if not counts:
        return ""
    value, count = counts.most_common(1)[0]
    return value if count >= 2 else ""


def _proxy_urls(proxy: dict) -> list[tuple[str, str]]:
    host, port = str(proxy["host"]), int(proxy["port"])
    username = quote(str(proxy.get("username") or ""), safe="")
    password = quote(str(proxy.get("password") or ""), safe="")
    auth = f"{username}:{password}@" if username or password else ""
    protocol = str(proxy.get("protocol") or "auto").lower()
    urls = []
    if protocol in {"auto", "socks5"}:
        urls.append(("socks5", f"socks5h://{auth}{host}:{port}"))
    if protocol in {"auto", "http", "https"}:
        urls.append(("http", f"http://{auth}{host}:{port}"))
    return urls


def check_proxy(proxy: dict, timeout: float = 10, runner=subprocess.run) -> dict:
    started = time.monotonic()
    deadline = started + max(PROXY_DEADLINE, max(1, timeout))
    errors: list[str] = []
    blocked_results: list[tuple[str, str]] = []
    saw_transient = False
    saw_uncertain = False
    for protocol, proxy_url in _proxy_urls(proxy):
        for _attempt in range(PROBE_ATTEMPTS):
            if time.monotonic() >= deadline:
                break
            verified: dict = {}
            insecure_results: dict = {}
            plain_http: dict = {}
            protocol_blocked: list[str] = []
            remaining = max(1, deadline - time.monotonic())
            per_probe = max(1, min(8, remaining / (len(PROBE_URLS) + len(HTTP_PROBE_URLS))))
            for probe in PROBE_URLS:
                response, error = _probe_once(proxy_url, probe, False, per_probe, runner)
                if error:
                    errors.append(error)
                    saw_transient = True
                    continue
                blocked = _captive_error(response["body"], response["meta"])
                if blocked:
                    protocol_blocked.append(blocked)
                    continue
                if response["returncode"] in {7, 28, 52, 55, 56}:
                    saw_transient = True
                verified[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            verified_ip = _quorum(verified, require_tls=True)
            if any(response and response["returncode"] in {35, 51, 60} for response in verified.values()):
                saw_uncertain = True
                for probe in PROBE_URLS:
                    response, error = _probe_once(proxy_url, probe, True, per_probe, runner)
                    if error:
                        errors.append(error)
                        saw_transient = True
                        continue
                    blocked = _captive_error(response["body"], response["meta"])
                    if blocked:
                        protocol_blocked.append(blocked)
                        continue
                    insecure_results[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            insecure_ip = _quorum(insecure_results, require_tls=False)
            if verified_ip:
                latency = round((time.monotonic() - started) * 1000)
                return {
                    "status": "live",
                    "protocol": protocol,
                    "exit_ip": verified_ip,
                    "latency_ms": latency,
                    "error": "",
                }
            for probe in HTTP_PROBE_URLS:
                response, error = _probe_once(proxy_url, probe, False, per_probe, runner)
                if error:
                    errors.append(error)
                    saw_transient = True
                    continue
                blocked = _captive_error(response["body"], response["meta"])
                if blocked:
                    protocol_blocked.append(blocked)
                    continue
                if response["returncode"] in {7, 28, 52, 55, 56}:
                    saw_transient = True
                plain_http[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            plain_ip = _quorum(plain_http, require_tls=False)
            latency = round((time.monotonic() - started) * 1000)
            if insecure_ip:
                return {
                    "status": "live_unverified",
                    "protocol": protocol,
                    "exit_ip": insecure_ip,
                    "latency_ms": latency,
                    "error": "TLS certificate verification failed; exit IP confirmed by independent probes",
                }
            if plain_ip:
                return {
                    "status": "live",
                    "protocol": protocol,
                    "exit_ip": plain_ip,
                    "latency_ms": latency,
                    "error": "",
                }
    if blocked_results:
        protocol, error = blocked_results[0]
        return {
            "status": "blocked",
            "protocol": protocol,
            "exit_ip": "",
            "latency_ms": round((time.monotonic() - started) * 1000),
            "error": error,
        }
    status = "inconclusive" if saw_transient or saw_uncertain or errors else "dead"
    return {
        "status": status,
        "protocol": "unknown",
        "exit_ip": "",
        "latency_ms": None,
        "error": "; ".join(errors)[-500:] or "insufficient independent probe evidence",
    }
