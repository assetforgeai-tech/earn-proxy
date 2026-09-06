from __future__ import annotations

import contextlib
import ipaddress
import json
import re
import secrets
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Collection
from urllib.parse import quote, urlsplit

from app.network_safety import UnsafeProxyTarget, resolve_public_proxy_host

HTTP_PROBE_URLS = ("http://ifconfig.me/ip", "http://icanhazip.com")
PROXIO_WHOAMI_URL = "https://api.prox.io.vn/v1/check/whoami"
PROXIO_MIN_INTERVAL_SECONDS = 0.2
PROBE_URLS = (
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
    PROXIO_WHOAMI_URL,
)
PROXY_DEADLINE = 36
PROBE_ATTEMPTS = 2
PROBE_META = "__PROBE_META__:"
CAPTIVE_HOSTS = {"giahan.vnpt.com.vn"}
CAPTIVE_MARKERS = ("giahan.vnpt.com.vn", "/internet/logo.svg", "provider_blocked")
PROXY_FAILURE_CODES = {7, 67, 97}
PROXY_DNS_CODES = {5}
PROBE_ENDPOINT_CODES = {6}
TRANSIENT_CODES = {5, 28, 52, 55, 56}
TLS_CODES = {35, 51, 60}
MAX_PROBE_BODY_BYTES = 4096
MAX_PROBE_OUTPUT_BYTES = MAX_PROBE_BODY_BYTES + 2048
MAX_PROBE_STDERR_BYTES = 4096
MAX_READ_CHUNK_BYTES = 1024
_proxio_rate_lock = threading.Lock()
_proxio_next_request_at = 0.0


def parse_exit_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def parse_probe_exit_ip(probe: str, value: str) -> str:
    """Parse an egress IP according to the response contract of a probe host."""
    if str(probe or "").strip() != PROXIO_WHOAMI_URL:
        return parse_exit_ip(value)
    try:
        payload = json.loads(str(value or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    return parse_exit_ip(payload.get("ip"))


def _wait_for_probe_slot(probe: str, *, clock=time.monotonic, sleeper=time.sleep) -> None:
    """Keep this process within the externally verified Prox.io request rate."""
    if str(probe or "").strip() != PROXIO_WHOAMI_URL:
        return
    global _proxio_next_request_at
    with _proxio_rate_lock:
        now = clock()
        delay = max(0.0, _proxio_next_request_at - now)
        if delay:
            sleeper(delay)
            now = clock()
        _proxio_next_request_at = max(now, _proxio_next_request_at) + PROXIO_MIN_INTERVAL_SECONDS


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


def _proxy_config(proxy: dict) -> str:
    host, port = str(proxy["host"]), int(proxy["port"])

    def url_host(value: str) -> str:
        # URL authorities require brackets around literal IPv6 addresses.
        try:
            if ipaddress.ip_address(value).version == 6:
                return f"[{value.strip('[]')}]"
        except ValueError:
            pass
        return value

    def config_value(value: object) -> str:
        return str(value or "").replace("\\", "\\\\").replace('"', '\\"')

    username = config_value(proxy.get("username"))
    password = config_value(proxy.get("password"))
    protocol = str(proxy.get("protocol") or "http").lower()
    scheme = "socks5h" if protocol == "socks5" else "http"
    return 'proxy = "%s://%s:%s"\nproxy-user = "%s:%s"\n' % (
        scheme,
        config_value(url_host(host)),
        port,
        username,
        password,
    )


def _bounded_subprocess_run(command: list[str], proxy_config: str, timeout: float):
    """Run curl with capped pipe readers so a hostile endpoint cannot amplify RAM."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()

    def drain(stream, chunks: list[bytes], limit: int) -> None:
        total = 0
        while True:
            chunk = stream.read(MAX_READ_CHUNK_BYTES)
            if not chunk:
                return
            remaining = limit - total
            if remaining > 0:
                chunks.append(chunk[:remaining])
            total += len(chunk)
            if total > limit:
                overflow.set()
                return

    stdout_thread = threading.Thread(
        target=drain,
        args=(process.stdout, stdout_chunks, MAX_PROBE_OUTPUT_BYTES),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr, stderr_chunks, MAX_PROBE_STDERR_BYTES),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        if process.stdin is not None:
            process.stdin.write(proxy_config.encode("utf-8"))
            process.stdin.close()
        deadline = time.monotonic() + timeout + 1
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                process.kill()
                break
            time.sleep(0.005)
        process.wait(timeout=2)
    except Exception:
        with contextlib.suppress(Exception):
            process.kill()
        with contextlib.suppress(Exception):
            process.wait(timeout=2)
        raise
    finally:
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        for stream in (process.stdout, process.stderr):
            with contextlib.suppress(Exception):
                stream.close()
    return subprocess.CompletedProcess(
        command,
        125 if overflow.is_set() else (process.returncode if process.returncode is not None else 124),
        stdout=b"".join(stdout_chunks).decode("utf-8", "replace"),
        stderr=(
            b"".join(stderr_chunks).decode("utf-8", "replace")
            + ("\nprobe output exceeded the safety limit" if overflow.is_set() else "")
        ),
    )


def _probe_once(proxy: dict, probe: str, insecure: bool, timeout: float, runner, *, resolver=None):
    host, port = str(proxy["host"]), int(proxy["port"])
    effective_proxy = proxy
    # Injected runners are pure test seams and do not open a socket.  The real
    # subprocess path resolves and pins the provider address before curl runs,
    # preventing DNS rebinding from turning a public hostname into an internal
    # destination.
    if runner is subprocess.run or resolver is not None:
        try:
            pinned_address = (resolver or resolve_public_proxy_host)(host, port)
        except UnsafeProxyTarget as exc:
            return None, f"unsafe_target: {exc}"
        effective_proxy = {**proxy, "host": pinned_address}
    proxy_config = _proxy_config(effective_proxy)
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
        "--max-filesize",
        str(MAX_PROBE_BODY_BYTES),
        "--proxy",
        _proxy_target(effective_proxy),
        "--config",
        "-",
    ]
    if insecure:
        command.append("--insecure")
    # A per-request marker is not knowable to the upstream response body;
    # injected test runners retain the stable marker for compatibility.
    marker = PROBE_META if runner is not subprocess.run else f"{PROBE_META}{secrets.token_urlsafe(18)}:"
    command.extend(
        [
            "--write-out",
            f"\n{marker}%{{http_code}}|%{{url_effective}}|%{{ssl_verify_result}}\n",
            probe,
        ]
    )
    try:
        if runner is subprocess.run:
            _wait_for_probe_slot(probe)
            result = _bounded_subprocess_run(command, proxy_config, timeout)
        else:
            result = runner(
                command,
                input=proxy_config,
                capture_output=True,
                text=True,
                timeout=timeout + 1,
                check=False,
            )
    except Exception as exc:  # noqa: BLE001 - subprocess runner is injectable and failure-safe
        return None, str(exc)
    stdout = str(result.stdout or "")
    if len(stdout.encode("utf-8", "replace")) > MAX_PROBE_OUTPUT_BYTES:
        return None, "probe output exceeded the safety limit"
    parts = stdout.rsplit(marker, 1)
    return {
        "returncode": result.returncode,
        "body": parts[0],
        "meta": parts[1] if len(parts) > 1 else "",
        "stderr": str(result.stderr or "").strip(),
    }, ""


def _proxy_target(proxy: dict) -> str:
    host, port = str(proxy["host"]), int(proxy["port"])
    protocol = str(proxy.get("protocol") or "http").lower()
    scheme = "socks5h" if protocol == "socks5" else "http"
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host.strip('[]')}]"
    except ValueError:
        pass
    return f"{scheme}://{host}:{port}"


def _quorum(results: dict, *, require_tls: bool) -> str:
    values = []
    for probe, response in results.items():
        if (
            not response
            or response["returncode"] != 0
            or not _meta_valid(response["meta"], probe, require_tls=require_tls)
        ):
            continue
        value = parse_probe_exit_ip(probe, response["body"])
        if value:
            values.append(value)
    counts = Counter(values)
    if not counts:
        return ""
    value, count = counts.most_common(1)[0]
    return value if count >= 2 else ""


def _classify_curl_failure(returncode: int) -> str:
    """Separate proxy failures from probe infrastructure and transient faults."""
    if returncode in PROXY_DNS_CODES:
        return "proxy_dns"
    if returncode in PROXY_FAILURE_CODES:
        return "proxy"
    if returncode in PROBE_ENDPOINT_CODES:
        return "probe_endpoint"
    if returncode in TRANSIENT_CODES:
        return "transient"
    if returncode in TLS_CODES:
        return "tls"
    return "transient"


def _meta_http_code(meta: str) -> int:
    code = str(meta or "").strip().split("|", 1)[0]
    return int(code) if code.isdigit() else 0


def _record_response_failure(
    response: dict,
    probe: str,
    *,
    require_tls: bool,
    state: dict[str, bool],
) -> None:
    """Record evidence without treating a non-2xx probe response as proxy death."""
    returncode = int(response.get("returncode", 0))
    if returncode:
        failure_kind = _classify_curl_failure(returncode)
        if failure_kind == "proxy":
            state["proxy"] = True
        elif failure_kind == "probe_endpoint":
            state["probe_endpoint"] = True
        elif failure_kind == "tls":
            state["uncertain"] = True
        else:
            state["transient"] = True
        return
    if _meta_http_code(response.get("meta", "")) == 407:
        state["proxy"] = True
    elif not _meta_valid(response.get("meta", ""), probe, require_tls=require_tls):
        state["probe_endpoint"] = True


def _proxy_urls(proxy: dict) -> list[tuple[str, str]]:
    host, port = str(proxy["host"]), int(proxy["port"])
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host.strip('[]')}]"
    except ValueError:
        pass
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


def _probe_result(
    *,
    status: str,
    protocol: str,
    exit_ip: str = "",
    latency_ms: int | None = None,
    error: str = "",
    failure_kind: str = "",
    probe_endpoint: str = "",
    next_probe_index: int = 0,
    failed_probe_endpoint: str = "",
    egress_trusted: bool = False,
) -> dict:
    return {
        "status": status,
        "protocol": protocol,
        "exit_ip": exit_ip,
        "latency_ms": latency_ms,
        "error": error,
        "failure_kind": failure_kind,
        "probe_endpoint": probe_endpoint,
        "next_probe_index": next_probe_index,
        "failed_probe_endpoint": failed_probe_endpoint,
        "egress_trusted": bool(egress_trusted),
    }


def _probe_candidates(probe_index: int, unavailable_endpoints: Collection[str] | None = None):
    unavailable = {str(item).strip() for item in (unavailable_endpoints or ())}
    start = max(0, int(probe_index)) % len(PROBE_URLS)
    for offset in range(len(PROBE_URLS)):
        index = (start + offset) % len(PROBE_URLS)
        if PROBE_URLS[index] not in unavailable:
            yield index, PROBE_URLS[index]


def check_proxy_fast(
    proxy: dict,
    *,
    probe_index: int = 0,
    expected_exit_ip: str = "",
    unavailable_endpoints: Collection[str] | None = None,
    timeout: float = 8,
    runner=subprocess.run,
    resolver=None,
) -> dict:
    """Run one cheap observation through the already-selected protocol."""
    started = time.monotonic()
    urls = _proxy_urls(proxy)
    if not urls:
        return _probe_result(
            status="needs_confirmation",
            protocol="unknown",
            error="proxy protocol is not supported",
            failure_kind="protocol",
        )
    protocol, _proxy_url = urls[0]
    candidates = list(_probe_candidates(probe_index, unavailable_endpoints))
    if not candidates:
        return _probe_result(
            status="inconclusive",
            protocol=protocol,
            error="all probe endpoints are temporarily unavailable",
            failure_kind="probe_endpoint",
            next_probe_index=(max(0, int(probe_index)) + 1) % len(PROBE_URLS),
        )
    selected_index, probe = candidates[0]
    next_index = (selected_index + 1) % len(PROBE_URLS)
    # Preserve the selected protocol when the row is still marked ``auto``;
    # fast checks must never silently fall back to a second transport.
    selected_proxy = {**proxy, "protocol": protocol}
    response, runner_error = _probe_once(
        selected_proxy,
        probe,
        False,
        max(1, min(8, timeout)),
        runner,
        resolver=resolver,
    )
    latency = round((time.monotonic() - started) * 1000)
    if runner_error or not response:
        failure_kind = "unsafe_target" if str(runner_error or "").startswith("unsafe_target:") else "transient"
        return _probe_result(
            status="needs_confirmation",
            protocol=protocol,
            latency_ms=latency,
            error=runner_error or "probe worker did not return a response",
            failure_kind=failure_kind,
            probe_endpoint=probe,
            next_probe_index=next_index,
            failed_probe_endpoint=probe,
        )
    blocked = _captive_error(response["body"], response["meta"])
    if blocked:
        return _probe_result(
            status="blocked",
            protocol=protocol,
            latency_ms=latency,
            error=blocked,
            failure_kind="provider_blocked",
            probe_endpoint=probe,
            next_probe_index=next_index,
        )
    if response["returncode"] in TLS_CODES:
        return _probe_result(
            status="needs_confirmation",
            protocol=protocol,
            latency_ms=latency,
            error=response["stderr"] or "TLS verification failed",
            failure_kind="tls",
            probe_endpoint=probe,
            next_probe_index=next_index,
            failed_probe_endpoint=probe,
        )
    if response["returncode"] != 0:
        failure_kind = _classify_curl_failure(response["returncode"])
        return _probe_result(
            status="inconclusive" if failure_kind in {"probe_endpoint", "proxy_dns"} else "needs_confirmation",
            protocol=protocol,
            latency_ms=latency,
            error=response["stderr"] or f"curl exited with {response['returncode']}",
            failure_kind=failure_kind,
            probe_endpoint=probe,
            next_probe_index=next_index,
            failed_probe_endpoint=probe if failure_kind == "probe_endpoint" else "",
        )
    if _meta_http_code(response["meta"]) == 407:
        return _probe_result(
            status="needs_confirmation",
            protocol=protocol,
            latency_ms=latency,
            error="proxy authentication rejected (HTTP 407)",
            failure_kind="proxy",
            probe_endpoint=probe,
            next_probe_index=next_index,
        )
    if not _meta_valid(response["meta"], probe, require_tls=True):
        return _probe_result(
            status="inconclusive",
            protocol=protocol,
            latency_ms=latency,
            error="probe endpoint returned an invalid HTTP response",
            failure_kind="probe_endpoint",
            probe_endpoint=probe,
            next_probe_index=next_index,
            failed_probe_endpoint=probe,
        )
    exit_ip = parse_probe_exit_ip(probe, response["body"])
    if not exit_ip:
        return _probe_result(
            status="inconclusive",
            protocol=protocol,
            latency_ms=latency,
            error="probe endpoint did not return an IP address",
            failure_kind="probe_endpoint",
            probe_endpoint=probe,
            next_probe_index=next_index,
            failed_probe_endpoint=probe,
        )
    if expected_exit_ip and exit_ip != expected_exit_ip:
        return _probe_result(
            status="needs_confirmation",
            protocol=protocol,
            exit_ip=exit_ip,
            latency_ms=latency,
            error="exit IP changed and requires independent confirmation",
            failure_kind="egress_changed",
            probe_endpoint=probe,
            next_probe_index=next_index,
        )
    return _probe_result(
        status="live",
        protocol=protocol,
        exit_ip=exit_ip,
        latency_ms=latency,
        probe_endpoint=probe,
        next_probe_index=next_index,
    )


def check_proxy_strong(
    proxy: dict,
    timeout: float = 10,
    runner=subprocess.run,
    *,
    unavailable_endpoints: Collection[str] | None = None,
    resolver=None,
) -> dict:
    started = time.monotonic()
    deadline = started + max(PROXY_DEADLINE, max(1, timeout))
    errors: list[str] = []
    blocked_results: list[tuple[str, str]] = []
    saw_transient = False
    saw_uncertain = False
    saw_proxy_failure = False
    saw_probe_endpoint_failure = False
    proxy_urls = _proxy_urls(proxy)
    for protocol_index, (protocol, _proxy_url) in enumerate(proxy_urls):
        current = time.monotonic()
        if current >= deadline:
            break
        remaining_protocols = max(1, len(proxy_urls) - protocol_index)
        # Reserve a fair share of the total deadline for HTTP auto-detection
        # when a non-SOCKS endpoint accepts a connection but never completes a
        # SOCKS handshake.
        protocol_deadline = current + max(1, (deadline - current) / remaining_protocols)
        for _attempt in range(PROBE_ATTEMPTS):
            if time.monotonic() >= protocol_deadline:
                break
            verified: dict = {}
            insecure_results: dict = {}
            plain_http: dict = {}
            protocol_blocked: list[str] = []
            remaining = max(1, min(deadline, protocol_deadline) - time.monotonic())
            per_probe = max(1, min(8, remaining / (len(PROBE_URLS) + len(HTTP_PROBE_URLS))))
            for probe in _probe_candidates(0, unavailable_endpoints):
                _probe_index, probe = probe
                if time.monotonic() >= protocol_deadline:
                    break
                response, error = _probe_once(
                    {**proxy, "protocol": protocol}, probe, False, per_probe, runner, resolver=resolver
                )
                if error:
                    errors.append(error)
                    saw_transient = True
                    continue
                blocked = _captive_error(response["body"], response["meta"])
                if blocked:
                    protocol_blocked.append(blocked)
                    continue
                evidence = {"proxy": False, "probe_endpoint": False, "transient": False, "uncertain": False}
                _record_response_failure(response, probe, require_tls=False, state=evidence)
                saw_proxy_failure |= evidence["proxy"]
                saw_probe_endpoint_failure |= evidence["probe_endpoint"]
                saw_transient |= evidence["transient"]
                saw_uncertain |= evidence["uncertain"]
                verified[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            verified_ip = _quorum(verified, require_tls=True)
            if any(response and response["returncode"] in TLS_CODES for response in verified.values()):
                saw_uncertain = True
                for _probe_index, probe in _probe_candidates(0, unavailable_endpoints):
                    if time.monotonic() >= protocol_deadline:
                        break
                    response, error = _probe_once(
                        {**proxy, "protocol": protocol}, probe, True, per_probe, runner, resolver=resolver
                    )
                    if error:
                        errors.append(error)
                        saw_transient = True
                        continue
                    blocked = _captive_error(response["body"], response["meta"])
                    if blocked:
                        protocol_blocked.append(blocked)
                        continue
                    evidence = {"proxy": False, "probe_endpoint": False, "transient": False, "uncertain": False}
                    _record_response_failure(response, probe, require_tls=False, state=evidence)
                    saw_proxy_failure |= evidence["proxy"]
                    saw_probe_endpoint_failure |= evidence["probe_endpoint"]
                    saw_transient |= evidence["transient"]
                    saw_uncertain |= evidence["uncertain"]
                    insecure_results[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            insecure_ip = _quorum(insecure_results, require_tls=False)
            if verified_ip:
                latency = round((time.monotonic() - started) * 1000)
                return _probe_result(
                    status="live",
                    protocol=protocol,
                    exit_ip=verified_ip,
                    latency_ms=latency,
                    probe_endpoint=",".join(PROBE_URLS),
                    egress_trusted=True,
                )
            for probe in HTTP_PROBE_URLS:
                if time.monotonic() >= protocol_deadline:
                    break
                response, error = _probe_once(
                    {**proxy, "protocol": protocol}, probe, False, per_probe, runner, resolver=resolver
                )
                if error:
                    errors.append(error)
                    saw_transient = True
                    continue
                blocked = _captive_error(response["body"], response["meta"])
                if blocked:
                    protocol_blocked.append(blocked)
                    continue
                evidence = {"proxy": False, "probe_endpoint": False, "transient": False, "uncertain": False}
                _record_response_failure(response, probe, require_tls=False, state=evidence)
                saw_proxy_failure |= evidence["proxy"]
                saw_probe_endpoint_failure |= evidence["probe_endpoint"]
                saw_transient |= evidence["transient"]
                saw_uncertain |= evidence["uncertain"]
                plain_http[probe] = response
            if protocol_blocked:
                blocked_results.extend((protocol, item) for item in protocol_blocked)
                break
            plain_ip = _quorum(plain_http, require_tls=False)
            latency = round((time.monotonic() - started) * 1000)
            if insecure_ip:
                return _probe_result(
                    status="live_unverified",
                    protocol=protocol,
                    exit_ip=insecure_ip,
                    latency_ms=latency,
                    error="TLS certificate verification failed; exit IP confirmed by independent probes",
                    probe_endpoint=",".join(PROBE_URLS),
                )
            if plain_ip:
                return _probe_result(
                    status="live_unverified",
                    protocol=protocol,
                    exit_ip=plain_ip,
                    latency_ms=latency,
                    error="TLS probes unavailable; exit IP confirmed by independent plain HTTP probes",
                    probe_endpoint=",".join(HTTP_PROBE_URLS),
                )
    if blocked_results:
        protocol, error = blocked_results[0]
        return _probe_result(
            status="blocked",
            protocol=protocol,
            latency_ms=round((time.monotonic() - started) * 1000),
            error=error,
            failure_kind="provider_blocked",
            probe_endpoint=",".join(PROBE_URLS),
        )
    status = (
        "dead"
        if saw_proxy_failure and not (saw_transient or saw_uncertain or saw_probe_endpoint_failure or errors)
        else "inconclusive"
    )
    failure_kind = "proxy" if status == "dead" else ("probe_endpoint" if saw_probe_endpoint_failure else "transient")
    return _probe_result(
        status=status,
        protocol="unknown",
        error="; ".join(errors)[-500:] or "insufficient independent probe evidence",
        failure_kind=failure_kind,
        probe_endpoint=",".join(PROBE_URLS),
    )


def check_proxy(proxy: dict, timeout: float = 10, runner=subprocess.run) -> dict:
    """Compatibility alias for the strong qualification probe."""
    return check_proxy_strong(proxy, timeout=timeout, runner=runner)
