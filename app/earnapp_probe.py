"""EarnApp WSS proxy qualification, ported from the supplied desktop probe."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import ssl
from datetime import UTC, datetime
from typing import Any

WSS_HOST = "proxyjs.brdtnet.com"
WSS_PORT = 443
SDK = "1.617.813"
EARN_UA = f"Hola earnapp/{SDK}"
DEFAULT_WAIT_MS = 18_000
MAKEFLAGS = (
    "DIST=APP RELEASE=y IS_IOS=y IOS_SDK=y IOS_UNITY=n "
    "CONFIG_BATREQ=y CONFIG_BAT_CYCLE=y CONFIG_BAT_PLATFORM=app_macr_ios_sdk"
)
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def build_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # The supplied EarnApp probe accepts the proxy tunnel's interception certificate.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def classify_verdict(verdict: str, reason: str = "") -> str:
    value = str(verdict or "UNKNOWN").strip().upper()
    if value == "CID_SET":
        return "allow"
    if value in {"BLACKLIST", "DECLINE"} or str(reason or "").strip() == "earnapp_blacklist":
        return "risk"
    return "pending"


def build_tunnel_identity(*, now_ms: int | None = None, uuid_hex: str | None = None) -> dict[str, Any]:
    now = int(now_ms if now_ms is not None else datetime.now(UTC).timestamp() * 1000)
    timestamp = datetime.fromtimestamp(now / 1000, UTC).strftime("%Y-%m-%d %H:%M:%S")
    device_hex = str(uuid_hex or secrets.token_hex(16))
    return {
        "arch": "arm64",
        "release": "Version 17.6.1 (Build 21G93)",
        "platform": "ios",
        "version": SDK,
        "appid": "ios_com.brd.earnapp",
        "uuid": f"sdk-ios-{device_hex}",
        "type": "wifi",
        "ifname": "en0",
        "usage": {
            "total_bytes": "",
            "app_bytes": json.dumps(
                {
                    "wifi_connected": True,
                    "screen_on": True,
                    "battery_level": 41,
                    "using_battery": True,
                    "on_call": False,
                    "roaming": False,
                    "mobile_connected": False,
                },
                separators=(",", ":"),
            ),
            "ts": timestamp,
        },
        "consent_ts": now,
        "new_state": {
            "full_screen": "off",
            "power_source": "battery",
            "monitor_power": "on",
            "battery_percentage": 41,
            "session_state": "logged",
            "idle_state": {"cpu_usage": 11, "mem_usage": 13},
            "user_io": 1000,
        },
        "makeflags": MAKEFLAGS,
        "sdk_version": SDK,
        "gw_ip": "0.0.0.0",
        "http3": True,
        "is_swift": True,
        "status_send": True,
        "mobile_connected": False,
        "mobile_type": "wifi",
        "roaming": False,
        "is_debug": False,
        "idle": False,
        "ipv6_supported": False,
    }


def encode_client_frame(payload: bytes, *, mask_key: bytes | None = None, opcode: int = 1) -> bytes:
    """Encode a masked client frame without coercing binary control payloads to text."""
    if not 0 <= int(opcode) <= 0x0F:
        raise ValueError("WebSocket opcode must fit in four bits")
    payload = bytes(payload)
    key = mask_key or os.urandom(4)
    if len(key) != 4:
        raise ValueError("WebSocket mask key must be four bytes")
    first = 0x80 | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = bytes([first, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([first, 0xFE]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, 0xFF]) + length.to_bytes(8, "big")
    masked = bytes(value ^ key[index % 4] for index, value in enumerate(payload))
    return header + key + masked


def encode_client_text_frame(text: str, *, mask_key: bytes | None = None, opcode: int = 1) -> bytes:
    return encode_client_frame(str(text).encode("utf-8"), mask_key=mask_key, opcode=opcode)


async def read_server_frame(reader: asyncio.StreamReader, *, timeout: float) -> tuple[int, bool, bytes]:
    head = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    final = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), timeout=timeout), "big")
    elif length == 127:
        length = int.from_bytes(await asyncio.wait_for(reader.readexactly(8), timeout=timeout), "big")
    if length > 2_000_000:
        raise ValueError("WebSocket frame is too large")
    mask = await asyncio.wait_for(reader.readexactly(4), timeout=timeout) if masked else b""
    payload = await asyncio.wait_for(reader.readexactly(length), timeout=timeout) if length else b""
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return opcode, final, payload


async def _read_http_headers(reader: asyncio.StreamReader, *, timeout: float) -> tuple[str, dict[str, str]]:
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
    if len(raw) > 65_536:
        raise ValueError("HTTP headers are too large")
    lines = raw.decode("iso-8859-1", "replace").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return lines[0], headers


async def _connect_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    username: str,
    password: str,
    timeout: float,
) -> None:
    methods = [0]
    if username or password:
        methods.append(2)
    writer.write(bytes([5, len(methods), *methods]))
    await writer.drain()
    response = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    if response[0] != 5 or response[1] == 0xFF:
        raise ConnectionError("SOCKS5 authentication method rejected")
    if response[1] == 2:
        user = username.encode("utf-8")
        secret = password.encode("utf-8")
        if len(user) > 255 or len(secret) > 255:
            raise ValueError("SOCKS5 credentials are too long")
        writer.write(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), timeout=timeout) != b"\x01\x00":
            raise ConnectionError("SOCKS5 credentials rejected")
    elif response[1] != 0:
        raise ConnectionError("SOCKS5 proxy requires unsupported authentication")

    encoded_host = WSS_HOST.encode("ascii")
    writer.write(b"\x05\x01\x00\x03" + bytes([len(encoded_host)]) + encoded_host + WSS_PORT.to_bytes(2, "big"))
    await writer.drain()
    reply = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    if reply[0] != 5 or reply[1] != 0:
        raise ConnectionError(f"SOCKS5 CONNECT failed with code {reply[1]}")
    atyp = reply[3]
    if atyp == 1:
        await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
    elif atyp == 3:
        host_len = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
        await asyncio.wait_for(reader.readexactly(host_len + 2), timeout=timeout)
    elif atyp == 4:
        await asyncio.wait_for(reader.readexactly(18), timeout=timeout)
    else:
        raise ConnectionError("SOCKS5 proxy returned an unknown address type")


async def _connect_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    username: str,
    password: str,
    timeout: float,
) -> None:
    headers = [
        f"CONNECT {WSS_HOST}:{WSS_PORT} HTTP/1.1",
        f"Host: {WSS_HOST}:{WSS_PORT}",
        "Proxy-Connection: keep-alive",
    ]
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    status, _ = await _read_http_headers(reader, timeout=timeout)
    if " 200 " not in f" {status} ":
        raise ConnectionError(f"HTTP CONNECT rejected: {status}")


async def _open_wss_tunnel(
    host: str,
    port: int,
    *,
    protocol: str,
    username: str,
    password: str,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        if protocol == "socks5":
            await _connect_socks5(reader, writer, username=username, password=password, timeout=timeout)
        elif protocol == "http":
            await _connect_http(reader, writer, username=username, password=password, timeout=timeout)
        else:
            raise ValueError("EarnApp probe supports only http and socks5 proxies")
        context = build_tls_context()
        await asyncio.wait_for(writer.start_tls(context, server_hostname=WSS_HOST), timeout=timeout)

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET / HTTP/1.1\r\n"
            f"Host: {WSS_HOST}:{WSS_PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: {EARN_UA}\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await writer.drain()
        status, headers = await _read_http_headers(reader, timeout=timeout)
        if " 101 " not in f" {status} ":
            raise ConnectionError(f"WSS handshake rejected: {status}")
        expected = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise ConnectionError("WSS handshake returned an invalid accept token")
        return reader, writer
    except Exception:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        raise


async def probe_earnapp_proxy(
    host: str,
    port: int,
    *,
    protocol: str,
    username: str = "",
    password: str = "",
    timeout_ms: int = DEFAULT_WAIT_MS,
) -> dict[str, Any]:
    wait_seconds = max(4.0, float(timeout_ms or DEFAULT_WAIT_MS) / 1000)
    result: dict[str, Any] = {
        "verdict": "UNKNOWN",
        "reason": "",
        "eligibility": "unknown",
        "exit_ip": "",
        "latency_ms": None,
        "probe_version": f"earnapp-wss-{SDK}",
    }
    started = asyncio.get_running_loop().time()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await _open_wss_tunnel(
            str(host or "").strip(),
            int(port or 0),
            protocol=str(protocol or "").strip().lower(),
            username=str(username or ""),
            password=str(password or ""),
            timeout=min(15.0, wait_seconds),
        )
        identity = build_tunnel_identity()
        deadline = asyncio.get_running_loop().time() + wait_seconds
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                result.update(
                    verdict="TIMEOUT",
                    reason=f"no decline/cid in {int(wait_seconds * 1000)}ms",
                )
                break
            opcode, _final, payload = await read_server_frame(reader, timeout=remaining)
            if opcode == 8:
                result.update(verdict="WSS_CLOSE", reason="server closed connection")
                break
            if opcode == 9:
                writer.write(encode_client_frame(payload, opcode=10))
                await writer.drain()
                continue
            if opcode != 1:
                continue
            try:
                message = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            msg_type = str(message.get("type") or "")
            command = str(message.get("cmd") or "")
            data = message.get("msg") if isinstance(message.get("msg"), dict) else {}
            if msg_type == "ipc_post" and command == "tunnel_init_decline":
                reason = str(data.get("reason") or "")
                result.update(
                    verdict="BLACKLIST" if reason == "earnapp_blacklist" else "DECLINE",
                    reason=reason,
                )
                break
            if msg_type == "ipc_post" and command == "cid_set":
                result.update(verdict="CID_SET", reason=str(data.get("cid") or ""))
                break
            if msg_type == "ipc_call" and command == "tunnel_init":
                result["exit_ip"] = str(data.get("ext_ip") or "")
                reply = {
                    "type": "ipc_result",
                    "cmd": command,
                    "cookie": message.get("cookie"),
                    "msg": identity,
                }
                writer.write(encode_client_text_frame(json.dumps(reply, separators=(",", ":"))))
                await writer.drain()
            elif msg_type == "ipc_call" and command in {
                "tunnel_init_done",
                "check_status_send",
            }:
                body = {"idle": False} if command == "check_status_send" else {"ok": True}
                reply = {
                    "type": "ipc_result",
                    "cmd": command,
                    "cookie": message.get("cookie"),
                    "msg": body,
                }
                writer.write(encode_client_text_frame(json.dumps(reply, separators=(",", ":"))))
                await writer.drain()
    except TimeoutError:
        result.update(verdict="TIMEOUT", reason=f"no decline/cid in {int(wait_seconds * 1000)}ms")
    except Exception as exc:  # noqa: BLE001 - all network/protocol failures map to WSS_FAIL
        result.update(verdict="WSS_FAIL", reason=str(exc)[:300])
    finally:
        result["latency_ms"] = max(0, int((asyncio.get_running_loop().time() - started) * 1000))
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    result["eligibility"] = classify_verdict(str(result["verdict"]), str(result["reason"]))
    return result
