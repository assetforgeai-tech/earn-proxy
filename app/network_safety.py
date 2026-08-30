from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable


class UnsafeProxyTarget(ValueError):
    pass


_LOCAL_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
_LEGACY_NUMERIC_HOST = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)$", re.IGNORECASE)


def _public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise UnsafeProxyTarget("Proxy target did not resolve to a valid IP address") from exc
    if not address.is_global:
        raise UnsafeProxyTarget("Proxy target resolves to a non-public IP address")
    return str(address)


def validate_proxy_host(host: str) -> str:
    """Reject local, malformed, and legacy numeric aliases before DNS lookup."""
    normalized = str(host or "").strip().lower().rstrip(".")
    if not normalized or normalized in _LOCAL_HOSTS:
        raise UnsafeProxyTarget("Proxy target must use a public host")
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        if _LEGACY_NUMERIC_HOST.fullmatch(normalized) or (
            "." in normalized and all(_LEGACY_NUMERIC_HOST.fullmatch(part) for part in normalized.split("."))
        ):
            raise UnsafeProxyTarget("Legacy numeric proxy host aliases are not allowed") from None
        labels = normalized.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            raise UnsafeProxyTarget("Proxy host is invalid") from None
        return normalized
    _public_ip(str(parsed))
    return str(parsed)


def resolve_public_proxy_host(
    host: str,
    port: int,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> str:
    """Resolve and pin one public address, rejecting DNS answers that cross trust boundaries."""
    normalized = validate_proxy_host(host)
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        literal = None
    if literal is not None:
        return _public_ip(str(literal))

    try:
        rows = resolver(normalized, int(port), type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise UnsafeProxyTarget(f"Proxy host cannot be resolved: {exc}") from exc
    addresses: list[str] = []
    for row in rows:
        sockaddr = row[4]
        if not sockaddr:
            continue
        addresses.append(str(sockaddr[0]))
    if not addresses:
        raise UnsafeProxyTarget("Proxy host returned no usable DNS addresses")

    public: list[str] = []
    for address in addresses:
        public.append(_public_ip(address))
    return sorted(set(public), key=lambda value: (ipaddress.ip_address(value).version, value))[0]
