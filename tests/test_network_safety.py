from __future__ import annotations

import socket

import pytest

from app.network_safety import UnsafeProxyTarget, resolve_public_proxy_host


def _resolver_for(*addresses):
    def resolve(_host, port, **_kwargs):
        rows = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            rows.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return rows

    return resolve


def test_proxy_dns_resolution_rejects_private_only_answers():
    with pytest.raises(UnsafeProxyTarget):
        resolve_public_proxy_host(
            "proxy.example",
            9000,
            resolver=_resolver_for("127.0.0.1", "10.1.2.3"),
        )


def test_proxy_dns_resolution_pins_a_public_answer():
    address = resolve_public_proxy_host(
        "proxy.example",
        9000,
        resolver=_resolver_for("8.8.8.8"),
    )

    assert address == "8.8.8.8"


def test_proxy_dns_resolution_rejects_mixed_public_and_private_answers():
    with pytest.raises(UnsafeProxyTarget):
        resolve_public_proxy_host(
            "proxy.example",
            9000,
            resolver=_resolver_for("8.8.8.8", "127.0.0.1"),
        )


def test_proxy_dns_resolution_accepts_a_public_ipv6_answer():
    address = resolve_public_proxy_host(
        "proxy.example",
        9000,
        resolver=_resolver_for("2001:4860:4860::8888"),
    )

    assert address == "2001:4860:4860::8888"


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.1",
        "10.1.2.3",
        "169.254.169.254",
        "2130706433",
        "0x7f000001",
        "017700000001",
        "localhost",
    ],
)
def test_proxy_dns_resolution_rejects_local_and_numeric_aliases_before_lookup(host):
    called = False

    def resolver(*_args, **_kwargs):
        nonlocal called
        called = True
        return []

    with pytest.raises(UnsafeProxyTarget):
        resolve_public_proxy_host(host, 9000, resolver=resolver)
    assert called is False
