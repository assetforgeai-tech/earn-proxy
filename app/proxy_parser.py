from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class ProxyParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedProxy:
    protocol: str
    host: str
    port: int
    username: str
    password: str

    @property
    def raw(self) -> str:
        if self.username or self.password:
            return f"{self.host}:{self.port}:{self.username}:{self.password}"
        return f"{self.host}:{self.port}"


MAX_RAW_PROXY_LENGTH = 4096


def _validate(protocol: str, host: str, port: int, username: str, password: str) -> ParsedProxy:
    normalized_host = str(host or "").strip().lower()
    if not normalized_host or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in normalized_host):
        raise ProxyParseError("Proxy host is invalid")
    if not 1 <= int(port) <= 65535:
        raise ProxyParseError("Proxy port must be between 1 and 65535")
    if len(normalized_host) > 253:
        raise ProxyParseError("Proxy host is too long")
    if len(username) > 512:
        raise ProxyParseError("Proxy username is too long")
    if len(password) > 2048:
        raise ProxyParseError("Proxy password is too long")
    normalized_protocol = str(protocol or "auto").lower()
    if normalized_protocol == "https":
        normalized_protocol = "http"
    if normalized_protocol not in {"auto", "http", "socks5"}:
        raise ProxyParseError("Only auto, HTTP, and SOCKS5 proxies are supported")
    if any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in (username, password)):
        raise ProxyParseError("Proxy credentials contain control characters")
    return ParsedProxy(normalized_protocol, normalized_host, int(port), username, password)


def parse_proxy(raw: str) -> ParsedProxy:
    value = str(raw or "").strip()
    if not value:
        raise ProxyParseError("Proxy is required")
    if len(value) > MAX_RAW_PROXY_LENGTH:
        raise ProxyParseError("Proxy value is too long")

    if "://" in value:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ProxyParseError("Proxy port is invalid") from exc
        if not parsed.hostname or not port:
            raise ProxyParseError("Proxy URL must include host and port")
        return _validate(
            parsed.scheme,
            parsed.hostname,
            port,
            unquote(parsed.username or ""),
            unquote(parsed.password or ""),
        )

    if "@" in value:
        credentials, endpoint = value.rsplit("@", 1)
        if ":" not in credentials or ":" not in endpoint:
            raise ProxyParseError("Proxy must use user:password@host:port")
        username, password = credentials.split(":", 1)
        host, port_text = endpoint.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ProxyParseError("Proxy port is invalid") from exc
        return _validate("auto", host, port, username, password)

    parts = value.split(":")
    if len(parts) < 2:
        raise ProxyParseError("Proxy must include host and port")
    host, port_text = parts[0], parts[1]
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ProxyParseError("Proxy port is invalid") from exc
    username = parts[2] if len(parts) >= 3 else ""
    password = ":".join(parts[3:]) if len(parts) >= 4 else ""
    return _validate("auto", host, port, username, password)
