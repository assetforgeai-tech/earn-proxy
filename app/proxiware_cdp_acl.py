"""Install the local owner ACL protecting the Proxiware CDP endpoint."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from urllib.parse import urlparse


def nft_ruleset(*, table: str, port: int, uid: int) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", table):
        raise ValueError("invalid nftables table name")
    if not 1 <= int(port) <= 65535:
        raise ValueError("invalid CDP port")
    if int(uid) < 0:
        raise ValueError("invalid browser uid")
    return (
        f"table inet {table} {{\n"
        "  chain output {\n"
        # Run before UFW's permissive output chain so the reject cannot be
        # bypassed by an earlier accept verdict.
        "    type filter hook output priority -200; policy accept;\n"
        f"    ip daddr 127.0.0.1 tcp dport {int(port)} meta skuid {int(uid)} accept\n"
        f"    ip daddr 127.0.0.1 tcp dport {int(port)} reject\n"
        "  }\n"
        "}\n"
    )


def _cdp_port(cdp_url: str) -> int:
    parsed = urlparse(str(cdp_url or "").strip())
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("CDP endpoint must be http://127.0.0.1:9222")
    try:
        port = int(parsed.port or 0)
    except ValueError:
        raise ValueError("CDP endpoint must be http://127.0.0.1:9222") from None
    if port != 9222:
        raise ValueError("CDP endpoint must be http://127.0.0.1:9222")
    return port


def _nft_binary() -> str:
    binary = shutil.which("nft")
    if not binary:
        raise RuntimeError("nftables is required for the CDP owner ACL")
    return binary


def remove_acl(*, table: str) -> None:
    subprocess.run(
        [_nft_binary(), "delete", "table", "inet", table],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def install_acl(*, table: str, cdp_url: str, user: str) -> None:
    try:
        import pwd
    except ImportError:
        raise RuntimeError("the CDP owner ACL requires POSIX") from None

    port = _cdp_port(cdp_url)
    uid = pwd.getpwnam(user).pw_uid
    binary = _nft_binary()
    remove_acl(table=table)
    subprocess.run(
        [binary, "-f", "-"],
        input=nft_ruleset(table=table, port=port, uid=uid),
        text=True,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the Proxiware loopback CDP owner ACL")
    parser.add_argument("action", choices=("install", "remove"))
    parser.add_argument("--table", default="earn_proxy_cdp")
    parser.add_argument("--cdp-url", default="http://127.0.0.1:9222")
    parser.add_argument("--user", default="earnproxy-browser")
    args = parser.parse_args()

    if args.action == "install":
        install_acl(table=args.table, cdp_url=args.cdp_url, user=args.user)
    else:
        remove_acl(table=args.table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
