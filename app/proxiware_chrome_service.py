"""Optional isolated Chromium launcher for the Proxiware observer boundary."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from urllib.parse import urlparse


@dataclass(frozen=True)
class ChromeConfig:
    enabled: bool
    binary: Path
    cdp_url: str
    profile_dir: Path
    profile_root: Path | None = None
    headless: bool = True


def _loopback_port(cdp_url: str) -> int:
    parsed = urlparse(str(cdp_url or "").strip())
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("CDP endpoint must be loopback")
    try:
        port = int(parsed.port or 0)
    except ValueError:
        raise ValueError("CDP endpoint port is invalid") from None
    if not 1 <= port <= 65535:
        raise ValueError("CDP endpoint port is invalid")
    return port


def build_chrome_command(config: ChromeConfig) -> list[str]:
    if not config.enabled:
        return []
    binary = Path(config.binary)
    if not binary.is_absolute():
        raise ValueError("Chrome binary must be absolute")
    if not binary.is_file():
        raise ValueError("Chrome binary is missing")
    profile = Path(config.profile_dir)
    if not profile.is_absolute():
        raise ValueError("Chrome profile must be absolute")
    profile = profile.resolve()
    if config.profile_root is not None:
        root = Path(config.profile_root)
        if not root.is_absolute():
            raise ValueError("Chrome profile root must be absolute")
        root = root.resolve()
        try:
            profile.relative_to(root)
        except ValueError:
            raise ValueError("Chrome profile must stay inside isolated root") from None
    port = _loopback_port(config.cdp_url)
    profile.mkdir(parents=True, exist_ok=True)
    command = [
        str(binary.resolve()),
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-features=Translate,MediaRouter",
    ]
    if config.headless:
        command.append("--headless=new")
    return command


def _chrome_child_environment(config: ChromeConfig) -> dict[str, str]:
    """Keep application credentials out of the browser process environment."""

    profile = Path(config.profile_dir).resolve()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("EARN_PROXY_")}
    environment["HOME"] = str(profile.parent)
    environment["XDG_CONFIG_HOME"] = str(profile / "config")
    environment["XDG_CACHE_HOME"] = str(profile / "cache")
    return environment


def _config_from_env() -> ChromeConfig:
    return ChromeConfig(
        enabled=os.environ.get("EARN_PROXY_PROXIWARE_CHROME_ENABLED", "0") == "1",
        binary=Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_BINARY", "/usr/bin/google-chrome")),
        cdp_url=os.environ.get("EARN_PROXY_PROXIWARE_CDP_URL", "http://127.0.0.1:9222"),
        profile_dir=Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR", "/run/earn-proxy-browser/profile")),
        profile_root=Path(os.environ.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT", "/run/earn-proxy-browser")),
        headless=os.environ.get("EARN_PROXY_PROXIWARE_CHROME_HEADLESS", "1") == "1",
    )


def run(config: ChromeConfig) -> int:
    command = build_chrome_command(config)
    if not command:
        # Keep the systemd unit stable while the feature is intentionally off;
        # an immediate exit would create a Restart=always loop.
        stopped = Event()
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
        stopped.wait()
        return 0
    process = subprocess.Popen(command, close_fds=True, env=_chrome_child_environment(config))

    def stop(*_args) -> None:
        if process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    return int(process.wait())


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the isolated Proxiware Chromium CDP process")
    parser.add_argument("--once", action="store_true", help="validate configuration and exit")
    args = parser.parse_args()
    config = _config_from_env()
    if args.once:
        build_chrome_command(config)
        return 0
    return run(config)


if __name__ == "__main__":
    raise SystemExit(main())
