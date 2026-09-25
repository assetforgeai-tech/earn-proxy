from __future__ import annotations

import argparse
import importlib.util
import os
import posixpath
import sqlite3
import sys
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse


def validate_runtime_prefix(release_dir: Path) -> list[str]:
    expected = (release_dir / ".venv").resolve()
    actual = Path(sys.prefix).resolve()
    if actual != expected:
        return [f"virtualenv prefix is not {expected}"]
    return []


def validate_browser_runtime(environment: Mapping[str, str] | None = None) -> list[str]:
    env = os.environ if environment is None else environment
    browser_enabled = str(env.get("EARN_PROXY_PROXIWARE_BROWSER_ENABLED", "0")) == "1"
    chrome_enabled = str(env.get("EARN_PROXY_PROXIWARE_CHROME_ENABLED", "0")) == "1"
    if browser_enabled and not chrome_enabled:
        return ["enabled Proxiware browser requires isolated Chrome"]
    if not chrome_enabled:
        return []

    errors: list[str] = []
    binary = Path(str(env.get("EARN_PROXY_PROXIWARE_CHROME_BINARY", "/usr/bin/google-chrome")))
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        errors.append("Proxiware Chrome binary is missing or not executable")

    endpoint = urlparse(str(env.get("EARN_PROXY_PROXIWARE_CDP_URL", "http://127.0.0.1:9222")))
    try:
        port = int(endpoint.port or 0)
    except ValueError:
        port = 0
    if (
        endpoint.scheme not in {"http", "https"}
        or endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
        or not 1 <= port <= 65535
    ):
        errors.append("Proxiware CDP endpoint must be loopback HTTP with an explicit port")

    root = posixpath.normpath(
        str(env.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_ROOT", "/run/earn-proxy-browser"))
    )
    profile = posixpath.normpath(
        str(env.get("EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR", "/run/earn-proxy-browser/profile"))
    )
    if not root.startswith("/run/"):
        errors.append("Proxiware Chrome profile root must be under /run")
    if profile == root or not profile.startswith(root.rstrip("/") + "/"):
        errors.append("Proxiware Chrome profile must stay inside its runtime root")
    return errors


def validate_runtime(release_dir: Path) -> list[str]:
    errors = validate_runtime_prefix(release_dir)
    errors.extend(validate_browser_runtime())
    missing_modules = [
        name
        for name in ("app", "cryptography", "flask", "gunicorn", "playwright", "requests", "urllib3")
        if importlib.util.find_spec(name) is None
    ]
    if missing_modules:
        return [*errors, f"runtime modules are missing: {', '.join(missing_modules)}"]

    import app

    app_path = Path(app.__file__).resolve()
    if release_dir.resolve() not in app_path.parents:
        errors.append(f"application package is outside {release_dir.resolve()}")

    required_env = (
        "EARN_PROXY_SECRET_KEY",
        "EARN_PROXY_FERNET_KEY",
        "EARN_PROXY_INTERNAL_API_KEY",
        "EARN_PROXY_ADMIN_PASSWORD",
        "EARN_PROXY_DATABASE",
    )
    missing = [name for name in required_env if not str(os.environ.get(name) or "").strip()]
    if missing:
        errors.append(f"required environment is missing: {', '.join(missing)}")
        return errors

    from app import create_app

    application = create_app()
    database = Path(application.config["DATABASE"])
    if not database.is_absolute():
        errors.append("production database path is not absolute")
    if release_dir.resolve() in database.resolve().parents:
        errors.append("production database is inside the immutable release directory")
    try:
        with sqlite3.connect(database) as connection:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                errors.append("database quick_check did not return ok")
    except sqlite3.Error as exc:
        errors.append(f"database check failed: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Earn Proxy release before activation.")
    parser.add_argument("--release-dir", type=Path, default=Path.cwd())
    args = parser.parse_args()
    errors = validate_runtime(args.release_dir)
    if errors:
        for error in errors:
            print(f"preflight: {error}", file=sys.stderr)
        return 1
    print("preflight: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
