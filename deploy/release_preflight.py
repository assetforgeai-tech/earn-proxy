from __future__ import annotations

import argparse
import importlib.util
import os
import sqlite3
import sys
from pathlib import Path


def validate_runtime_prefix(release_dir: Path) -> list[str]:
    expected = (release_dir / ".venv").resolve()
    actual = Path(sys.prefix).resolve()
    if actual != expected:
        return [f"virtualenv prefix is not {expected}"]
    return []


def validate_runtime(release_dir: Path) -> list[str]:
    errors = validate_runtime_prefix(release_dir)
    missing_modules = [
        name
        for name in ("app", "cryptography", "flask", "gunicorn", "requests", "urllib3")
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
