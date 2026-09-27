"""Import an operator-authenticated Proxiware browser session from stdin."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from app import create_app
from app.db import get_db
from app.services.proxiware_browser import BrowserAdapterUnavailable, _safe_cookie_list
from app.services.proxiware_credentials import record_provider_audit, store_provider_session

MAX_INPUT_BYTES = 64 * 1024
MAX_COOKIES = 100
DASHBOARD_URL = "https://app.proxiware.com/static/proxy/isp"


def _expiry(cookies: list[dict[str, object]], current: datetime) -> datetime:
    candidates: list[datetime] = []
    for cookie in cookies:
        try:
            timestamp = float(cookie.get("expires") or 0)
        except (TypeError, ValueError):
            continue
        if timestamp > current.timestamp():
            candidates.append(datetime.fromtimestamp(timestamp, UTC))
    # ponytail: session-only cookies get a one-hour lease; add a manual
    # revalidation endpoint if the provider exposes authoritative expiry.
    return min(candidates) if candidates else current + timedelta(hours=1)


def import_session(db, stream: TextIO, *, now: datetime | None = None) -> dict[str, object]:
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("input_too_large")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError("invalid_session") from None
    if isinstance(payload, dict) and isinstance(payload.get("cookies"), list):
        payload = payload["cookies"]
    if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_COOKIES:
        raise ValueError("invalid_session")
    try:
        cookies = _safe_cookie_list(payload, url=DASHBOARD_URL)
    except (BrowserAdapterUnavailable, TypeError, ValueError):
        raise ValueError("invalid_session") from None

    current = now or datetime.now(UTC)
    current = current.astimezone(UTC) if current.tzinfo else current.replace(tzinfo=UTC)
    expires_at = _expiry(cookies, current)
    store_provider_session(db, cookies, expires_at=expires_at, now=current)
    record_provider_audit(db, action="import_session", result="success", now=current)
    return {"status": "active", "cookie_count": len(cookies), "expires_at": expires_at.isoformat()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a Proxiware session from JSON on stdin")
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args()
    app = create_app({"DATABASE": str(args.database)})
    try:
        with app.app_context():
            result = import_session(get_db(), sys.stdin)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
