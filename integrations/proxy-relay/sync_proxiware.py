from __future__ import annotations

import json
import logging
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from app import PROXIWARE_SLOT_FEED_URL, RELAY_FEED_KEY, conn, reload_relay, sync_proxiware_bindings

MAX_FEED_BYTES = 15_000_000


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def fetch_slots() -> list[dict]:
    target = urlsplit(PROXIWARE_SLOT_FEED_URL)
    if (
        target.scheme != "http"
        or target.hostname not in {"127.0.0.1", "localhost", "::1"}
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        raise ValueError("invalid feed target")
    if not RELAY_FEED_KEY:
        raise ValueError("missing feed key")
    request = Request(
        PROXIWARE_SLOT_FEED_URL,
        headers={"X-Relay-Feed-Key": RELAY_FEED_KEY, "Accept": "application/json"},
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=8) as response:
        content = response.read(MAX_FEED_BYTES + 1)
    if len(content) > MAX_FEED_BYTES:
        raise ValueError("feed too large")
    payload = json.loads(content)
    if not isinstance(payload, dict) or payload.get("complete") is not True:
        raise ValueError("incomplete feed")
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > 50000:
        raise ValueError("invalid feed")
    if payload.get("count") != len(items):
        raise ValueError("inconsistent feed count")
    return items


def run_sync() -> dict[str, int | bool]:
    items = fetch_slots()
    database = conn()
    try:
        result = sync_proxiware_bindings(database, items, reload=False)
    finally:
        database.close()
    if result["changed"]:
        reload_relay()
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        logging.info("Proxiware slot sync complete: %s", json.dumps(run_sync(), sort_keys=True))
    except HTTPError as error:
        logging.error("Proxiware slot sync failed: provider_feed_http_%s", error.code)
        raise SystemExit(1) from None
    except (URLError, TimeoutError):
        logging.error("Proxiware slot sync failed: provider_feed_unavailable")
        raise SystemExit(1) from None
    except (ValueError, json.JSONDecodeError):
        logging.error("Proxiware slot sync failed: invalid_provider_feed")
        raise SystemExit(1) from None
    except Exception as error:  # noqa: BLE001
        # Keep upstream credentials out of systemd logs.
        logging.error("Proxiware slot sync failed: internal_error_%s", type(error).__name__)
        raise SystemExit(1) from None
