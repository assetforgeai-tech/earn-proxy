"""Restart-safe Proxiware inventory synchronizer.

The worker intentionally owns only read/sync work. Swap execution remains a
separate guarded job so a failed provider sync cannot mutate an assignment.
"""

from __future__ import annotations

import argparse
import logging
import signal
import threading
from dataclasses import asdict, is_dataclass
from time import monotonic
from typing import Any, Callable

from app import create_app
from app.db import get_db
from app.services.proxiware import ProxiwareClient, SyncAlreadyRunning, load_api_key_file, sync_proxiware_inventory
from app.services.proxiware_health import is_proxiware_automation_paused, record_worker_heartbeat

logger = logging.getLogger(__name__)


def safe_error_code(exc: BaseException) -> str:
    """Map provider failures to a stable code without returning exception text."""
    name = type(exc).__name__.lower()
    if isinstance(exc, SyncAlreadyRunning) or "alreadyrunning" in name:
        return "already_running"
    status = getattr(exc, "status_code", None)
    if status in {401, 403} or "auth" in name or "permission" in name:
        return "permission_denied"
    if status == 409:
        return "provider_conflict"
    if status == 429:
        return "provider_rate_limited"
    if isinstance(exc, (TimeoutError,)) or "timeout" in name:
        return "provider_timeout"
    if isinstance(exc, (ValueError, TypeError, KeyError, AttributeError)):
        return "invalid_response"
    return "provider_unavailable"


def _as_result(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return dict(asdict(value))
    if isinstance(value, dict):
        return dict(value)
    return {"result": value}


class ProxiwareSyncRunner:
    def __init__(
        self,
        *,
        app=None,
        client_factory: Callable[[str], Any] = ProxiwareClient,
        api_key_provider: Callable[[Any], str] | None = None,
        interval_seconds: int = 300,
        retry_limit: int = 3,
        retry_backoff_seconds: float = 5.0,
    ) -> None:
        self.app = app or create_app()
        self.client_factory = client_factory
        self.api_key_provider = api_key_provider or self._configured_api_key
        self.interval_seconds = max(5, int(interval_seconds))
        self.retry_limit = max(1, min(5, int(retry_limit)))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))
        self._stop = threading.Event()

    @staticmethod
    def _configured_api_key(db) -> str:
        from flask import current_app

        from app.services.proxiware_credentials import get_provider_secret

        # Database credentials are authoritative once configured; environment
        # file support remains a bootstrap fallback for first installation.
        stored = get_provider_secret(db, "api_key")
        if stored:
            return stored

        direct = str(current_app.config.get("PROXIWARE_API_KEY") or "").strip()
        if direct:
            return direct
        path = str(current_app.config.get("PROXIWARE_API_KEY_FILE") or "").strip()
        return load_api_key_file(path) if path else ""

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def _retryable(exc: BaseException) -> bool:
        return safe_error_code(exc) in {"provider_timeout", "provider_unavailable", "provider_rate_limited"}

    def run_once(self) -> dict[str, Any]:
        if self.stopped:
            return {"status": "stopped"}
        with self.app.app_context():
            db = get_db()
            if is_proxiware_automation_paused(db):
                record_worker_heartbeat(db, "sync_worker", "paused")
                return {"status": "paused"}
            record_worker_heartbeat(db, "sync_worker", "starting")
            api_key = str(self.api_key_provider(db) or "").strip()
            if not api_key:
                record_worker_heartbeat(db, "sync_worker", "not_configured", error_code="missing_api_key")
                return {"status": "not_configured", "error_code": "missing_api_key"}
            from flask import current_app

            base_url = str(current_app.config.get("PROXIWARE_API_BASE_URL") or "").strip()
            try:
                client = self.client_factory(api_key, base_url=base_url) if base_url else self.client_factory(api_key)
            except TypeError:
                # Keep simple injected test/dry-run factories one-argument compatible.
                client = self.client_factory(api_key)
            last_error: BaseException | None = None
            for attempt in range(1, self.retry_limit + 1):
                if self.stopped:
                    return {"status": "stopped", "attempt": attempt - 1}
                started = monotonic()
                try:
                    result = _as_result(sync_proxiware_inventory(db, client))
                    record_worker_heartbeat(db, "sync_worker", "ok", last_success=True)
                    result.update(
                        {"status": "ok", "attempt": attempt, "duration_ms": round((monotonic() - started) * 1000)}
                    )
                    logger.info("proxiware sync completed status=ok attempt=%s", attempt)
                    return result
                except Exception as exc:  # noqa: BLE001 - worker boundary must isolate provider failures
                    last_error = exc
                    code = safe_error_code(exc)
                    record_worker_heartbeat(db, "sync_worker", "error", error_code=code)
                    logger.warning("proxiware sync failed code=%s attempt=%s", code, attempt)
                    if not self._retryable(exc) or attempt >= self.retry_limit:
                        return {"status": "error", "error_code": code, "attempt": attempt}
                    if self._stop.wait(self.retry_backoff_seconds * attempt):
                        return {"status": "stopped", "attempt": attempt}
            return {
                "status": "error",
                "error_code": safe_error_code(last_error or RuntimeError()),
                "attempt": self.retry_limit,
            }

    def run_forever(self, *, max_cycles: int | None = None) -> int:
        cycles = 0
        while not self.stopped and (max_cycles is None or cycles < max_cycles):
            self.run_once()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            self._stop.wait(self.interval_seconds)
        return cycles


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize Proxiware static ISP inventory")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=300)
    args = parser.parse_args()
    runner = ProxiwareSyncRunner(interval_seconds=args.interval_seconds)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_once()
    else:
        runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
