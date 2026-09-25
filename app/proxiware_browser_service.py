"""Read-only Proxiware dashboard observation worker.

Provider mutation remains in the separately guarded swap worker. This worker
restores an encrypted session, observes the dashboard, and stores only typed
safe fields plus durable heartbeat metadata.
"""

from __future__ import annotations

import argparse
import logging
import signal
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from typing import Any, Callable

from app import create_app
from app.db import get_db
from app.services.proxiware_browser import (
    BrowserAdapterUnavailable,
    BrowserProviderResponseError,
    build_browser_adapter,
)
from app.services.proxiware_credentials import load_provider_session, mark_manual_action_required
from app.services.proxiware_dashboard import (
    DashboardAssignment,
    DashboardObservationError,
    apply_dashboard_snapshot,
)
from app.services.proxiware_health import is_proxiware_automation_paused, record_worker_heartbeat

logger = logging.getLogger(__name__)
DEFAULT_INTERVAL_SECONDS = 300


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


class ProxiwareBrowserRunner:
    def __init__(
        self,
        *,
        app=None,
        adapter_factory: Callable[[], Any] | None = None,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        now: Callable[[], datetime] | None = None,
        heartbeat_interval_seconds: float | None = None,
    ) -> None:
        self.app = app or create_app()
        self._uses_configured_adapter = adapter_factory is None
        self.adapter_factory = adapter_factory or self._configured_adapter
        self.interval_seconds = max(5.0, float(interval_seconds))
        self.now = now or (lambda: datetime.now(UTC))
        self.heartbeat_interval_seconds = max(
            0.05,
            float(
                heartbeat_interval_seconds
                if heartbeat_interval_seconds is not None
                else min(60.0, self.interval_seconds / 4)
            ),
        )
        self._stop = Event()

    def _configured_adapter(self):
        factory = self.app.extensions.get("proxiware_browser_adapter_factory")
        if factory is not None:
            return factory()
        return build_browser_adapter(
            enabled=bool(self.app.config.get("PROXIWARE_BROWSER_ENABLED", False)),
            cdp_url=str(self.app.config.get("PROXIWARE_CDP_URL") or "").strip() or None,
            dry_run=bool(self.app.config.get("PROXIWARE_BROWSER_DRY_RUN", False)),
            dashboard_url=str(
                self.app.config.get("PROXIWARE_BROWSER_DASHBOARD_URL") or "https://app.proxiware.com/static/proxy/isp"
            ),
            # The observer boundary is read-only; swap mutation is built only
            # by the separately guarded swap worker.
            allow_mutation=False,
        )

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    def _wait_with_heartbeat(self, seconds: float) -> None:
        remaining = max(0.0, float(seconds))
        while remaining > 0 and not self.stopped:
            with self.app.app_context():
                record_worker_heartbeat(get_db(), "browser_worker", "sleeping")
            step = min(60.0, remaining)
            if self._stop.wait(step):
                break
            remaining -= step

    def _active_session(self, db, current: datetime):
        row = db.execute("SELECT state,expires_at FROM provider_sessions WHERE provider='proxiware'").fetchone()
        if row is None or str(row["state"] or "").strip().lower() != "active":
            return None
        expires_at = str(row["expires_at"] or "").strip()
        if expires_at:
            try:
                if _utc(datetime.fromisoformat(expires_at)) <= current:
                    return None
            except ValueError:
                raise BrowserAdapterUnavailable("invalid_session") from None
        try:
            return load_provider_session(db)
        except ValueError:
            raise BrowserAdapterUnavailable("invalid_session") from None

    def _subscriptions(self, db, current: datetime) -> list[str]:
        rows = db.execute(
            "SELECT external_id FROM provider_subscriptions WHERE provider='proxiware' "
            "AND status IN ('active','ready') AND missing_at IS NULL "
            "AND (dashboard_next_observe_at IS NULL OR dashboard_next_observe_at<=?) ORDER BY id",
            (current.isoformat(),),
        ).fetchall()
        return [str(row["external_id"]) for row in rows]

    def _schedule(self, db, subscription_id: str, current: datetime, *, error_code: str = "") -> None:
        row = db.execute(
            "SELECT dashboard_observation_failures FROM provider_subscriptions "
            "WHERE provider='proxiware' AND external_id=?",
            (str(subscription_id),),
        ).fetchone()
        failures = int(row["dashboard_observation_failures"] or 0) if row else 0
        if error_code:
            failures += 1
            delay = min(self.interval_seconds, max(30.0, 30.0 * (2 ** min(failures - 1, 6))))
        else:
            failures = 0
            delay = self.interval_seconds
        next_at = (current + timedelta(seconds=delay)).isoformat()
        db.execute(
            "UPDATE provider_subscriptions SET dashboard_next_observe_at=?, "
            "dashboard_observation_failures=?, dashboard_last_error_code=?, updated_at=? "
            "WHERE provider='proxiware' AND external_id=?",
            (next_at, failures, str(error_code or ""), current.isoformat(), str(subscription_id)),
        )
        db.commit()

    def _manual(self, db, code: str, *, subscriptions: int = 0) -> dict[str, Any]:
        mark_manual_action_required(db, code, now=self.now())
        record_worker_heartbeat(db, "browser_worker", "manual_action_required", error_code=code)
        return {"status": "manual_action_required", "observed": 0, "subscriptions": subscriptions}

    @staticmethod
    def _safe_degraded_code(exc: BaseException) -> str:
        if isinstance(exc, DashboardObservationError):
            message = str(exc).strip().lower().replace(" ", "_")
            if message in {
                "empty_dashboard_snapshot",
                "ambiguous_dashboard_assignment",
                "dashboard_assignment_not_found",
            }:
                return message.replace("dashboard_", "")
            return "provider_error"
        if isinstance(exc, TimeoutError):
            return "provider_timeout"
        if isinstance(exc, BrowserProviderResponseError):
            return str(getattr(exc, "error_code", "provider_error") or "provider_error")
        if isinstance(exc, (ConnectionError, OSError)):
            return "provider_unavailable"
        return "provider_error"

    def _active_heartbeat(self, stop: Event) -> None:
        while not stop.wait(self.heartbeat_interval_seconds):
            if self.stopped:
                return
            try:
                with self.app.app_context():
                    record_worker_heartbeat(get_db(), "browser_worker", "running")
            except Exception:  # noqa: BLE001 - heartbeat must not kill observation
                logger.warning("proxiware browser heartbeat update failed")

    def run_once(self) -> dict[str, Any]:
        if self.stopped:
            return {"status": "stopped", "observed": 0, "subscriptions": 0}
        current = _utc(self.now())
        with self.app.app_context():
            db = get_db()
            if is_proxiware_automation_paused(db):
                record_worker_heartbeat(db, "browser_worker", "paused")
                return {"status": "paused", "observed": 0, "subscriptions": 0}
            if self._uses_configured_adapter and not bool(self.app.config.get("PROXIWARE_BROWSER_ENABLED", False)):
                record_worker_heartbeat(db, "browser_worker", "disabled")
                return {"status": "disabled", "observed": 0, "subscriptions": 0}
            subscriptions = self._subscriptions(db, current)
            if not subscriptions:
                record_worker_heartbeat(
                    db,
                    "browser_worker",
                    "idle",
                    next_wake_at=current + timedelta(seconds=self.interval_seconds),
                )
                return {"status": "idle", "observed": 0, "subscriptions": 0}
            try:
                cookies = self._active_session(db, current)
            except BrowserAdapterUnavailable as exc:
                return self._manual(db, exc.error_code, subscriptions=len(subscriptions))
            if cookies is None:
                return self._manual(db, "session_expired", subscriptions=len(subscriptions))
            adapter = None
            heartbeat_stop = None
            heartbeat_thread = None
            try:
                adapter = self.adapter_factory()
                if adapter is None:
                    raise BrowserAdapterUnavailable("manual_action_required")
                restore = getattr(adapter, "restore_session", None)
                observe = getattr(adapter, "observe_dashboard", None)
                if restore is None or observe is None:
                    raise BrowserAdapterUnavailable("manual_action_required")
                heartbeat_stop = Event()
                heartbeat_thread = Thread(target=self._active_heartbeat, args=(heartbeat_stop,), daemon=True)
                heartbeat_thread.start()
                record_worker_heartbeat(db, "browser_worker", "running")
                restore(cookies)
                observed = 0
                for subscription_id in subscriptions:
                    try:
                        snapshots = observe(subscription_id=subscription_id)
                        if not isinstance(snapshots, list) or not all(
                            isinstance(snapshot, DashboardAssignment) for snapshot in snapshots
                        ):
                            raise DashboardObservationError("invalid dashboard response")
                        if any(
                            str(snapshot.subscription_id).strip() != str(subscription_id).strip()
                            for snapshot in snapshots
                        ):
                            raise DashboardObservationError("dashboard subscription scope mismatch")
                        apply_dashboard_snapshot(db, subscription_id, snapshots, now=current)
                        self._schedule(db, subscription_id, current)
                        observed += len(snapshots)
                    except Exception as exc:
                        code = self._safe_degraded_code(exc)
                        self._schedule(db, subscription_id, current, error_code=code)
                        raise
                record_worker_heartbeat(db, "browser_worker", "ok", last_success=True)
                return {"status": "ok", "observed": observed, "subscriptions": len(subscriptions)}
            except BrowserAdapterUnavailable as exc:
                code = str(getattr(exc, "error_code", "manual_action_required") or "manual_action_required")
                return self._manual(db, code, subscriptions=len(subscriptions))
            except DashboardObservationError as exc:
                if "scope mismatch" in str(exc).lower():
                    return self._manual(db, "manual_action_required", subscriptions=len(subscriptions))
                code = self._safe_degraded_code(exc)
                record_worker_heartbeat(db, "browser_worker", "degraded", error_code=code)
                return {"status": "degraded", "observed": 0, "subscriptions": len(subscriptions), "error_code": code}
            except (BrowserProviderResponseError, TimeoutError, ConnectionError, OSError) as exc:
                code = self._safe_degraded_code(exc)
                record_worker_heartbeat(db, "browser_worker", "degraded", error_code=code)
                return {"status": "degraded", "observed": 0, "subscriptions": len(subscriptions), "error_code": code}
            except Exception:  # noqa: BLE001 - browser boundary must fail closed
                logger.warning("proxiware dashboard observation failed code=provider_error")
                record_worker_heartbeat(db, "browser_worker", "degraded", error_code="provider_error")
                return {
                    "status": "degraded",
                    "observed": 0,
                    "subscriptions": len(subscriptions),
                    "error_code": "provider_error",
                }
            finally:
                if heartbeat_stop is not None:
                    heartbeat_stop.set()
                if heartbeat_thread is not None:
                    heartbeat_thread.join(timeout=max(1.0, self.heartbeat_interval_seconds * 2))
                close = getattr(adapter, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:  # noqa: BLE001 - cleanup must not mask worker state
                        logger.warning("proxiware browser adapter cleanup failed")

    def run_forever(self, *, max_cycles: int | None = None) -> int:
        cycles = 0
        while not self.stopped and (max_cycles is None or cycles < max_cycles):
            self.run_once()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            self._wait_with_heartbeat(self.interval_seconds)
        return cycles


def main() -> int:
    parser = argparse.ArgumentParser(description="Observe Proxiware dashboard state")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    args = parser.parse_args()
    app = create_app()
    runner = ProxiwareBrowserRunner(
        app=app,
        interval_seconds=args.interval_seconds,
        heartbeat_interval_seconds=float(app.config.get("PROXIWARE_BROWSER_HEARTBEAT_INTERVAL_SECONDS", 30)),
    )
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_once()
    else:
        runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
