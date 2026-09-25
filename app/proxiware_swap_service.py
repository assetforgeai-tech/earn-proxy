"""Restart-safe execution boundary for already-approved Proxiware swaps.

The state machine owns all persistence and guards.  This worker only calls an
injected adapter, making dry-run and production adapters interchangeable while
keeping undocumented provider mutations out of the web request path.
"""

from __future__ import annotations

import argparse
import inspect
import logging
import signal
import threading
from datetime import UTC, datetime
from typing import Any, Callable

from app import create_app
from app.db import get_db
from app.services.proxiware_browser import build_browser_adapter
from app.services.proxiware_credentials import load_provider_session, mark_manual_action_required
from app.services.proxiware_health import is_proxiware_automation_paused, record_worker_heartbeat
from app.services.proxiware_swap import (
    MANUAL_ACTION_CODES,
    claim_next_swap,
    mark_provider_applied,
    mark_reconciliation_required,
    mark_swap_blocked,
    mark_swap_failed,
    queue_eligible_swaps,
    revalidate_swap_job,
)
from app.services.settings import get_setting

logger = logging.getLogger(__name__)


def safe_swap_error(exc: BaseException) -> str:
    code = str(getattr(exc, "error_code", "") or "").strip().lower()
    if code in MANUAL_ACTION_CODES:
        return code
    message = str(exc).lower()
    for candidate in MANUAL_ACTION_CODES:
        if candidate in message:
            return candidate
    if "quota" in message:
        return "quota_exhausted"
    if "stock" in message:
        return "stock_unavailable"
    if "timeout" in message:
        return "provider_timeout"
    if "conflict" in message or "409" in message:
        return "provider_conflict"
    return "provider_error"


class DryRunSwapAdapter:
    """Adapter used by preflight; records intent without contacting Proxiware."""

    def __init__(self) -> None:
        self.calls: list[int] = []

    def swap(self, job) -> dict[str, Any]:
        self.calls.append(int(job["id"]))
        raise RuntimeError("manual_action_required")


class ProxiwareSwapRunner:
    def __init__(
        self,
        *,
        app=None,
        adapter_factory: Callable[..., Any] | None = None,
        interval_seconds: float = 5.0,
        claim_seconds: int = 300,
    ) -> None:
        self.app = app or create_app()
        self._uses_configured_adapter = adapter_factory is None
        self.adapter_factory = adapter_factory or self._configured_adapter
        self.interval_seconds = max(1.0, float(interval_seconds))
        self.claim_seconds = max(30, int(claim_seconds))
        self._stop = threading.Event()

    def _configured_adapter(self):
        return build_browser_adapter(
            enabled=bool(self.app.config.get("PROXIWARE_BROWSER_ENABLED", False)),
            cdp_url=str(self.app.config.get("PROXIWARE_CDP_URL") or "").strip() or None,
            dashboard_url=str(
                self.app.config.get("PROXIWARE_BROWSER_DASHBOARD_URL") or "https://app.proxiware.com/static/proxy/isp"
            ),
            allow_mutation=bool(self.app.config.get("PROXIWARE_BROWSER_ALLOW_MUTATION", False)),
        )

    @staticmethod
    def _configured_session(db) -> tuple[Any | None, str]:
        row = db.execute("SELECT state,expires_at FROM provider_sessions WHERE provider='proxiware'").fetchone()
        if row is None or str(row["state"] or "").strip().lower() != "active":
            return None, "session_expired"
        expires_at = str(row["expires_at"] or "").strip()
        if expires_at:
            try:
                expiry = datetime.fromisoformat(expires_at)
                expiry = expiry.astimezone(UTC) if expiry.tzinfo else expiry.replace(tzinfo=UTC)
            except ValueError:
                return None, "invalid_session"
            if expiry <= datetime.now(UTC):
                return None, "session_expired"
        try:
            cookies = load_provider_session(db)
        except ValueError:
            return None, "invalid_session"
        return (cookies, "") if cookies else (None, "session_expired")

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    def _adapter(self, job):
        try:
            parameters = inspect.signature(self.adapter_factory).parameters
            if parameters:
                return self.adapter_factory(job)
        except (TypeError, ValueError):
            pass
        return self.adapter_factory()

    @staticmethod
    def _execute(adapter, job) -> dict[str, Any]:
        if adapter is None:
            raise RuntimeError("manual_action_required")
        method = getattr(adapter, "swap", None) or getattr(adapter, "execute_swap", None)
        if method is None:
            raise RuntimeError("manual_action_required")
        result = method(job)
        if not isinstance(result, dict):
            raise RuntimeError("manual_action_required")
        old_external = str(result.get("old_assignment_external_id") or "").strip()
        new_external = str(result.get("new_assignment_external_id") or "").strip()
        new_address = str(result.get("new_assignment_address") or "").strip()
        if not old_external or not (new_external or new_address):
            raise RuntimeError("manual_action_required")
        return result

    @staticmethod
    def _close_adapter(adapter: Any | None) -> None:
        close = getattr(adapter, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001 - cleanup must not mask swap state
                logger.warning("proxiware swap adapter cleanup failed")

    def run_once(self) -> dict[str, Any]:
        return self._run_once_for_job(None, allow_manual=False)

    def _run_once_for_job(self, job_id: int | None, *, allow_manual: bool) -> dict[str, Any]:
        adapter_holder: dict[str, Any | None] = {"adapter": None}
        try:
            return self._run_once_for_job_impl(job_id, allow_manual=allow_manual, adapter_holder=adapter_holder)
        finally:
            self._close_adapter(adapter_holder["adapter"])

    def _run_once_for_job_impl(
        self,
        job_id: int | None,
        *,
        allow_manual: bool,
        adapter_holder: dict[str, Any | None],
    ) -> dict[str, Any]:
        if self.stopped:
            return {"status": "stopped"}
        with self.app.app_context():
            db = get_db()
            record_worker_heartbeat(db, "swap_worker", "starting")
            if is_proxiware_automation_paused(db) and not allow_manual:
                record_worker_heartbeat(db, "swap_worker", "paused")
                return {"status": "paused"}
            if get_setting(db, "proxiware_swap_worker_paused", "0") == "1":
                record_worker_heartbeat(db, "swap_worker", "paused")
                return {"status": "paused"}
            if not allow_manual and get_setting(db, "proxiware_auto_swap", "0") != "1":
                record_worker_heartbeat(db, "swap_worker", "disabled")
                return {"status": "disabled"}
            configured_adapter = None
            if self._uses_configured_adapter:
                if (
                    not bool(self.app.config.get("PROXIWARE_BROWSER_ENABLED", False))
                    or not bool(self.app.config.get("PROXIWARE_BROWSER_ALLOW_MUTATION", False))
                    or bool(self.app.config.get("PROXIWARE_BROWSER_DRY_RUN", False))
                ):
                    record_worker_heartbeat(db, "swap_worker", "manual_action_required", error_code="adapter_missing")
                    return {"status": "manual_action_required", "error_code": "adapter_missing"}
                cookies, session_error = self._configured_session(db)
                if session_error:
                    mark_manual_action_required(db, session_error)
                    record_worker_heartbeat(db, "swap_worker", "manual_action_required", error_code=session_error)
                    return {"status": "manual_action_required", "error_code": session_error}
                try:
                    configured_adapter = self._adapter(None)
                    adapter_holder["adapter"] = configured_adapter
                    restore = getattr(configured_adapter, "restore_session", None)
                    if not callable(restore):
                        raise RuntimeError("adapter_missing")
                    restore(cookies)
                except Exception as exc:  # noqa: BLE001 - session restore must fail before a mutation claim
                    code = safe_swap_error(exc)
                    if code == "provider_error":
                        code = "manual_action_required"
                    mark_manual_action_required(db, code)
                    record_worker_heartbeat(db, "swap_worker", "manual_action_required", error_code=code)
                    return {"status": "manual_action_required", "error_code": code}
            if not allow_manual and job_id is None:
                queue_eligible_swaps(db)
            job = claim_next_swap(db, claim_seconds=self.claim_seconds, job_id=job_id)
            if job is None:
                record_worker_heartbeat(db, "swap_worker", "idle")
                return {"status": "idle"}
            context = db.execute(
                "SELECT sj.*, pa.external_id AS old_assignment_external_id, "
                "pa.dashboard_assignment_id, pa.dashboard_eligible, pa.dashboard_connections, "
                "ps.external_id AS subscription_external_id "
                "FROM swap_jobs sj "
                "JOIN provider_assignments pa ON pa.id=sj.old_assignment_id "
                "JOIN provider_subscriptions ps ON ps.id=sj.subscription_id "
                "WHERE sj.id=? AND sj.provider=? AND pa.provider=? AND ps.provider=?",
                (int(job["id"]), "proxiware", "proxiware", "proxiware"),
            ).fetchone()
            if context is None:
                mark_swap_blocked(
                    db, int(job["id"]), error_code="manual_action_required", claim_token=job["claim_token"]
                )
                record_worker_heartbeat(db, "swap_worker", "blocked", error_code="manual_action_required")
                return {"status": "blocked", "job_id": int(job["id"]), "error_code": "manual_action_required"}
            job = context
            mutation_started = False
            try:
                decision = revalidate_swap_job(
                    db,
                    int(job["id"]),
                    allow_manual=allow_manual,
                    claim_token=job["claim_token"],
                )
                if not decision.allowed:
                    record_worker_heartbeat(db, "swap_worker", "blocked", error_code=decision.reason)
                    return {
                        "status": "rejected",
                        "job_id": int(job["id"]),
                        "error_code": decision.reason,
                    }
                adapter = configured_adapter or self._adapter(job)
                adapter_holder["adapter"] = adapter
                if adapter is None or not (getattr(adapter, "swap", None) or getattr(adapter, "execute_swap", None)):
                    raise RuntimeError("manual_action_required")
                if getattr(adapter, "allow_mutation", True) is not True:
                    raise RuntimeError("manual_action_required")
                decision = revalidate_swap_job(
                    db,
                    int(job["id"]),
                    allow_manual=allow_manual,
                    claim_token=job["claim_token"],
                    enter_mutation=True,
                )
                if not decision.allowed:
                    record_worker_heartbeat(db, "swap_worker", "blocked", error_code=decision.reason)
                    return {
                        "status": "rejected",
                        "job_id": int(job["id"]),
                        "error_code": decision.reason,
                    }
                mutation_started = True
                fenced = db.execute(
                    "SELECT * FROM swap_jobs WHERE id=? AND provider=? AND state='mutating' AND claim_token=?",
                    (int(job["id"]), "proxiware", str(job["claim_token"])),
                ).fetchone()
                if fenced is None:
                    raise RuntimeError("manual_action_required")
                job = dict(fenced)
                job["old_assignment_external_id"] = job["mutation_old_assignment_external_id"]
                job["dashboard_assignment_id"] = job["mutation_dashboard_assignment_id"]
                job["subscription_external_id"] = job["mutation_subscription_external_id"]
                result = self._execute(adapter, job)
                mark_provider_applied(
                    db,
                    int(job["id"]),
                    old_assignment_external_id=result["old_assignment_external_id"],
                    new_assignment_external_id=result.get("new_assignment_external_id"),
                    new_assignment_address=result.get("new_assignment_address"),
                    applied_at=datetime.now(UTC),
                    claim_token=job["claim_token"],
                )
                record_worker_heartbeat(db, "swap_worker", "provider_applied")
                return {"status": "reconciliation_required", "job_id": int(job["id"])}
            except Exception as exc:  # noqa: BLE001 - worker boundary must isolate adapters
                code = safe_swap_error(exc)
                if mutation_started:
                    mark_reconciliation_required(
                        db,
                        int(job["id"]),
                        error_code=code,
                        claim_token=job["claim_token"],
                    )
                    state = "reconciliation_required"
                elif code in MANUAL_ACTION_CODES:
                    mark_swap_blocked(db, int(job["id"]), error_code=code, claim_token=job["claim_token"])
                    state = "blocked"
                else:
                    state = mark_swap_failed(
                        db,
                        int(job["id"]),
                        error_code=code,
                        claim_token=job["claim_token"],
                    )
                logger.warning("proxiware swap job=%s state=%s code=%s", job["id"], state, code)
                record_worker_heartbeat(db, "swap_worker", state, error_code=code)
                return {"status": state, "job_id": int(job["id"]), "error_code": code}

    def run_job(self, job_id: int) -> dict[str, Any]:
        """Execute one explicitly selected job for an admin manual action."""

        return self._run_once_for_job(int(job_id), allow_manual=True)

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
    parser = argparse.ArgumentParser(description="Execute guarded Proxiware swap jobs")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    args = parser.parse_args()
    runner = ProxiwareSwapRunner(interval_seconds=args.interval_seconds)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_once()
    else:
        runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
