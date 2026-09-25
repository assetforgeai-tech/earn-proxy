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
from typing import Any, Callable

from app import create_app
from app.db import get_db
from app.services.proxiware_health import is_proxiware_automation_paused, record_worker_heartbeat
from app.services.proxiware_swap import (
    MANUAL_ACTION_CODES,
    claim_next_swap,
    mark_swap_blocked,
    mark_swap_failed,
    mark_swap_success,
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
        self.adapter_factory = adapter_factory
        self.interval_seconds = max(1.0, float(interval_seconds))
        self.claim_seconds = max(30, int(claim_seconds))
        self._stop = threading.Event()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    def _adapter(self, job):
        if self.adapter_factory is None:
            return None
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
        if not old_external or not new_external:
            raise RuntimeError("manual_action_required")
        return result

    def run_once(self) -> dict[str, Any]:
        return self._run_once_for_job(None, allow_manual=False)

    def _run_once_for_job(self, job_id: int | None, *, allow_manual: bool) -> dict[str, Any]:
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
            job = claim_next_swap(db, claim_seconds=self.claim_seconds, job_id=job_id)
            if job is None:
                record_worker_heartbeat(db, "swap_worker", "idle")
                return {"status": "idle"}
            try:
                decision = revalidate_swap_job(db, int(job["id"]), allow_manual=allow_manual)
                if not decision.allowed:
                    return {
                        "status": "rejected",
                        "job_id": int(job["id"]),
                        "error_code": decision.reason,
                    }
                result = self._execute(self._adapter(job), job)
                mark_swap_success(
                    db,
                    int(job["id"]),
                    old_assignment_external_id=result["old_assignment_external_id"],
                    new_assignment_external_id=result["new_assignment_external_id"],
                    new_assignment=result.get("new_assignment"),
                    claim_token=job["claim_token"],
                )
                record_worker_heartbeat(db, "swap_worker", "ok", last_success=True)
                return {"status": "success", "job_id": int(job["id"])}
            except Exception as exc:  # noqa: BLE001 - worker boundary must isolate adapters
                code = safe_swap_error(exc)
                if code in MANUAL_ACTION_CODES:
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
