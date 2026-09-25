"""Restart-safe, bounded qualification worker for provider assignments."""

from __future__ import annotations

import argparse
import asyncio
import logging
import secrets
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any, Callable

from app import create_app
from app.checker import check_proxy
from app.db import get_db
from app.earnapp_probe import probe_earnapp_proxy
from app.services.proxiware_health import is_proxiware_automation_paused, record_worker_heartbeat
from app.services.proxiware_qualification import qualify_proxiware_assignment
from app.services.proxiware_swap import ensure_proxiware_swap_schema
from app.services.settings import get_setting

logger = logging.getLogger(__name__)
DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_CLAIM_SECONDS = 900
MAX_CONCURRENCY = 20


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _default_probe(proxy: dict[str, Any]) -> dict[str, Any]:
    return check_proxy(proxy)


def _default_eligibility(proxy: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(
        probe_earnapp_proxy(
            proxy["host"],
            proxy["port"],
            protocol=proxy.get("protocol", "auto"),
            username=proxy.get("username", ""),
            password=proxy.get("password", ""),
        )
    )
    return {
        "verdict": result.get("verdict", "UNKNOWN"),
        "reason": result.get("reason", ""),
    }


class ProxiwareQualificationRunner:
    """Claim due assignments, process a bounded batch, then sleep when idle."""

    def __init__(
        self,
        *,
        app=None,
        probe: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        eligibility: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        concurrency: int | None = None,
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
        claim_seconds: int = DEFAULT_CLAIM_SECONDS,
        check_interval_seconds: int | None = None,
    ) -> None:
        self.app = app or create_app()
        self.probe = probe or _default_probe
        self.eligibility = eligibility or _default_eligibility
        self.concurrency = None if concurrency is None else max(1, min(MAX_CONCURRENCY, int(concurrency)))
        self.interval_seconds = max(5, int(interval_seconds))
        self.claim_seconds = max(60, int(claim_seconds))
        self.check_interval_seconds = max(60, int(check_interval_seconds or interval_seconds))
        self._stop = Event()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def stop(self) -> None:
        self._stop.set()

    def _wait_with_heartbeat(self, seconds: float) -> None:
        """Sleep in bounded slices so an idle worker remains observable."""

        remaining = max(0.0, float(seconds))
        while remaining > 0 and not self.stopped:
            with self.app.app_context():
                record_worker_heartbeat(get_db(), "qualification_worker", "sleeping")
            step = min(60.0, remaining)
            if self._stop.wait(step):
                break
            remaining -= step

    def _settings(self, db) -> tuple[int, int]:
        concurrency = self.concurrency
        if concurrency is None:
            try:
                concurrency = int(get_setting(db, "proxiware_worker_concurrency", "1"))
            except (TypeError, ValueError):
                concurrency = 1
        try:
            interval = int(get_setting(db, "proxiware_qualification_interval_seconds", str(self.interval_seconds)))
        except (TypeError, ValueError):
            interval = self.interval_seconds
        return max(1, min(MAX_CONCURRENCY, concurrency)), max(60, interval)

    @staticmethod
    def _claim(db, *, limit: int, claim_seconds: int, now: datetime) -> list[tuple[int, str]]:
        ensure_proxiware_swap_schema(db)
        token = secrets.token_urlsafe(18)
        claimed_until = (now + timedelta(seconds=max(60, claim_seconds))).isoformat()
        timestamp = now.isoformat()
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute(
                "SELECT id FROM provider_assignments "
                "WHERE provider='proxiware' AND missing_at IS NULL "
                "AND status IN ('active','current') "
                "AND (qualification_next_check_at IS NULL OR qualification_next_check_at<=? "
                "OR qualification_claimed_until IS NOT NULL AND qualification_claimed_until<=?) "
                "AND (qualification_claimed_until IS NULL OR qualification_claimed_until<=?) "
                "ORDER BY COALESCE(qualification_next_check_at, created_at), id LIMIT ?",
                (timestamp, timestamp, timestamp, max(1, int(limit))),
            ).fetchall()
            if rows:
                db.executemany(
                    "UPDATE provider_assignments SET qualification_claim_token=?, qualification_claimed_until=?, "
                    "updated_at=? WHERE id=?",
                    [(token, claimed_until, timestamp, int(row["id"])) for row in rows],
                )
            db.commit()
            return [(int(row["id"]), token) for row in rows]
        except Exception:
            db.rollback()
            raise

    def _process_one(self, assignment_id: int, token: str, interval_seconds: int) -> dict[str, Any]:
        with self.app.app_context():
            db = get_db()
            try:
                result = qualify_proxiware_assignment(
                    db,
                    assignment_id,
                    probe=self.probe,
                    eligibility=self.eligibility,
                    claim_token=token,
                    check_interval_seconds=interval_seconds,
                )
                return {"status": "checked", "assignment_id": assignment_id, "qualification": result.qualification}
            except LookupError:
                return {"status": "stale_claim", "assignment_id": assignment_id}
            except Exception:  # noqa: BLE001 - isolate one provider row
                now = _utc_now().isoformat()
                db.execute(
                    "UPDATE provider_assignments SET live_status='inconclusive', qualification='pending', "
                    "distribution_enabled=0, last_error_code='worker_error', last_checked_at=?, "
                    "qualification_next_check_at=?, qualification_claimed_until=NULL, "
                    "qualification_claim_token=NULL, qualification_attempts=qualification_attempts+1, updated_at=? "
                    "WHERE id=? AND qualification_claim_token=?",
                    (now, (datetime.fromisoformat(now) + timedelta(minutes=5)).isoformat(), now, assignment_id, token),
                )
                db.commit()
                logger.exception("provider qualification failed assignment=%s", assignment_id)
                return {"status": "error", "assignment_id": assignment_id}

    def run_once(self) -> dict[str, Any]:
        if self.stopped:
            return {"status": "stopped", "checked": 0}
        with self.app.app_context():
            db = get_db()
            if is_proxiware_automation_paused(db):
                record_worker_heartbeat(db, "qualification_worker", "paused")
                return {"status": "paused", "checked": 0}
            record_worker_heartbeat(db, "qualification_worker", "starting")
            concurrency, interval = self._settings(db)
            claims = self._claim(db, limit=concurrency, claim_seconds=self.claim_seconds, now=_utc_now())
        if not claims:
            with self.app.app_context():
                record_worker_heartbeat(get_db(), "qualification_worker", "idle")
            return {"status": "idle", "checked": 0}
        checked = 0
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="proxiware-qual") as pool:
            futures = [
                pool.submit(self._process_one, assignment_id, token, interval) for assignment_id, token in claims
            ]
            for future in as_completed(futures):
                if self.stopped:
                    for pending in futures:
                        pending.cancel()
                    break
                outcome = future.result()
                checked += int(outcome.get("status") == "checked")
        with self.app.app_context():
            record_worker_heartbeat(get_db(), "qualification_worker", "ok", last_success=True)
        return {"status": "ok", "checked": checked, "claimed": len(claims), "concurrency": concurrency}

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
    parser = argparse.ArgumentParser(description="Qualify Proxiware provider assignments")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS)
    args = parser.parse_args()
    runner = ProxiwareQualificationRunner(interval_seconds=args.interval_seconds)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_once()
    else:
        runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
