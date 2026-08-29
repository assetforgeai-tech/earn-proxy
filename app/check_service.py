from __future__ import annotations

import argparse
import asyncio
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from app import create_app
from app.checker import check_proxy
from app.db import get_db
from app.earnapp_probe import probe_earnapp_proxy
from app.services.checks import (
    MAX_HEALTH_CONCURRENCY,
    apply_earnapp_result,
    apply_health_result,
    archive_due_dead_proxies,
    batch_spacing_seconds,
    checker_settings,
    claim_due_earnapp,
    claim_due_proxies,
)
from app.services.earnings import accrue_eligible_time
from app.services.proxies import reveal_proxy


@dataclass(frozen=True)
class SchedulerState:
    interval_minutes: int = 60
    concurrency: int = 5
    last_sweep_at: datetime | None = None
    # Health and qualification sweeps have independent clocks.  Keep the
    # legacy ``last_sweep_at`` field for callers that persisted the old state.
    last_health_sweep_at: datetime | None = None
    last_earnapp_sweep_at: datetime | None = None
    earnapp_interval_hours: int = 168


class CheckRunner:
    def __init__(self, *, app=None, state: SchedulerState | None = None):
        self.app = app
        self.state = state or SchedulerState()
        self._stop = threading.Event()
        self._health_due = self.state.last_health_sweep_at is None and self.state.last_sweep_at is None
        self._earnapp_due = self.state.last_earnapp_sweep_at is None

    @property
    def concurrency(self) -> int:
        return max(1, min(MAX_HEALTH_CONCURRENCY, int(self.state.concurrency)))

    @property
    def interval_seconds(self) -> int:
        return max(15, min(1440, int(self.state.interval_minutes))) * 60

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    @property
    def health_due(self) -> bool:
        """Whether the current rolling health sweep still has work to do."""
        return self._health_due

    @property
    def earnapp_due(self) -> bool:
        """Whether the slow EarnApp qualification sweep is due."""
        return self._earnapp_due

    @property
    def earnapp_interval_seconds(self) -> int:
        return max(24, min(720, int(self.state.earnapp_interval_hours))) * 3600

    def refresh_settings(self, db) -> None:
        """Refresh live admin settings without resetting scheduler clocks."""
        settings = checker_settings(db)
        self.state = replace(
            self.state,
            interval_minutes=settings.health_interval_minutes,
            concurrency=settings.health_concurrency,
            earnapp_interval_hours=settings.earnapp_refresh_hours,
        )

    def _refresh_due_flags(self, now: datetime) -> None:
        health_at = self.state.last_health_sweep_at or self.state.last_sweep_at
        if (
            not self._health_due
            and health_at is not None
            and now >= health_at + timedelta(seconds=self.interval_seconds)
        ):
            self._health_due = True
        if (
            not self._earnapp_due
            and self.state.last_earnapp_sweep_at is not None
            and now >= self.state.last_earnapp_sweep_at + timedelta(seconds=self.earnapp_interval_seconds)
        ):
            self._earnapp_due = True

    @staticmethod
    def _health_queue_due(db, now: datetime) -> bool:
        return (
            db.execute(
                """
            SELECT 1 FROM proxies
            WHERE archived_at IS NULL
              AND ((next_check_at IS NULL OR next_check_at <= ?)
                OR (check_claimed_until IS NOT NULL AND check_claimed_until <= ?))
              AND (check_claimed_until IS NULL OR check_claimed_until <= ?)
            LIMIT 1
            """,
                (now.isoformat(), now.isoformat(), now.isoformat()),
            ).fetchone()
            is not None
        )

    def mark_health_sweep(self, at: datetime | None = None) -> None:
        """Close a completed health sweep and start its 60-minute window."""
        timestamp = at or datetime.now(UTC)
        self.state = replace(
            self.state,
            last_sweep_at=timestamp,
            last_health_sweep_at=timestamp,
        )
        self._health_due = False

    def mark_earnapp_sweep(self, at: datetime | None = None) -> None:
        """Close a completed slow qualification sweep."""
        timestamp = at or datetime.now(UTC)
        self.state = replace(self.state, last_earnapp_sweep_at=timestamp)
        self._earnapp_due = False

    def stop(self) -> None:
        self._stop.set()

    def next_wait_seconds(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        self._refresh_due_flags(current)
        if self.state.last_sweep_at is None:
            return 0
        due = self.state.last_sweep_at + timedelta(seconds=self.interval_seconds)
        return max(0, int((due - current).total_seconds()))

    def _check_one(self, row, parsed=None) -> tuple[int, dict]:
        parsed = parsed or reveal_proxy(row)
        result = check_proxy(
            {
                "host": parsed.host,
                "port": parsed.port,
                "username": parsed.username,
                "password": parsed.password,
                "protocol": parsed.protocol,
            }
        )
        result["_credential_generation"] = int(row["credential_generation"] or 1)
        result["_check_claim_token"] = str(row["check_claim_token"] or "")
        return int(row["id"]), result

    def run_batch(self) -> int:
        if self.app is None:
            return 0
        with self.app.app_context():
            db = get_db()
            self.refresh_settings(db)
            settings = checker_settings(db)
            rows = claim_due_proxies(db, limit=settings.health_concurrency)
            if not rows:
                accrue_eligible_time(db)
                archive_due_dead_proxies(db)
                # An empty queue is only a completed sweep for a due window;
                # manual invocations during the cooldown must not postpone it.
                if self.health_due:
                    self.mark_health_sweep(datetime.now(UTC))
                return 0
            completed = 0
            work = [(row, reveal_proxy(row)) for row in rows]
            with ThreadPoolExecutor(
                max_workers=settings.health_concurrency,
                thread_name_prefix="proxy-health",
            ) as pool:
                futures = [pool.submit(self._check_one, row, parsed) for row, parsed in work]
                future_context = {
                    future: (
                        int(row["id"]),
                        int(row["credential_generation"] or 1),
                        str(row["check_claim_token"] or ""),
                    )
                    for future, (row, _parsed) in zip(futures, work, strict=True)
                }
                for future in as_completed(futures):
                    if self.stopped:
                        break
                    try:
                        proxy_id, result = future.result()
                        _proxy_id, generation, claim_token = future_context[future]
                        proxy_id = _proxy_id
                        result = dict(result)
                        result.setdefault("_credential_generation", generation)
                        result.setdefault("_check_claim_token", claim_token)
                    except Exception as exc:  # noqa: BLE001 - isolate each third-party probe worker
                        # A single malformed credential or network worker must not kill the sweep.
                        proxy_id, generation, claim_token = future_context[future]
                        result = {
                            "status": "inconclusive",
                            "error": f"checker worker failed: {exc}",
                            "_credential_generation": generation,
                            "_check_claim_token": claim_token,
                        }
                    apply_health_result(db, proxy_id, result)
                    completed += 1
            accrue_eligible_time(db)
            archive_due_dead_proxies(db)
            # A sweep is complete only after the durable queue has no due rows;
            # this prevents a 30k inventory from being marked complete after one batch.
            now = datetime.now(UTC)
            due = db.execute(
                """
                SELECT COUNT(*) AS count FROM proxies
                WHERE archived_at IS NULL
                  AND ((next_check_at IS NULL OR next_check_at <= ?)
                    OR (check_claimed_until IS NOT NULL AND check_claimed_until <= ?))
                """,
                (now.isoformat(), now.isoformat()),
            ).fetchone()["count"]
            if int(due) == 0:
                self.mark_health_sweep(now)
            return completed

    def run_earnapp_batch(self) -> int:
        if self.app is None:
            return 0
        with self.app.app_context():
            db = get_db()
            self.refresh_settings(db)
            settings = checker_settings(db)
            rows = claim_due_earnapp(db, limit=min(settings.health_concurrency, 2))
            completed = 0
            if not rows:
                self.mark_earnapp_sweep(datetime.now(UTC))
                return 0
            for row in rows:
                if self.stopped:
                    break
                parsed = reveal_proxy(row)
                protocol = str(row["detected_protocol"] or parsed.protocol)
                if protocol not in {"http", "socks5"}:
                    # An auto/unknown endpoint must not retain its claim and
                    # immediately re-enter the due queue on every loop.
                    apply_earnapp_result(
                        db,
                        int(row["id"]),
                        {
                            "verdict": "UNKNOWN",
                            "reason": "protocol not detected",
                            "_credential_generation": int(row["credential_generation"] or 1),
                            "_earnapp_claim_token": str(row["earnapp_claim_token"] or ""),
                        },
                    )
                    completed += 1
                    continue
                try:
                    result = asyncio.run(
                        probe_earnapp_proxy(
                            parsed.host,
                            parsed.port,
                            protocol=protocol,
                            username=parsed.username,
                            password=parsed.password,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - external WSS failures become durable evidence
                    result = {
                        "verdict": "WSS_FAIL",
                        "reason": f"checker worker failed: {exc}",
                    }
                result["_credential_generation"] = int(row["credential_generation"] or 1)
                result["_earnapp_claim_token"] = str(row["earnapp_claim_token"] or "")
                apply_earnapp_result(db, int(row["id"]), result)
                completed += 1
            now = datetime.now(UTC)
            due = db.execute(
                """
                SELECT COUNT(*) AS count FROM proxies
                WHERE archived_at IS NULL AND status='online'
                  AND (earnapp_next_check_at IS NULL OR earnapp_next_check_at <= ?)
                """,
                (now.isoformat(),),
            ).fetchone()["count"]
            if int(due) == 0:
                self.mark_earnapp_sweep(now)
            return completed

    def run_forever(self) -> None:
        while not self.stopped:
            now = datetime.now(UTC)
            queue_due = False
            if self.app is not None:
                with self.app.app_context():
                    db = get_db()
                    self.refresh_settings(db)
                    queue_due = self._health_queue_due(db, now)
            self._refresh_due_flags(now)
            if queue_due:
                self._health_due = True
            completed = self.run_batch() if self.health_due else 0
            qualification_completed = 0
            if not completed and self.earnapp_due:
                qualification_completed = self.run_earnapp_batch()
            if completed and self.app is not None:
                with self.app.app_context():
                    db = get_db()
                    now = datetime.now(UTC)
                    due_count = db.execute(
                        "SELECT COUNT(*) AS count FROM proxies WHERE archived_at IS NULL AND next_check_at <= ?",
                        (now.isoformat(),),
                    ).fetchone()["count"]
                    if int(due_count):
                        wait_seconds = batch_spacing_seconds(db, due_count=int(due_count))
                    else:
                        next_due = db.execute(
                            "SELECT MIN(next_check_at) AS next_due FROM proxies WHERE archived_at IS NULL",
                        ).fetchone()["next_due"]
                        if next_due:
                            due_at = datetime.fromisoformat(next_due)
                            if due_at.tzinfo is None:
                                due_at = due_at.replace(tzinfo=UTC)
                            wait_seconds = max(1, (due_at - now).total_seconds())
                        else:
                            wait_seconds = self.interval_seconds
            elif qualification_completed:
                # Qualification is deliberately serialized and infrequent; a
                # short yield avoids hammering the database while it drains.
                wait_seconds = 1
            else:
                # Sleep until the next durable window rather than polling every
                # few seconds.  Event.wait remains interruptible on shutdown.
                now = datetime.now(UTC)
                health_wait = self.next_wait_seconds(now=now) if not self.health_due else 0
                earn_at = self.state.last_earnapp_sweep_at
                earn_wait = 0
                if not self.earnapp_due and earn_at is not None:
                    earn_wait = max(
                        0,
                        int((earn_at + timedelta(seconds=self.earnapp_interval_seconds) - now).total_seconds()),
                    )
                waits = [value for value in (health_wait, earn_wait) if value > 0]
                wait_seconds = min(waits) if waits else 1
            self._stop.wait(wait_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded Earn Proxy health checks")
    parser.add_argument("--once", action="store_true", help="Run one due batch and exit")
    args = parser.parse_args()
    application = create_app()
    runner = CheckRunner(app=application)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_batch()
        return 0
    runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
