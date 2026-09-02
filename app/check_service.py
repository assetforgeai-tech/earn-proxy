from __future__ import annotations

import argparse
import asyncio
import inspect
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from app import create_app
from app.checker import check_proxy_fast, check_proxy_strong
from app.db import get_db
from app.earnapp_probe import probe_earnapp_proxy
from app.proxy_intelligence import lookup_country_cached
from app.services.checks import (
    MAX_HEALTH_CONCURRENCY,
    apply_earnapp_result,
    apply_health_result,
    batch_spacing_seconds,
    checker_settings,
    claim_due_earnapp,
    claim_due_proxies,
    release_earnapp_claims,
    release_health_claims,
)
from app.services.proxies import reveal_proxy

PROBE_CIRCUIT_FAILURE_THRESHOLD = 3
PROBE_CIRCUIT_COOLDOWN_SECONDS = 300


def _call_compatible_checker(checker, proxy, *, timeout: float | None = None, runner=None, unavailable_endpoints=None):
    """Keep the checker injection seam compatible with one-argument test/hooks."""
    kwargs = {}
    try:
        parameters = inspect.signature(checker).parameters
        accepts_var_kwargs = any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values())
    except (TypeError, ValueError):
        parameters = {}
        accepts_var_kwargs = True
    for name, value in (
        ("timeout", timeout),
        ("runner", runner),
        ("unavailable_endpoints", unavailable_endpoints),
    ):
        if value is not None and (accepts_var_kwargs or name in parameters):
            kwargs[name] = value
    return checker(proxy, **kwargs)


def check_proxy(proxy, timeout: float = 10, runner=None, *, unavailable_endpoints=None):
    """Compatibility hook that follows the current strong checker at call time."""
    return _call_compatible_checker(
        check_proxy_strong,
        proxy,
        timeout=timeout,
        runner=runner,
        unavailable_endpoints=unavailable_endpoints,
    )


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
    def __init__(self, *, app=None, state: SchedulerState | None = None, worker: str = "health"):
        self.app = app
        self.state = state or SchedulerState()
        if worker not in {"health", "earnapp"}:
            raise ValueError("worker must be health or earnapp")
        self.worker = worker
        self._stop = threading.Event()
        self._health_executor = ThreadPoolExecutor(
            max_workers=MAX_HEALTH_CONCURRENCY,
            thread_name_prefix="proxy-health",
        )
        self._provider_lock = threading.Lock()
        self._provider_slots: dict[str, tuple[int, threading.BoundedSemaphore]] = {}
        self._probe_circuit_lock = threading.Lock()
        self._probe_endpoint_state: dict[str, tuple[int, float]] = {}
        self.per_host_concurrency = 2
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
        self.per_host_concurrency = settings.health_per_host_concurrency

    @property
    def health_executor(self) -> ThreadPoolExecutor:
        return self._health_executor

    @contextmanager
    def provider_slot(self, host: str):
        key = str(host or "").strip().lower()
        limit = max(1, min(3, int(self.per_host_concurrency)))
        with self._provider_lock:
            current = self._provider_slots.get(key)
            if current is None or current[0] != limit:
                current = (limit, threading.BoundedSemaphore(limit))
                self._provider_slots[key] = current
            semaphore = current[1]
        semaphore.acquire()
        try:
            yield
        finally:
            semaphore.release()

    def close(self) -> None:
        self._health_executor.shutdown(wait=True, cancel_futures=True)

    def unavailable_probe_endpoints(self, *, now: float | None = None) -> set[str]:
        current = time.monotonic() if now is None else float(now)
        with self._probe_circuit_lock:
            expired = [
                endpoint
                for endpoint, (_failures, open_until) in self._probe_endpoint_state.items()
                if open_until and open_until <= current
            ]
            for endpoint in expired:
                self._probe_endpoint_state.pop(endpoint, None)
            return {
                endpoint
                for endpoint, (_failures, open_until) in self._probe_endpoint_state.items()
                if open_until > current
            }

    def record_fast_probe_result(self, result: dict, *, now: float | None = None) -> None:
        current = time.monotonic() if now is None else float(now)
        failed_endpoint = str(result.get("failed_probe_endpoint") or "").strip()
        successful_endpoint = str(result.get("probe_endpoint") or "").strip()
        with self._probe_circuit_lock:
            if result.get("failure_kind") == "probe_endpoint" and failed_endpoint:
                failures, _open_until = self._probe_endpoint_state.get(failed_endpoint, (0, 0.0))
                failures += 1
                open_until = (
                    current + PROBE_CIRCUIT_COOLDOWN_SECONDS if failures >= PROBE_CIRCUIT_FAILURE_THRESHOLD else 0.0
                )
                self._probe_endpoint_state[failed_endpoint] = (failures, open_until)
            elif result.get("status") in {"live", "live_unverified"} and successful_endpoint:
                self._probe_endpoint_state.pop(successful_endpoint, None)

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
            SELECT 1 FROM proxies AS p
            JOIN users AS u ON u.id = p.user_id
            WHERE p.archived_at IS NULL AND u.status='active'
              AND ((p.next_check_at IS NULL OR p.next_check_at <= ?)
                OR (p.check_claimed_until IS NOT NULL AND p.check_claimed_until <= ?))
              AND (p.check_claimed_until IS NULL OR p.check_claimed_until <= ?)
            LIMIT 1
            """,
                (now.isoformat(), now.isoformat(), now.isoformat()),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _next_health_wake_seconds(db, now: datetime) -> float | None:
        """Return the earliest durable health timestamp worth waking for."""
        row = db.execute(
            """
            SELECT MIN(wake_at) AS wake_at FROM (
                SELECT next_check_at AS wake_at
                FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND u.status='active' AND p.next_check_at IS NOT NULL
                UNION ALL
                SELECT p.check_claimed_until AS wake_at
                FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND u.status='active' AND p.check_claimed_until IS NOT NULL
            )
            """
        ).fetchone()
        value = row["wake_at"] if row else None
        if not value:
            return None
        wake_at = datetime.fromisoformat(value)
        if wake_at.tzinfo is None:
            wake_at = wake_at.replace(tzinfo=UTC)
        return max(1.0, (wake_at - now).total_seconds())

    @staticmethod
    def _earnapp_queue_due(db, now: datetime) -> bool:
        return (
            db.execute(
                """
                SELECT 1 FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND p.status='online' AND u.status='active'
                  AND (p.earnapp_next_check_at IS NULL OR p.earnapp_next_check_at <= ?)
                  AND (p.earnapp_claimed_until IS NULL OR p.earnapp_claimed_until <= ?)
                LIMIT 1
                """,
                (now.isoformat(), now.isoformat()),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _next_earnapp_wake_seconds(db, now: datetime) -> float | None:
        row = db.execute(
            """
            SELECT MIN(wake_at) AS wake_at FROM (
                SELECT earnapp_next_check_at AS wake_at
                FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND p.status='online' AND u.status='active' AND p.earnapp_next_check_at IS NOT NULL
                UNION ALL
                SELECT p.earnapp_claimed_until AS wake_at
                FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND p.status='online' AND u.status='active' AND p.earnapp_claimed_until IS NOT NULL
            )
            """
        ).fetchone()
        value = row["wake_at"] if row else None
        if not value:
            return None
        wake_at = datetime.fromisoformat(value)
        if wake_at.tzinfo is None:
            wake_at = wake_at.replace(tzinfo=UTC)
        return max(1.0, (wake_at - now).total_seconds())

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
        health_at = self.state.last_health_sweep_at or self.state.last_sweep_at
        if health_at is None:
            return 0
        due = health_at + timedelta(seconds=self.interval_seconds)
        return max(0, int((due - current).total_seconds()))

    def _check_one(self, row, parsed=None) -> tuple[int, dict]:
        if parsed is None and self.app is not None:
            # Flask contexts are thread-local and are not inherited by the
            # executor; credential decryption reads the app encryption key.
            with self.app.app_context():
                parsed = reveal_proxy(row)
        else:
            parsed = parsed or reveal_proxy(row)
        detected = str(row["detected_protocol"] or "unknown")
        protocol = detected if detected in {"http", "socks5"} else parsed.protocol
        proxy = {
            "host": parsed.host,
            "port": parsed.port,
            "username": parsed.username,
            "password": parsed.password,
            "protocol": protocol,
        }
        with self.provider_slot(parsed.host):
            if str(row["health_mode"] or "strong") == "fast" and detected in {"http", "socks5"}:
                result = check_proxy_fast(
                    proxy,
                    probe_index=int(row["next_probe_index"] or 0),
                    expected_exit_ip=str(row["exit_ip"] or ""),
                    unavailable_endpoints=self.unavailable_probe_endpoints(),
                )
                self.record_fast_probe_result(result)
                if result.get("status") in {"needs_confirmation", "inconclusive"} and result.get(
                    "failure_kind"
                ) not in {"probe_endpoint", "provider_blocked"}:
                    result = _call_compatible_checker(
                        check_proxy,
                        proxy,
                        unavailable_endpoints=self.unavailable_probe_endpoints(),
                    )
            else:
                result = _call_compatible_checker(
                    check_proxy,
                    proxy,
                    unavailable_endpoints=self.unavailable_probe_endpoints(),
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
            rows = claim_due_proxies(
                db,
                limit=settings.health_concurrency,
                per_host_limit=settings.health_per_host_concurrency,
            )
            if not rows:
                # An empty queue is only a completed sweep for a due window;
                # manual invocations during the cooldown must not postpone it.
                if self.health_due:
                    self.mark_health_sweep(datetime.now(UTC))
                return 0
            completed = 0
            # Resolve encrypted credentials inside the worker so one corrupt row
            # is handled by the same per-future isolation as a probe failure.
            futures = [self._health_executor.submit(self._check_one, row, None) for row in rows]
            future_context = {
                future: (
                    int(row["id"]),
                    int(row["credential_generation"] or 1),
                    str(row["check_claim_token"] or ""),
                )
                for future, row in zip(futures, rows, strict=True)
            }
            processed_futures = set()
            for future in as_completed(futures):
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
                        "failure_kind": "worker",
                        "_credential_generation": generation,
                        "_check_claim_token": claim_token,
                    }
                apply_health_result(db, proxy_id, result)
                processed_futures.add(future)
                completed += 1
                if self.stopped:
                    break
            if len(processed_futures) != len(futures):
                pending_claims = []
                for future in futures:
                    if future in processed_futures:
                        continue
                    _proxy_id, _generation, claim_token = future_context[future]
                    if future.cancel():
                        pending_claims.append((_proxy_id, claim_token))
                release_health_claims(db, pending_claims)
            # A sweep is complete only after the durable queue has no due rows;
            # this prevents a 30k inventory from being marked complete after one batch.
            now = datetime.now(UTC)
            due = db.execute(
                """
                SELECT COUNT(*) AS count FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND u.status='active'
                  AND ((p.next_check_at IS NULL OR p.next_check_at <= ?)
                    OR (p.check_claimed_until IS NOT NULL AND p.check_claimed_until <= ?))
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
                try:
                    parsed = reveal_proxy(row)
                    protocol = str(row["detected_protocol"] or parsed.protocol)
                    if protocol not in {"http", "socks5"}:
                        result = {
                            "verdict": "UNKNOWN",
                            "reason": "protocol not detected",
                        }
                    else:
                        result = asyncio.run(
                            probe_earnapp_proxy(
                                parsed.host,
                                parsed.port,
                                protocol=protocol,
                                username=parsed.username,
                                password=parsed.password,
                            )
                        )
                        exit_ip = str(result.get("exit_ip") or "").strip()
                        if exit_ip:
                            result.update(lookup_country_cached(db, exit_ip))
                except Exception as exc:  # noqa: BLE001 - external WSS failures become durable evidence
                    result = {
                        "verdict": "WSS_FAIL",
                        "reason": f"checker worker failed: {exc}",
                    }
                result["_credential_generation"] = int(row["credential_generation"] or 1)
                result["_earnapp_claim_token"] = str(row["earnapp_claim_token"] or "")
                apply_earnapp_result(db, int(row["id"]), result)
                completed += 1
            if completed != len(rows):
                release_earnapp_claims(
                    db,
                    [(int(row["id"]), str(row["earnapp_claim_token"] or "")) for row in rows[completed:]],
                )
            now = datetime.now(UTC)
            due = db.execute(
                """
                SELECT COUNT(*) AS count FROM proxies AS p
                JOIN users AS u ON u.id = p.user_id
                WHERE p.archived_at IS NULL AND p.status='online' AND u.status='active'
                  AND (p.earnapp_next_check_at IS NULL OR p.earnapp_next_check_at <= ?)
                """,
                (now.isoformat(),),
            ).fetchone()["count"]
            if int(due) == 0:
                self.mark_earnapp_sweep(now)
            return completed

    def run_forever(self) -> None:
        if self.worker == "earnapp":
            self.run_earnapp_forever()
            return
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
            if completed and self.app is not None:
                with self.app.app_context():
                    db = get_db()
                    now = datetime.now(UTC)
                    due_count = db.execute(
                        "SELECT COUNT(*) AS count FROM proxies AS p JOIN users AS u ON u.id=p.user_id WHERE p.archived_at IS NULL AND u.status='active' AND p.next_check_at <= ?",
                        (now.isoformat(),),
                    ).fetchone()["count"]
                    if int(due_count):
                        wait_seconds = batch_spacing_seconds(db, due_count=int(due_count))
                    else:
                        next_due = db.execute(
                            "SELECT MIN(p.next_check_at) AS next_due FROM proxies AS p JOIN users AS u ON u.id=p.user_id WHERE p.archived_at IS NULL AND u.status='active'",
                        ).fetchone()["next_due"]
                        if next_due:
                            due_at = datetime.fromisoformat(next_due)
                            if due_at.tzinfo is None:
                                due_at = due_at.replace(tzinfo=UTC)
                            wait_seconds = max(1, (due_at - now).total_seconds())
                        else:
                            wait_seconds = self.interval_seconds
            else:
                # Sleep until the next durable window rather than polling every
                # few seconds.  Event.wait remains interruptible on shutdown.
                now = datetime.now(UTC)
                health_wait = self.next_wait_seconds(now=now) if not self.health_due else 0
                durable_wait = None
                if self.app is not None:
                    with self.app.app_context():
                        durable_wait = self._next_health_wake_seconds(get_db(), now)
                waits = [value for value in (health_wait, durable_wait) if value and value > 0]
                wait_seconds = min(waits) if waits else 1
            self._stop.wait(wait_seconds)

    def run_earnapp_forever(self) -> None:
        while not self.stopped:
            now = datetime.now(UTC)
            if self.app is not None:
                with self.app.app_context():
                    db = get_db()
                    self.refresh_settings(db)
                    if self._earnapp_queue_due(db, now):
                        self._earnapp_due = True
            self._refresh_due_flags(now)
            completed = self.run_earnapp_batch() if self.earnapp_due else 0
            if completed:
                wait_seconds = 1
            else:
                now = datetime.now(UTC)
                earn_at = self.state.last_earnapp_sweep_at
                window_wait = None
                if not self.earnapp_due and earn_at is not None:
                    window_wait = max(
                        1.0, (earn_at + timedelta(seconds=self.earnapp_interval_seconds) - now).total_seconds()
                    )
                durable_wait = None
                if self.app is not None:
                    with self.app.app_context():
                        durable_wait = self._next_earnapp_wake_seconds(get_db(), now)
                waits = [value for value in (window_wait, durable_wait) if value and value > 0]
                wait_seconds = min(waits) if waits else 1
            self._stop.wait(wait_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded Earn Proxy health checks")
    parser.add_argument("--once", action="store_true", help="Run one due batch and exit")
    parser.add_argument("--worker", choices=("health", "earnapp"), default="health")
    args = parser.parse_args()
    application = create_app()
    runner = CheckRunner(app=application, worker=args.worker)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        try:
            runner.run_batch() if args.worker == "health" else runner.run_earnapp_batch()
            return 0
        finally:
            runner.close()
    try:
        runner.run_forever()
        return 0
    finally:
        runner.close()


if __name__ == "__main__":
    raise SystemExit(main())
