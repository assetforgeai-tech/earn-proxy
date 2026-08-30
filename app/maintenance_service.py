from __future__ import annotations

import argparse
import signal
import threading
from datetime import UTC, datetime

from app import create_app
from app.db import get_db
from app.services.checks import archive_due_dead_proxies
from app.services.earnings import accrue_eligible_time


def checkpoint_wal(db) -> None:
    db.execute("PRAGMA wal_checkpoint(PASSIVE)")


class MaintenanceRunner:
    def __init__(self, *, app=None, interval_seconds: int = 1800):
        self.app = app
        self.interval_seconds = max(60, int(interval_seconds))
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run_cycle(self, *, now: datetime | None = None) -> dict[str, int]:
        if self.app is None:
            return {"archived": 0}
        current = now or datetime.now(UTC)
        with self.app.app_context():
            db = get_db()
            accrue_eligible_time(db, now=current)
            archived = archive_due_dead_proxies(db, now=current)
            checkpoint_wal(db)
        return {"archived": archived}

    def run_forever(self) -> None:
        while not self._stop.is_set():
            self.run_cycle()
            self._stop.wait(self.interval_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Earn Proxy earnings and archival maintenance")
    parser.add_argument("--once", action="store_true", help="Run one maintenance cycle and exit")
    parser.add_argument("--interval-seconds", type=int, default=1800)
    args = parser.parse_args()
    runner = MaintenanceRunner(app=create_app(), interval_seconds=args.interval_seconds)
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    signal.signal(signal.SIGINT, lambda *_: runner.stop())
    if args.once:
        runner.run_cycle()
        return 0
    runner.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
