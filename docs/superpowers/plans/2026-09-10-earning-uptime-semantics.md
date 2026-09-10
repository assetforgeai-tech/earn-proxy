# Earning Uptime Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stop displaying online hours for proxies that are not earning, and make displayed online/offline durations reflect only confirmed health intervals.

**Architecture:** Keep health counters in `proxies` as the source for operational uptime. Build the contributor view with an earning-aware projection: online duration is visible only for canonical, earning-eligible proxies; offline duration remains an operational health metric. Bound an active interval by the last successful health observation plus the configured stale window.

**Tech Stack:** Python 3.11, Flask, SQLite, pytest.

## Global Constraints

- Do not change the earnings ledger or payout calculations.
- Do not expose credentials or internal egress details.
- Preserve the fixed 30-day duration formatting.
- Use TDD: each behavior change gets a failing regression test first.

### Task 1: Define the uptime projection contract

**Files:**
- Modify: `tests/test_uptime.py`
- Modify: `app/services/uptime.py`
- Modify: `app/routes/dashboard.py`

**Interfaces:**
- `uptime_hours(row, now=..., earning_enabled=...)` returns `UptimeHours`.
- `dashboard._render_dashboard()` passes the earning projection into uptime calculation.

- [x] Add tests for pending, duplicate, awaiting-egress, and allow/risk canonical rows.
- [x] Run focused tests and confirm they fail for the current implementation.
- [x] Implement the smallest earning-aware projection and stale-window bound.
- [x] Run focused tests, then the full suite.

### Task 2: Verify health transitions and stale gaps

**Files:**
- Modify: `tests/test_uptime.py`
- Modify: `tests/test_check_service.py` only if a confirmed transition exposes a regression.

**Interfaces:**
- Existing `apply_health_result()` transition semantics remain unchanged unless a test proves overcounting.

- [x] Add regression coverage for online -> suspect -> offline -> online and stale recovery.
- [x] Run focused transition tests.
- [x] Change only the failing transition path if required.

### Task 3: Audit and release

**Files:**
- No additional application files unless verification finds a direct regression.

- [x] Run `pytest -q`.
- [x] Run `ruff check app tests` and `python -m compileall app`.
- [x] Review diff and confirm no CashPilot files changed.
- [x] Commit, push, deploy with `deploy/release.sh`, and smoke-test the production dashboard.
