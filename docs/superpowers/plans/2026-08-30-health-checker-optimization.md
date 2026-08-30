# Health Checker Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the heavyweight uniform proxy sweep with a low-cost, state-aware health pipeline that can service a 30,000-proxy inventory accurately while isolating earnings and EarnApp maintenance work.

**Architecture:** New or changed credentials receive a strong protocol/egress qualification check. Stable proxies receive one-endpoint fast checks through the previously detected protocol, with strong confirmation only after a failure or changed egress. Durable SQLite state drives short retry windows, stale-success exclusion, fair provider-host limits, and independent health, EarnApp, and maintenance workers.

**Tech Stack:** Python 3.11, Flask, SQLite WAL, subprocess-backed curl probes, bounded thread pools, systemd/Docker Compose, pytest, Playwright.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`.
- Keep the service self-contained; do not add Redis, PostgreSQL, RabbitMQ, or a separate probe server.
- Preserve raw proxy API output and the existing `Allow`/`Risk` admin toggles.
- Never mark a proxy offline from a single transient third-party probe failure.
- Keep checks safe for the upstream provider by limiting concurrent checks sharing a provider host.
- Preserve encrypted credentials and global duplicate-egress behavior.
- Add migrations that upgrade existing SQLite databases without data loss.

---

### Task 1: Durable health state and policy

**Files:**
- Modify: `app/db.py`
- Modify: `app/services/checks.py`
- Modify: `app/routes/admin.py`
- Test: `tests/test_check_service.py`
- Test: `tests/test_admin_ui.py`
- Test: `tests/test_migrations.py`

**Interfaces:**
- Produces proxy fields `last_success_at`, `health_mode`, `next_probe_index`, `last_probe_endpoint`, `last_latency_ms`, and `failure_kind`.
- Produces settings for normal interval, retry intervals, stale-success threshold, health concurrency, and per-host concurrency.

- [ ] Write failing migration and settings tests for the new columns and bounded defaults.
- [ ] Run focused tests and confirm failures are caused by missing schema/settings.
- [ ] Add idempotent SQLite migrations, indexes, checker settings, and Admin form persistence.
- [ ] Run focused tests until green.

### Task 2: Fast and strong probe modes

**Files:**
- Modify: `app/checker.py`
- Test: `tests/test_checker.py`

**Interfaces:**
- Produces `check_proxy_fast(proxy, probe_index, timeout, runner) -> dict`.
- Produces `check_proxy_strong(proxy, timeout, runner) -> dict` while retaining `check_proxy` as a compatibility alias.
- Result dictionaries include `status`, `protocol`, `exit_ip`, `latency_ms`, `error`, `failure_kind`, `probe_endpoint`, and `next_probe_index`.

- [ ] Write failing tests proving a stable proxy uses one endpoint and one detected protocol.
- [ ] Write failing tests proving a changed egress or failed fast probe requests strong confirmation.
- [ ] Write failing circuit-breaker classification tests separating endpoint failure from proxy failure.
- [ ] Implement endpoint rotation, fast probe parsing, strong fallback, and explicit failure kinds.
- [ ] Run checker tests until green.

### Task 3: State-aware retry and stale-success rules

**Files:**
- Modify: `app/services/checks.py`
- Modify: `app/routes/internal_api.py`
- Test: `tests/test_check_service.py`
- Test: `tests/test_internal_api.py`

**Interfaces:**
- A first confirmed failure schedules a 5-minute retry and keeps the prior state.
- A second confirmed failure schedules a 15-minute retry and marks `suspect`.
- A third independent confirmed failure marks `offline`.
- `inconclusive` results do not increment failure streaks but cannot leave an endpoint distributable past the stale-success threshold.

- [ ] Write failing tests for retry timing, suspect transition, recovery, and stale API exclusion.
- [ ] Run focused tests and verify the intended failures.
- [ ] Implement result application and API freshness filtering.
- [ ] Run focused tests until green.

### Task 4: Efficient scheduler and provider-aware concurrency

**Files:**
- Modify: `app/check_service.py`
- Modify: `app/services/checks.py`
- Test: `tests/test_check_runner.py`
- Test: `tests/test_scheduler.py`

**Interfaces:**
- Health runner selects fast or strong mode from row state.
- Health concurrency is configurable from 5 to 20; per-host concurrency is capped from 1 to 3.
- One long-lived executor is reused for health batches.
- Database result writes are serialized without rescanning the entire earnings inventory after every five proxies.

- [ ] Write failing tests for mode selection, executor reuse, host caps, and absence of per-batch maintenance scans.
- [ ] Run focused tests and verify failure reasons.
- [ ] Implement the runner changes and fair host-aware batch execution.
- [ ] Run scheduler tests until green.

### Task 5: Independent EarnApp and maintenance workers

**Files:**
- Create: `app/maintenance_service.py`
- Modify: `app/check_service.py`
- Modify: `docker-compose.yml`
- Modify: `deploy/earn-proxy-checker.service`
- Create: `deploy/earn-proxy-earnapp.service`
- Create: `deploy/earn-proxy-maintenance.service`
- Modify: `pyproject.toml`
- Test: `tests/test_scheduler.py`
- Test: `tests/test_maintenance_service.py`

**Interfaces:**
- `python -m app.check_service --worker health` runs health only.
- `python -m app.check_service --worker earnapp` runs qualification only.
- `python -m app.maintenance_service` accrues earnings, archives dead proxies, and checkpoints WAL on a fixed schedule.

- [ ] Write failing tests proving health backlog cannot starve EarnApp or maintenance.
- [ ] Implement independent entry points and deployment units.
- [ ] Run worker tests until green.

### Task 6: Admin observability and responsive UX

**Files:**
- Modify: `app/services/checks.py`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/static/app.css`
- Modify: `scripts/smoke_ui.py`
- Test: `tests/test_admin_stats.py`
- Test: `tests/test_browser_forms.py`

**Interfaces:**
- Admin shows healthy, suspect, offline, stale, due, average latency, checks/minute, and sweep lag.
- Policy controls expose health concurrency, per-host cap, retry timing, and stale-success threshold with safe help text.

- [ ] Write failing UI contract tests for metrics, labels, bounds, and settings persistence.
- [ ] Implement the compact responsive operations panel without exposing internal proxy evidence to users.
- [ ] Run browser form tests and Playwright desktop/mobile smoke tests.

### Task 7: Documentation, performance verification, and release

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/test.yml`
- Test: all tests

**Interfaces:**
- Documents capacity math, freshness semantics, the three worker processes, deployment, and rollback.

- [ ] Add deterministic load-model tests for 30,000 proxies and bounded concurrency.
- [ ] Run the full pytest, Ruff, format, compile, dependency, secret, and diff checks.
- [ ] Verify Docker Compose configuration when Docker is available; otherwise report the exact limitation.
- [ ] Commit, push `main`, and wait for GitHub Actions to pass.
