# Proxiware Provider Control Center Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated, secure, operationally complete `Providers -> Proxiware` control center for inventory sync, qualification, session health, guarded swap jobs, and audit without exposing provider internals to users.

**Architecture:** Keep Proxiware data and workers behind provider-specific services and admin-only routes. Reuse the canonical proxy checker and global egress-duplicate reconciliation; use durable DB state for sync, qualification, and swap claims. Official API calls remain read-only except for the explicitly approved swap adapter; browser/session automation is injected, fail-closed, and disabled by default.

**Tech Stack:** Python 3.11, Flask, SQLite, requests, existing encryption helpers, pytest, existing TailAdmin templates, Docker/systemd.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never modify `D:\1. WORK_true\CashPilot`.
- Continue from branch `feat/proxiware-sync-swap`; preserve dirty changes; never reset or overwrite unrelated work.
- Never commit API keys, passwords, cookies, CAPTCHA tokens, CDP state, fingerprints, or raw provider responses.
- Use the official Proxiware API for supported read operations; do not automate purchase, billing, renewal, or subscription creation.
- Auto-swap is OFF by default. `Allow`, `Dead`, `Pending`, `inconclusive`, `unknown`, duplicate-egress, and unclear states never auto-swap.
- Swap requires live + `Risk` + provider eligible `<1000` + connections `<1000` + quota + cooldown + no duplicate job; wait at least 60 seconds after success before probing the replacement.
- Provider inventory never creates user earnings, uptime, quota, or user-facing provider terminology.
- All admin mutations require authorization, CSRF, confirmation, audit, rate limiting, and redacted errors.

## Provider menu contract

Add one first-class sidebar group, separate from Distribution API and user proxy management:

| Area | Route | Required function |
| --- | --- | --- |
| Overview | `/admin/providers/proxiware` | health, counts, worker state, last success/error |
| Inventory | `/admin/providers/proxiware/inventory` | search, filters, sort, pagination, bulk selection |
| Qualification | `/admin/providers/proxiware/qualification` | live/protocol/egress/country/quality state |
| Sync | `/admin/providers/proxiware/sync` | sync now, progress, cancel, history |
| Swap queue | `/admin/providers/proxiware/swaps` | actionable pending/cooldown/running/failed/manual-action jobs |
| Swap history | `/admin/providers/proxiware/swaps/history` | immutable old/new mapping, reason, attempts, timestamps, result |
| Session | `/admin/providers/proxiware/session` | connection test, expiry, renew, blocked state |
| Credentials | `/admin/providers/proxiware/credentials` | write-only API/login/2Captcha secrets; clear individually |
| Policy | `/admin/providers/proxiware/policy` | auto-swap toggle, thresholds, concurrency, retry, cooldown |
| Audit | `/admin/providers/proxiware/audit` | redacted actor/action/result timeline |

Every item uses a canonical URL and server-rendered active state; no hash-only navigation and no redirecting every page back to `/admin`. Every list uses server-side count/filter/sort/pagination and preserves query state. GET is side-effect free. Dangerous actions name the target and consequence. Desktop/mobile layouts must remain keyboard accessible and usable without JavaScript for basic navigation/forms.

The overview shows four compact groups: provider/API health, inventory/qualification counts, worker/queue health, and session/manual-action status. Credentials display only `configured`, `missing`, or `expired`; saved values are never returned to HTML or JSON. Queue actions appear only for compatible states. Provider inventory and internal reason codes never appear in contributor pages; distribution remains a separate, default-OFF policy.

The provider workspace is operationally separate from user proxy management. Its sidebar badge and overview alerts must expose stale sync, stopped worker, expired session, blocked queue, and manual-action-required states without exposing credentials. Every mutation, worker claim, audit record, and object lookup is scoped to `provider='proxiware'`, preventing cross-provider IDOR or accidental state changes when more providers are added later.

### Task 1: Reconcile current implementation and schema

**Files:**
- Inspect/modify: `app/db.py`, `app/services/proxiware.py`, `app/services/proxiware_qualification.py`, `app/services/proxiware_swap.py`, `app/routes/admin.py`
- Test: `tests/test_proxiware_bootstrap.py`, `tests/test_proxiware_sync.py`, `tests/test_proxiware_swap.py`

- [ ] Run focused tests and inspect all existing Proxiware tables, settings keys, claims, and route names.
- [ ] Make every app/worker bootstrap path create or migrate provider tables before first query; normalize settings to `proxiware_auto_swap`, `proxiware_eligible_threshold`, `proxiware_worker_concurrency`, `proxiware_retry_limit`, and `proxiware_cooldown_seconds`.
- [ ] Ensure stale claims recover after lease expiry/reboot and that schema helpers do not reference absent core tables.
- [ ] Add tests for fresh, partial, legacy, and restarted databases.

### Task 2: Finish sync and qualification workers

**Files:**
- Modify: `app/proxiware_sync_service.py`, `app/services/proxiware_qualification_service.py`, `docker-compose.yml`, `deploy/earn-proxy-proxiware.service`, `deploy/earn-proxy-proxiware-qualification.service`
- Test: `tests/test_proxiware_sync.py`, `tests/test_proxiware_qualification_service.py`, `tests/test_proxiware_qualification_integration.py`

- [ ] Enforce one active sync/qualification claim per provider, bounded concurrency, idle sleep, finite retry, cancel, progress, and crash recovery.
- [ ] Process inventory in bounded batches suitable for 30,000 proxies; never prefetch an unbounded list or busy-loop while idle.
- [ ] Use the canonical checker with `unknown -> auto`; preserve `inconclusive` rather than converting it to `Dead`.
- [ ] Reconcile egress duplicates against every user and every provider inventory, including late-arriving records.
- [ ] Persist safe status, country, protocol, last probe, next probe, and reason codes only.

### Task 3: Complete guarded swap state machine

**Files:**
- Modify: `app/services/proxiware_swap.py`, `app/proxiware_swap_service.py`
- Create/modify: `app/services/proxiware_browser.py`
- Test: `tests/test_proxiware_swap.py`, `tests/test_proxiware_swap_service.py`, `tests/test_proxiware_browser.py`

- [ ] Queue only when every guard passes; make decisions explicit and durable.
- [ ] Persist old/new mapping before marking success; set replacement readiness to `success_at + max(configured_cooldown, 60s)`.
- [ ] Bound retries and stop on provider conflict, quota, session, CSRF, CAPTCHA, fingerprint, or manual-action errors.
- [ ] Keep the browser adapter injectable and fail-closed. It may use the owner-configured account and 2Captcha only when authorized; never spoof fingerprint or persist raw token/cookie/password.
- [ ] Provide a dry-run adapter that records intended calls without contacting mutation endpoints. Auto-swap remains OFF.

### Task 4: Build the dedicated admin workspace

**Files:**
- Modify: `app/routes/admin.py`, `app/templates/base.html`, `app/templates/admin_proxiware.html`, `app/static/app.css`, `app/static/app.js`, `app/__init__.py`
- Test: `tests/test_admin_proxiware_workspace.py`, `tests/test_admin_proxiware_actions.py`

- [ ] Add the sidebar group and stable routes in the provider menu contract; remove duplicate provider controls from unrelated menus.
- [ ] Give every area a real route, breadcrumb, active sidebar state, and direct reload/deep-link support; do not use `#` as application navigation.
- [ ] Add overview count cards for total/live/dead/Allow/Risk/pending/inconclusive/duplicate/queued/blocked/manual-action states.
- [ ] Add provider health alerts for stale sync, worker heartbeat loss, session expiry, blocked queue, and manual action; link each alert to the exact corrective view.
- [ ] Add inventory, qualification, sync, swap, session, credentials, policy, and audit views with shared validated query/pagination helpers.
- [ ] Separate actionable swap queue from immutable swap history; show masked assignment/old/new proxy identifiers, reason, attempts, timestamps, and safe result codes.
- [ ] Add working `Sync now`, `Cancel`, `Test connection`, `Renew session`, `Retry`, `Cancel swap`, and `Pause/Resume` actions with target-specific confirmation.
- [ ] Limit buttons by state: no retry for running/success/cancelled jobs, no cancel for terminal jobs, no manual swap unless every guard except auto mode passes.
- [ ] Show inline progress and safe errors; never lock the entire page behind an infinite spinner.
- [ ] Show secrets as write-only configured/missing states; support independent rotate/clear actions for API key, email, password, and 2Captcha key.
- [ ] Redact secrets and internal checker/provider names from contributor/user pages, HTML, JSON, logs, URLs, and audit entries.
- [ ] Add `Cache-Control: no-store`, authorization, CSRF, rate limits, keyboard focus states, empty/error/stale/blocked states, and responsive layouts.
- [ ] Verify every read and mutation is provider-scoped and cannot access or change another provider's inventory, jobs, credentials, settings, session, or audit records.

### Task 5: Acceptance, security, and deployment gate

**Files:**
- Create/modify: `scripts/proxiware_preflight.py`, `tests/test_proxiware_acceptance.py`, `docs/runbooks/proxiware.md`, `README.md`

- [ ] Add redacted preflight and dry-run reports covering schema, settings, API read access, worker health, route auth, CSRF, rate limits, secret redaction, rollback, and no-mutation guarantees.
- [ ] Verify duplicate egress, stale probe, captive portal, TLS certificate failure, timeout, `inconclusive`, Allow/Risk/Dead/Pending, cooldown, retry, cancel, and restart behavior.
- [ ] Run:

```powershell
python -m pytest -p no:cacheprovider -q
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m compileall -q app tests scripts
python -m pip check
```

- [ ] Run Chrome CDP `9222` desktop/mobile smoke tests; inspect console/network for failed actions, secret leakage, focus issues, and broken pagination/filter/sort.
- [ ] Smoke-test every provider submenu by direct URL, reload, back/forward navigation, active menu state, empty state, and unauthorized access.
- [ ] Review `git diff`; commit logical units; push `feat/proxiware-sync-swap` only after all gates pass.
- [ ] Do not deploy VPS, enable auto-swap, or perform a real swap in this plan. A separate explicit approval is required for a one-assignment pilot.

## Definition of Done

- Admin sees one coherent `Providers -> Proxiware` control center with all required operational areas.
- Every submenu is independently addressable, reload-safe, permission-checked, and free of hash-only routing.
- Inventory, qualification, queue, history, and audit lists expose count/search/filter/sort/page-size/pagination without leaking credentials.
- Sync, qualification, and swap workers are durable, bounded, restart-safe, and observable.
- Duplicate egress is global and fail-closed.
- Auto-swap remains OFF until a dry-run and manual pilot approval pass.
- Full tests, static checks, browser smoke, security sweep, and preflight report pass with no secrets or CashPilot changes.
