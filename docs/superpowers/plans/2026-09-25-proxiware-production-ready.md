# Proxiware Production-Ready Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task. Keep checkbox steps, use TDD, commit at verified checkpoints, and never skip a release gate.

**Goal:** Close the remaining Proxiware production gates without weakening fail-closed safety, then release observation first and enable automatic swap only after a measured one-assignment canary.

**Architecture:** Keep the official Proxiware API read-only for account, subscription, and credential inventory. Use a separate isolated browser worker for dashboard observation and, only after explicit enablement, the authorized swap flow. SQLite remains the durable source for assignment, qualification, freshness, swap, and audit state. Every mutation revalidates fresh dashboard and qualification evidence immediately before execution.

**Tech stack:** Python 3.11, Flask, SQLite, requests, Fernet, pytest, Ruff, Gunicorn, systemd, Chrome/Chromium CDP.

## Global constraints

- Work only in D:\1. WORK_true\Tranfer Proxy\earn-proxy. Never modify or deploy CashPilot.
- Baseline release: 7f61f4397178b3ef00c28a3928f79158d7d4c62f.
- Never print, persist, or return plaintext passwords, API keys, cookies, CAPTCHA tokens, CDP state, fingerprints, or raw provider payloads.
- Official API stays read-only. Never automate purchase, billing, renewal, subscription creation, or payment.
- Auto-swap and Proxiware distribution remain OFF until the canary gate.
- CAPTCHA handling is allowed only for the explicitly authorized provider account. No bypass, fingerprint spoofing, stealth patch, or random profile rotation.
- Browser automation is fail-closed: missing adapter, expired session, provider rejection, CSRF/fingerprint error, or repeated challenge failure becomes manual_action_required and pauses automatic swap.
- Replacement probing starts only after at least 60 seconds from provider success.
- Do not repeat the already completed pilot swap 188.220.155.85 to 51.194.85.8.

## Current blockers to close

- Production adapter is UnavailableProxiwareBrowser and reports manual_action_required.
- Official API does not expose dashboard eligible/connections; current database values cannot authorize app-managed swap.
- Qualification service has shown a stale heartbeat while the systemd service remains active.
- Existing release is deployed and healthy; preserve the rollback release.

## Current execution state

Revalidate this snapshot before changing anything. It records the state observed on 2026-09-25, not a substitute for fresh preflight evidence.

- Working branch: `fix/proxiware-dashboard-observation`.
- `HEAD` and `origin/main`: `7f61f4397178b3ef00c28a3928f79158d7d4c62f`.
- In-progress dashboard observation and qualification heartbeat changes are uncommitted. Preserve them; do not restart or discard them.
- Last focused dashboard/sync/bootstrap result: `29 passed`.
- Last focused qualification/healthcheck result: `8 passed`.
- Last swap/service/admin result: `37 passed, 21 failed`. The known failure is test fixtures missing fresh dashboard evidence after the swap guard became fail-closed.
- Last clean baseline full-suite result before the current edits: `605 passed in 568.64s`.
- Production release symlink last observed at `/opt/earn-proxy-7f61f4397178b3ef00c28a3928f79158d7d4c62f` with rollback `/opt/earn-proxy-7e23a3db0f8f40e6c009bbd6363ca16511b54313`.
- Production browser adapter remains unavailable and must not be represented as ready.

## Execution rules

- Begin with `git status --short --branch`, inspect every existing diff, and continue from the current branch.
- Never reset, checkout, clean, stash, or overwrite existing work.
- Fix the first failing gate before adding the next production component.
- Use additive SQLite migrations only. Back up the production database before migration.
- Keep `proxiware_auto_swap=0` and `proxiware_distribution_enabled=0` through development, deployment, observation soak, and canary review.
- A service being `active` is not proof of health. Verify heartbeat age, bounded idle CPU, claim recovery, logs, and functional health endpoints.
- Never claim production-ready from mocks alone. Browser/session, release, rollback, and public health need production evidence.

## File ownership

- app/services/proxiware_dashboard.py: typed dashboard observation and freshness boundary.
- app/services/proxiware_browser.py: browser adapter interface, loopback/CDP validation, dry-run and fail-closed behavior.
- app/proxiware_browser_service.py: isolated browser/session worker and heartbeat.
- app/services/proxiware_qualification_service.py: bounded qualification claims and heartbeat.
- app/services/proxiware_swap.py and app/proxiware_swap_service.py: fresh guards, claims, mapping, retry, and cooldown.
- app/db.py: additive migrations only.
- app/routes/admin.py and app/templates/admin_proxiware*.html: safe status and controls.
- deploy/earn-proxy-proxiware-browser.service: least-privilege browser worker.
- tests/test_proxiware_dashboard.py, tests/test_proxiware_browser*.py, tests/test_proxiware_qualification_service.py, tests/test_proxiware_swap*.py, tests/test_proxiware_acceptance.py: gate coverage.
- docs/runbooks/proxiware.md and docs/security-audits/run-4/: operator and security evidence.

## Task 0: Close the current red test gate (completed 2026-09-25)

Files: `tests/test_proxiware_swap.py`, `tests/test_proxiware_swap_service.py`, `tests/test_admin_proxiware_actions.py`

- [x] Update shared swap fixtures to include a valid fresh dashboard observation: deterministic `dashboard_assignment_id`, `dashboard_eligible=1`, `dashboard_connections=10`, `dashboard_source='provider_dashboard'`, and a fresh observation timestamp.
- [x] Keep dedicated negative tests without those fields to prove missing, stale, ineligible, and `connections >= 1000` observations remain blocked.
- [x] Inspect `SwapDecision.for_subscription` and every SQL placeholder/column ordering touched by the new fields.
- [x] Run:
  `python -m pytest -q -p no:cacheprovider tests/test_proxiware_swap.py tests/test_proxiware_swap_service.py tests/test_admin_proxiware_actions.py`
- [x] Expected gate: zero failures: `58 passed in 52.97s`. The production guard remains fail-closed.
- [ ] Commit only this coherent dashboard-guard slice after the focused tests pass. (Commit is the next execution action.)

## Task 1: Freeze baseline and safety

Files: scripts/proxiware_preflight.py, tests/test_proxiware_acceptance.py, docs/runbooks/proxiware.md

- [ ] Verify branch, commit, remote, release symlink, rollback release, service state, auto_swap=0, and distribution=0 without mutation.
- [ ] Add a redacted preflight report containing only booleans, counts, safe codes, timestamps, and release paths.
- [ ] Assert that an unavailable adapter cannot claim swap success.
- [ ] Run:
  python -m pytest -q -p no:cacheprovider tests/test_proxiware_acceptance.py
  python scripts/proxiware_preflight.py --database .\instance\preflight.db

## Task 2: Repair qualification heartbeat and bounded work

Files: app/services/proxiware_qualification_service.py, app/services/proxiware_qualification.py, deploy/earn-proxy-proxiware-qualification.service, tests/test_proxiware_qualification_service.py

- [ ] Write failing tests for idle heartbeat, active claims, provider error, cancellation, restart, stale claim recovery, and no busy loop.
- [ ] Persist status, heartbeat_at, last safe error, and next wake time before every bounded sleep.
- [ ] Ensure each claim is released or recovered once; never duplicate a claim after restart.
- [ ] Keep worker and per-provider concurrency bounded.
- [ ] Add a read-only healthcheck returning ok, stale, disabled, or manual_action_required plus age.
- [ ] Observe two fresh production intervals before enabling any mutation.

## Task 3: Add dashboard observation boundary

Files: app/services/proxiware_dashboard.py, app/db.py, app/services/proxiware.py, tests/test_proxiware_dashboard.py, tests/test_proxiware_sync.py

Interface:
- DashboardAssignment(assignment_id, subscription_id, address, eligible, connections, observed_at)
- ProxiwareDashboardAdapter.observe(subscription_id) -> list[DashboardAssignment]
- apply_dashboard_observation(db, snapshot, now) -> None

- [ ] Add additive fields dashboard_assignment_id, dashboard_eligible, dashboard_connections, dashboard_observed_at, dashboard_source, and a safe observation error.
- [ ] Reject missing IDs, invalid counts, wrong subscription scope, and stale timestamps.
- [ ] Official API sync must not overwrite fresh dashboard fields with NULL.
- [ ] Identity changes invalidate the old observation.
- [ ] Mark observations older than the configured bound stale; stale data cannot authorize swap.
- [ ] Prove observation is read-only: no POST, PUT, or DELETE and no credential leakage.

## Task 4: Implement isolated browser/session worker

Files: app/services/proxiware_browser.py, app/proxiware_browser_service.py, deploy/earn-proxy-proxiware-browser.service, .env.example, tests/test_proxiware_browser.py, tests/test_proxiware_browser_service.py

- [ ] Separate observe_dashboard and swap_assignment interfaces.
- [ ] Run a dedicated browser OS user/profile with CDP bound to 127.0.0.1 only; never expose port 9222 or mount the desktop profile.
- [ ] Persist only encrypted session cookies and expiry metadata; restrict profile permissions and remove temporary artifacts on shutdown.
- [ ] Renew only the configured account with bounded challenge handling.
- [ ] Obtain fingerprint values only from the real page context; never spoof or store raw values.
- [ ] Persist worker heartbeat, session state, safe error, and restart state.
- [ ] Test success with a fake adapter, expiry, missing fingerprint, CAPTCHA timeout, provider rejection, redaction, and dry-run no-mutation.

## Task 5: Connect fresh observation to swap guards

Files: app/services/proxiware_swap.py, app/proxiware_swap_service.py, tests/test_proxiware_swap.py, tests/test_proxiware_swap_service.py

- [ ] Re-read identity, live state, Risk qualification, duplicate state, dashboard age, dashboard eligible, connections, quota, cooldown, active jobs, and pause state inside claim and immediately before mutation.
- [ ] Reject missing or stale dashboard evidence with durable manual_action_required or dashboard_stale.
- [ ] Preserve one active job per subscription and recover expired claims without duplicate mutation.
- [ ] Call only the injected browser mutation adapter after all guards pass.
- [ ] Persist old/new mapping before success, set replacement_ready_at to success plus at least 60 seconds, and clear distribution until requalification.
- [ ] Require post-swap observation to identify the replacement; otherwise block and pause.
- [ ] Test every guard, 409/429/5xx, session/CAPTCHA/CSRF/fingerprint errors, retries, cancellation, restart, and mapping integrity.

## Task 6: Finish admin controls and UX

Files: app/routes/admin.py, app/templates/admin_proxiware.html, app/templates/admin_proxiware_*.html, app/static/app.js, app/static/app.css, tests/test_admin_proxiware_actions.py, tests/test_admin_proxiware_workspace.py

- [ ] Show separate badges for API sync, dashboard freshness, browser adapter, session, qualification heartbeat, swap worker, auto-swap, and distribution.
- [ ] Keep observation, mutation adapter, auto-swap, and distribution controls independent and OFF by default.
- [ ] Require CSRF, admin authorization, target confirmation, rate limiting, audit, and no-store headers for every state change.
- [ ] Show safe reason codes without credentials or raw provider payloads.
- [ ] Link stale heartbeat/session/adapter alerts to corrective pages; no page-wide infinite spinner.
- [ ] Browser-smoke desktop/mobile, keyboard focus, filters, pagination, overflow, console, and network mutation expectations.

## Task 7: Distribution and API safety gate

Files: app/routes/internal_api.py, app/services/proxiware_swap.py, tests/test_proxiware_distribution.py, tests/test_internal_api.py

- [ ] Keep Proxiware distribution separate from user earnings, online hours, quota, and Transfer Proxy.
- [ ] Exclude dead, pending, inconclusive, unknown, duplicate, stale health, stale dashboard, cooldown, active swap, and distribution-disabled records.
- [ ] Keep raw and transfer outputs separate; never expose provider credentials or internal reason text.
- [ ] Prove provider pause or swap failure cannot alter user accounting or unrelated distribution.

## Task 8: Security and release audit

Files: docs/security-audits/run-4/, docs/runbooks/proxiware.md, README.md

- [ ] Audit authorization, CSRF, IDOR/provider scope, SSRF, XSS, SQL/command injection, redaction, cache headers, rate limits, replay/idempotency, filesystem permissions, and systemd sandboxing.
- [ ] Secret-scan tracked files, rendered HTML, logs, journals, and query strings; redact reports.
- [ ] Verify migration backup/rollback, dependency consistency, and release preflight.
- [ ] Run exactly:
  python -m pytest -q -p no:cacheprovider
  python -m ruff check app tests scripts
  python -m ruff format --check app tests scripts
  python -m compileall -q app tests scripts
  python -m pip check
  git diff --check

## Task 9: Staged deployment and one-assignment canary

Files: deploy/release.sh, deployment environment outside Git, docs/runbooks/proxiware.md

- [ ] Commit and push only after every local gate passes; verify main and origin/main match.
- [ ] Deploy through the existing versioned release script; preserve database backup and rollback release.
- [ ] Verify services enabled/active, local/public health, route authorization, fresh heartbeats, no secret leakage, auto_swap=0, distribution=0.
- [ ] Enable dashboard observation only and monitor at least two worker intervals.
- [ ] Require separate written approval naming exactly one target, rollback owner, account authorization, and observation window.
- [ ] Execute exactly one canary through the reviewed adapter; wait at least 60 seconds; re-observe, qualify, and verify mapping and distribution exclusion.
- [ ] Keep auto-swap OFF until canary review. Enable only as a separate approved change with live monitoring and rollback.
- [ ] On any failure, set manual_action_required, pause automation, and roll back; never simulate success.

## Definition of done

- [ ] Full tests, static, compile, dependency, security, preflight, and browser gates pass.
- [ ] Qualification heartbeat is fresh and bounded with no idle CPU loop or stranded claim.
- [ ] Dashboard observation is scoped, fresh, redacted, and protected from stale API overwrite.
- [ ] Browser worker is isolated, loopback-only, restart-safe, and fail-closed.
- [ ] Swap guard revalidates every condition immediately before mutation; mapping and 60-second delay are durable.
- [ ] Distribution/API excludes every unsafe or stale record and remains independent from user accounting.
- [ ] Admin UX exposes actionable state without secrets.
- [ ] One approved canary is verified; auto-swap is enabled only with separate approval.
- [ ] No CashPilot file, purchase, billing action, or unapproved swap is touched.

## Required final report

Report: changed files; schema/migrations; exact test/static/security results; release and rollback paths; service/heartbeat/health evidence; adapter/session state; canary evidence; residual risks; manual operator actions. Never claim production-ready while a required gate is skipped or the adapter/session is unverified.
