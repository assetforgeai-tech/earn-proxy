# Proxiware Production-Ready Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task. Keep checkbox steps, use TDD, commit at verified checkpoints, and never skip a release gate.

**Goal:** Close the remaining Proxiware production gates from commit `547edc4`, release observation first, and permit automatic swap only after an explicitly approved one-assignment canary.

**Architecture:** Keep the official Proxiware API read-only for account, subscription, and credential inventory. Use a separate isolated browser worker for dashboard observation and, only after explicit enablement, the authorized swap flow. SQLite remains the durable source for assignment, qualification, freshness, swap, and audit state. Every mutation revalidates fresh dashboard and qualification evidence immediately before execution.

**Tech stack:** Python 3.11, Flask, SQLite, requests, Fernet, pytest, Ruff, Gunicorn, systemd, Chrome/Chromium CDP.

## Global constraints

- Work only in D:\1. WORK_true\Tranfer Proxy\earn-proxy. Never modify or deploy CashPilot.
- Baseline release: `547edc4` on `fix/proxiware-dashboard-observation`; `origin/main` remains `7f61f4397178b3ef00c28a3928f79158d7d4c62f` until the merge gate.
- Never print, persist, or return plaintext passwords, API keys, cookies, CAPTCHA tokens, CDP state, fingerprints, or raw provider payloads.
- Official API stays read-only. Never automate purchase, billing, renewal, subscription creation, or payment.
- Auto-swap and Proxiware distribution remain OFF until the canary gate.
- CAPTCHA handling is allowed only for the explicitly authorized provider account. No bypass, fingerprint spoofing, stealth patch, or random profile rotation.
- Browser automation is fail-closed: missing adapter, expired session, provider rejection, CSRF/fingerprint error, or repeated challenge failure becomes manual_action_required and pauses automatic swap.
- Replacement probing starts only after at least 60 seconds from provider success.
- Do not repeat the already completed pilot swap 188.220.155.85 to 51.194.85.8.

## Current blockers to close

- Production adapter is still `UnavailableProxiwareBrowser` and must remain fail-closed until the isolated browser boundary is reviewed.
- The runtime observer boundary exists only as an uncommitted partial slice; scope validation, active-call heartbeat, durable scheduling/backoff, atomic snapshot application, production CDP integration, and release wiring remain incomplete.
- No dedicated browser/session service unit exists yet; the release script does not install one.
- Qualification heartbeat, batch aggregation, `next_wake_at`, and all-failure degradation are implemented in the current worktree; deterministic stop/cancel/restart claim recovery and production soak still need evidence.
- Swap execution still has non-idempotent race hazards: guard TOCTOU, expired-running automatic reclaim, cancellation during provider I/O, duplicate mutation, and provider/DB divergence.
- `mark_swap_success()` can clone the old credential into an unobserved replacement; post-swap identity and official credential evidence are not mandatory yet.
- Proxiware distribution now honors the Allow/Risk policy, parent subscription state, protocol allowlist, timestamp upper bounds, and active mutation states. One parity defect remains: user-owned rows only lower-bound `last_success_at`, so a timestamp far in the future is still exportable.
- Admin credential/settings mutations still need explicit `Cache-Control: no-store`, complete mutation rate limiting, authorization/CSRF/IDOR review, and conflict behavior while a job is `mutating`.
- Static/dependency gates are not green: Ruff import order and formatting failures remain in the current worktree; `pip check` reports `cryptography`/`rich` conflicts that must be classified and resolved without speculative dependency churn.
- Full static/security/preflight gates, merge, deploy, observation soak, and canary evidence are still pending.

## Current execution state

### Continuation checkpoint: 2026-09-26

- Run 5 security audit completed. One LOW oversized-registration-email finding
  was reproduced, fixed, independently verified, and recorded in
  `docs/security-audits/run-5/`.
- The dashboard observer now forces a read-only adapter even if the global
  mutation flag is accidentally enabled. The swap worker queues eligible jobs
  when automatic mode is explicitly enabled and freezes assignment identity at
  the durable mutation fence.
- Clean isolated venv gate: `pip check` passes; full test/static/compile gates
  must be rerun after the final diff. Auto-swap and distribution remain `0`.
- Production browser/session evidence, release/rollback evidence, observation
  soak, and the separately approved canary remain open. Do not claim
  production-ready or execute a provider mutation until those gates are
  evidenced.

Revalidate this snapshot before changing anything. It records the state observed on 2026-09-25, not a substitute for fresh preflight evidence.

- Working branch: `fix/proxiware-dashboard-observation`.
- `HEAD`: `547edc4 feat: require fresh Proxiware dashboard evidence`; `origin/main`: `7f61f4397178b3ef00c28a3928f79158d7d4c62f`.
- The worktree has valid uncommitted browser-worker, dashboard, qualification, distribution, healthcheck, test, plan, and prompt changes. Inspect every diff and continue from it; do not reset, stash, revert, or overwrite it.
- Focused swap/service/admin gate: `58 passed`.
- Combined dashboard/sync/qualification/health/swap/admin gate: `95 passed in 75.46s`.
- Current worktree full suite: `625 passed in 596.49s (0:09:56)`. This proves regression coverage only; it does not close the missing production adapter, worker, release, or canary gates.
- Latest focused uncommitted gates include qualification `12 passed`, Proxiware distribution `10 passed`, and wrong-subscription browser scope `1 passed`. Re-run these; do not treat the snapshot as current evidence.
- Scoped Ruff for the committed slice: `All checks passed!`; `git diff --check` passed.
- Production release symlink last observed at `/opt/earn-proxy-7f61f4397178b3ef00c28a3928f79158d7d4c62f` with rollback `/opt/earn-proxy-7e23a3db0f8f40e6c009bbd6363ca16511b54313`.
- Production browser adapter remains unavailable and must not be represented as ready.

## Execution rules

- Begin with `git status --short --branch`, inspect every existing diff, and continue from the current branch.
- Never reset, checkout, clean, stash, or overwrite existing work.
- Fix the first failing gate before adding the next production component.
- Use additive SQLite migrations only. Back up the production database before migration.
- Keep `proxiware_auto_swap=0` and `proxiware_distribution_enabled=0` through development, deployment, observation soak, and canary review.
- Treat swap as non-idempotent unless the provider supplies and verifies an idempotency key. Never automatically retry an uncertain mutation outcome.
- A service being `active` is not proof of health. Verify heartbeat age, bounded idle CPU, claim recovery, logs, and functional health endpoints.
- Never claim production-ready from mocks alone. Browser/session, release, rollback, and public health need production evidence.

## File ownership

- app/services/proxiware_dashboard.py: typed dashboard observation and freshness boundary.
- app/services/proxiware_browser.py: browser adapter interface, loopback/CDP validation, dry-run and fail-closed behavior.
- app/proxiware_browser_service.py: isolated browser/session worker and heartbeat.
- app/services/proxiware_qualification_service.py: bounded qualification claims and heartbeat.
- app/services/proxiware_swap.py and app/proxiware_swap_service.py: fresh guards, claims, mapping, retry, and cooldown.
- app/routes/internal_api.py: shared Allow/Risk policy and safe provider distribution query.
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
- [x] Commit only this coherent dashboard-guard slice after the focused tests pass: `547edc4 feat: require fresh Proxiware dashboard evidence`.

## Task 1: Freeze baseline and safety

Files: scripts/proxiware_preflight.py, tests/test_proxiware_acceptance.py, docs/runbooks/proxiware.md

- [ ] Verify branch, commit, remote, release symlink, rollback release, service state, auto_swap=0, and distribution=0 without mutation.
- [ ] Extend preflight beyond a disposable DB: report production branch/SHAs, release and rollback paths, service enabled/active state, heartbeat timestamps plus `age_seconds`, final settings, DB backup target, adapter/session state, and public/local health. Output only booleans, counts, safe codes, timestamps, and release paths.
- [ ] Instrument dry-run/read-only adapters so `provider_mutation_calls=0` is measured, not a local placeholder.
- [ ] Assert that an unavailable adapter cannot claim swap success.
- [ ] Run:
  python -m pytest -q -p no:cacheprovider tests/test_proxiware_acceptance.py
  python scripts/proxiware_preflight.py --database .\instance\preflight.db

## Task 2: Verify qualification heartbeat and bounded work

Files: app/services/proxiware_qualification_service.py, app/services/proxiware_qualification.py, deploy/earn-proxy-proxiware-qualification.service, tests/test_proxiware_qualification_service.py

- [x] Keep idle heartbeat fresh with bounded sleep slices; the implementation exists in the current worktree.
- [ ] Add failing tests proving: all-row failure is not reported as `ok`; heartbeat remains fresh during a probe longer than the health threshold; stop releases only work that never started; active work reaches one terminal row state; restart recovers each abandoned pre-probe claim once; idle mode does not busy-loop.
- [ ] Aggregate `checked`, `failed`, `stale_claim`, and `canceled` outcomes. Record `ok` and `last_success` only when at least one row completed successfully; use a safe degraded/error state when the whole batch fails.
- [ ] Persist status, heartbeat age, last safe error, and `next_wake_at` before every bounded sleep and after every batch.
- [ ] Refresh heartbeat while futures are active without opening a second worker cycle. On stop, stop claiming new rows, cancel only futures that have not started, and let active probes finalize or release their own claim exactly once.
- [ ] Ensure each claim is released or recovered once; never duplicate a claim after restart.
- [ ] Keep worker and per-provider concurrency bounded and verify the configured ceiling.
- [ ] Verify the read-only healthcheck returns `ok`, `stale`, `disabled`, or `manual_action_required` with age.
- [ ] Observe two fresh production intervals before enabling any mutation.

## Task 3: Wire the dashboard observation boundary

Files: app/services/proxiware_dashboard.py, app/db.py, app/services/proxiware.py, tests/test_proxiware_dashboard.py, tests/test_proxiware_sync.py

Interface:
- DashboardAssignment(assignment_id, subscription_id, address, eligible, connections, observed_at)
- ProxiwareDashboardAdapter.observe(subscription_id) -> list[DashboardAssignment]
- apply_dashboard_observation(db, snapshot, now) -> None

- [x] Add additive fields dashboard_assignment_id, dashboard_eligible, dashboard_connections, dashboard_observed_at, dashboard_source, and a safe observation error.
- [x] Reject missing IDs, invalid counts, wrong subscription scope, and stale timestamps.
- [x] Official API sync does not overwrite fresh dashboard fields with NULL.
- [x] Identity changes invalidate the old observation.
- [x] Mark observations older than the configured bound stale; stale data cannot authorize swap.
- [ ] Finish the runtime observer worker with durable per-subscription scheduling, bounded exponential backoff, safe error codes, `next_wake_at`, restart recovery, and heartbeat refresh during browser/network calls.
- [ ] Treat bounded transport/provider errors as degraded and retryable without invalidating a still-valid session. Only verified authentication/session/challenge failures become `manual_action_required`.
- [ ] Assert every returned snapshot belongs to the requested subscription and expected endpoint. Reject duplicate or ambiguous address mappings and wrong-scope rows before any write.
- [ ] Apply one subscription snapshot atomically. A partial/failed response must not mix old and new rows; an older observation must never overwrite a newer one.
- [ ] Prove observation is read-only: no POST, PUT, DELETE, provider mutation, raw response persistence, or credential leakage.

## Task 4: Implement isolated browser/session worker

Files: app/services/proxiware_browser.py, app/proxiware_browser_service.py, deploy/earn-proxy-proxiware-browser.service, .env.example, tests/test_proxiware_browser.py, tests/test_proxiware_browser_service.py

- [ ] Keep `restore_session`, `observe_dashboard`, and `swap_assignment` as separate interfaces; observation must work while mutation capability remains disabled.
- [ ] Implement the reviewed production CDP adapter for the real Proxiware page selectors and response shapes. The adapter must validate page origin, account scope, subscription ID, assignment ID, endpoint, and expected confirmation before returning typed data.
- [ ] Run a dedicated browser OS user/profile with CDP bound to 127.0.0.1 only; never expose port 9222 or mount the desktop profile.
- [ ] Persist only encrypted session cookies and expiry metadata; restrict profile permissions and remove temporary artifacts on shutdown.
- [ ] Restore only the configured account session. Any login challenge or expired/unverified session becomes `manual_action_required`; do not bypass CAPTCHA or spoof browser identity.
- [ ] Obtain fingerprint values only from the real page context; never spoof or store raw values.
- [ ] Persist worker heartbeat, session state, safe error, and restart state.
- [ ] Add config in `app/__init__.py` and `.env.example`, CLI entry in `pyproject.toml`, `deploy/earn-proxy-proxiware-browser.service`, release wiring, least-privilege directories, and healthcheck coverage.
- [ ] Test fake-adapter success, wrong account/origin/scope, expiry, missing page evidence, challenge, timeout, provider rejection, redaction, restart, graceful stop, and dry-run no-mutation.

## Task 5: Connect fresh observation to swap guards

Files: app/services/proxiware_swap.py, app/proxiware_swap_service.py, tests/test_proxiware_swap.py, tests/test_proxiware_swap_service.py

- [ ] Add red tests for guard TOCTOU, lease expiry during adapter I/O, two workers seeing one job, cancellation during provider I/O, timeout with unknown provider outcome, stale worker completion, missing replacement evidence, and accidental old-credential cloning.
- [ ] Construct the adapter without provider I/O, then atomically re-read identity, live state, Risk qualification, duplicate state, dashboard age, dashboard eligible, connections, quota, cooldown, active jobs, and pause state while moving the job into a durable `mutating` fence.
- [ ] Perform provider I/O outside the SQLite transaction under that immutable mutation fence and a hard timeout. `mutating` jobs cannot be canceled, reclaimed, retried, or executed by another worker.
- [ ] Reject missing or stale dashboard evidence with durable manual_action_required or dashboard_stale.
- [ ] Recover expired claims only before the mutation fence. An expired `mutating` job or uncertain timeout becomes `reconciliation_required`, disables auto-swap, and requires read-only provider reconciliation; never re-call the mutation automatically.
- [ ] Allow cancel only for queued/pre-mutation jobs. If mutation has started, return conflict and let the reconciliation path establish provider truth.
- [ ] Call only the injected browser mutation adapter after all guards pass.
- [ ] Persist the provider-returned old/new IDs and mutation timestamp as pending reconciliation evidence immediately after a confirmed response. Do not expose that evidence as a successful mapping yet.
- [ ] Require official read-only sync plus a dashboard observation newer than the mutation timestamp to identify the replacement. Clear all inherited `dashboard_*` fields at the mutation boundary; pre-swap evidence must never authorize the replacement.
- [ ] Never clone host, port, username, password, country, or eligibility from the old assignment. Create/retain the replacement as `pending`, with distribution disabled and credentials empty, until official read-only sync supplies credentials and dashboard observation confirms identity.
- [ ] Finalize the success mapping only after reconciliation evidence passes, set `replacement_ready_at` to at least 60 seconds after provider success, then require live probe, egress/duplicate check, and requalification before distribution.
- [ ] Test every guard, 409/429/5xx, session/CAPTCHA/CSRF/fingerprint errors, retries, cancellation, restart, and mapping integrity.

## Task 6: Finish admin controls and UX

Files: app/routes/admin.py, app/templates/admin_proxiware.html, app/templates/admin_proxiware_*.html, app/static/app.js, app/static/app.css, tests/test_admin_proxiware_actions.py, tests/test_admin_proxiware_workspace.py

- [ ] Show separate badges for API sync, dashboard freshness, browser adapter, session, qualification heartbeat, swap worker, auto-swap, distribution, and reconciliation-required jobs.
- [ ] Keep observation, mutation adapter, auto-swap, and distribution controls independent and OFF by default.
- [ ] Require CSRF, admin authorization, target confirmation, rate limiting, audit, and no-store headers for every state change. Destructive controls must return conflict while a job is `mutating`.
- [ ] Show safe reason codes without credentials or raw provider payloads.
- [ ] Link stale heartbeat/session/adapter alerts to corrective pages; no page-wide infinite spinner.
- [ ] Browser-smoke desktop/mobile, keyboard focus, filters, pagination, overflow, console, and network mutation expectations.

## Task 7: Distribution and API safety gate

Files: app/routes/internal_api.py, app/services/proxiware_swap.py, tests/test_proxiware_distribution.py, tests/test_internal_api.py

- [ ] Keep Proxiware distribution separate from user earnings, online hours, quota, and Transfer Proxy.
- [x] Apply `api_include_allow` and `api_include_risk` to Proxiware rows as well as user rows. Focused policy tests pass in the current worktree; re-run before commit.
- [x] Join Proxiware assignments to `provider_subscriptions` and require the parent subscription to be `active` or `ready`; reject unsupported protocols, future provider timestamps, and `mutating`/`provider_applied`/`reconciliation_required` jobs.
- [ ] Add a regression test where a user-owned proxy has `last_success_at = now + 7 days`; verify it is excluded. Apply the same bounded upper freshness limit used for Proxiware rows, allowing only the documented clock-skew window.
- [ ] Exclude dead, pending, inconclusive, unknown, duplicate, stale health, stale dashboard, cooldown, every active mutation/reconciliation state, and distribution-disabled records for both sources.
- [ ] Keep raw and transfer outputs separate. Raw credentials may be returned only by the authenticated internal API contract; never render or log them in admin/public UI, errors, query strings, or audit events. Never expose internal reason text.
- [ ] Prove provider pause or swap failure cannot alter user accounting or unrelated distribution.

## Task 8: Security and release audit

Files: docs/security-audits/run-4/, docs/runbooks/proxiware.md, README.md

- [ ] Audit authorization, CSRF, IDOR/provider scope, SSRF, XSS, SQL/command injection, redaction, cache headers, rate limits, replay/idempotency, filesystem permissions, and systemd sandboxing.
- [ ] Secret-scan tracked files, rendered HTML, logs, journals, and query strings; redact reports.
- [ ] Verify migration backup/rollback, dependency consistency, and release preflight.
- [ ] Specifically audit the browser profile/session file permissions, CDP bind address, mutation fence, uncertain-outcome reconciliation, provider scope, API class policy, and log/journal redaction.
- [ ] Run exactly:
  python -m pytest -q -p no:cacheprovider
  python -m ruff check app tests scripts
  python -m ruff format --check app tests scripts
  python -m compileall -q app tests scripts
  python -m pip check
  git diff --check

## Task 9: Staged deployment and observation soak

Files: deploy/release.sh, deployment environment outside Git, docs/runbooks/proxiware.md

- [ ] Commit and push only after every local gate passes; review the diff; merge to `main`; verify `main == origin/main`.
- [ ] Deploy through the existing versioned release script; preserve database backup and rollback release.
- [ ] Verify services enabled/active, local/public health, route authorization, fresh heartbeats, no secret leakage, auto_swap=0, distribution=0.
- [ ] Enable dashboard observation only and monitor at least two worker intervals.
- [ ] Verify snapshot scope and freshness, no provider mutation, bounded idle CPU/RAM, no stranded claims, no loop, no public CDP listener, and no secret in logs/journals.
- [ ] Keep swap worker, auto-swap, and Proxiware distribution OFF throughout this stage.

## Task 10: One-assignment canary and controlled enablement

Files: deployment environment outside Git, docs/runbooks/proxiware.md

- [ ] Require separate written approval naming exactly one target, rollback owner, account authorization, and observation window.
- [ ] Only after separate written approval naming exactly one target, rollback owner, and observation window, execute exactly one canary through the reviewed adapter; wait at least 60 seconds; re-observe, qualify, and verify mapping and distribution exclusion.
- [ ] Reconcile the canary through official read-only sync and fresh dashboard evidence before recording success. Confirm no old credential was copied and no second mutation occurred.
- [ ] Keep auto-swap OFF until canary review. Enable only as a separate approved change with live monitoring and rollback.
- [ ] On any failure, set manual_action_required, pause automation, and roll back; never simulate success.

## Definition of done

- [ ] Full tests, static, compile, dependency, security, preflight, and browser gates pass.
- [ ] Qualification heartbeat is fresh and bounded with no idle CPU loop or stranded claim.
- [ ] Dashboard observation is scoped, fresh, redacted, and protected from stale API overwrite.
- [ ] Browser worker is isolated, loopback-only, restart-safe, and fail-closed.
- [ ] Swap guard revalidates every condition at the mutation fence; uncertain outcomes cannot auto-retry; post-swap identity and credentials require reconciliation evidence.
- [ ] Distribution/API excludes every unsafe or stale record, honors Allow/Risk toggles for every source, and remains independent from user accounting.
- [ ] Admin UX exposes actionable state without secrets.
- [ ] One approved canary is verified; auto-swap remains OFF unless a separate approval explicitly enables it.
- [ ] No CashPilot file, purchase, billing action, or unapproved swap is touched.

## Required final report

Report: changed files; schema/migrations; exact test/static/security results; release and rollback paths; service/heartbeat/health evidence; adapter/session state; canary evidence; residual risks; manual operator actions. Never claim production-ready while a required gate is skipped or the adapter/session is unverified.
