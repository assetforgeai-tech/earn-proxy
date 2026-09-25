# Proxiware Provider Menu And Production Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish a first-class `Providers -> Proxiware` administration workspace and close the remaining correctness, security, worker, and acceptance gaps before any production swap or deployment.

**Architecture:** Keep Proxiware isolated behind provider-scoped services, routes, workers, tables, credentials, and audit records. Official API calls remain read-only. Swap uses an injectable browser adapter only after a fresh server-side guard check; unavailable or ambiguous browser/session behavior fails closed to `manual_action_required`. Provider inventory never becomes user earnings or user quota.

**Tech Stack:** Python 3.11, Flask, SQLite, requests, existing encryption helpers, pytest, Ruff, Docker/systemd, existing TailAdmin-compatible templates, Chrome CDP 9222 for read-only browser smoke.

**Decision:** Proxiware is a first-class provider-operations domain. It gets one dedicated admin workspace instead of being mixed into `Distribution API`, `Transfer Proxy`, or contributor pages. This keeps provider credentials, inventory, qualification, swap controls, and audit data behind one authorization boundary and allows provider automation to be paused without pausing unrelated proxy distribution.

## Why The Provider Menu Is Separate

Proxiware management is a control-plane workflow, not a user proxy or earnings workflow. The sidebar must expose one clear provider boundary:

```text
Providers
└── Proxiware
    ├── Overview
    ├── Inventory
    ├── Qualification
    ├── Sync
    ├── Swap queue
    ├── Swap history
    ├── Session
    ├── Credentials
    ├── Policy
    └── Audit
```

- Keep the provider menu out of `Distribution API`, `Transfer Proxy`, and contributor navigation.
- Reuse the existing admin authorization boundary; do not invent a second role system for this goal.
- Scope every read, mutation, worker claim, setting, credential, and audit lookup by `provider='proxiware'`.
- Show provider state in this workspace only; never convert it into user earnings, online hours, quota, or user-facing provider terminology.
- Keep provider automation pause/resume independent from unrelated proxy distribution and other providers.
- Every submenu must be direct-linkable, reload-safe, breadcrumbed, keyboard-usable, and reachable without hash-only navigation.
- If API, session, or worker is unavailable, keep the menu usable with an explicit stale, blocked, or `manual_action_required` state; never hide failure behind an infinite spinner or redirect everything to `/admin`.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never read, modify, migrate, deploy, or run commands in `D:\1. WORK_true\CashPilot`.
- Continue from branch `feat/proxiware-sync-swap`; preserve dirty changes; never reset or overwrite unrelated work.
- Never commit, log, render, or return API keys, passwords, cookies, CAPTCHA tokens, CDP state, fingerprints, or raw provider responses.
- Official Proxiware API is read-only; never automate purchase, billing, renewal, subscription creation, or payment actions.
- Auto-swap is OFF by default and remains OFF through acceptance. No real swap or VPS deployment without a separate explicit approval.
- `Allow`, `Dead`, `Pending`, `inconclusive`, `unknown`, duplicate-egress, cooldown, and active-swap records are not auto-swappable.
- A swap requires fresh validation at claim and execution time: live, `Risk`, provider eligible `<1000`, connections `<1000`, quota, no duplicate job, no duplicate egress, and cooldown elapsed.
- A successful swap persists old/new mapping before success and delays replacement probing at least 60 seconds.
- Browser fallback uses the owner's configured account/session only; CAPTCHA handling must be bounded and fail closed. `2Captcha` may solve hCaptcha only when authorized; it is not a fingerprint bypass. Preserve one isolated persistent browser profile instead of spoofing or randomizing fingerprints.
- Provider distribution is separate and default-OFF. It excludes dead, ambiguous, duplicate, cooldown, and active-swap records.

## Menu Contract

Create one sidebar group visible only to authorized admins:

`Providers -> Proxiware`

Canonical routes:

- `GET /admin/providers/proxiware` — overview and health.
- `GET /admin/providers/proxiware/inventory` — provider inventory.
- `GET /admin/providers/proxiware/qualification` — live/protocol/egress/country/quality.
- `GET /admin/providers/proxiware/sync` — sync progress and history.
- `GET /admin/providers/proxiware/swaps` — actionable queue.
- `GET /admin/providers/proxiware/swaps/history` — immutable history.
- `GET /admin/providers/proxiware/session` — session and connection state.
- `GET /admin/providers/proxiware/credentials` — write-only secrets.
- `GET /admin/providers/proxiware/policy` — guarded policy controls.
- `GET /admin/providers/proxiware/audit` — redacted audit trail.

Every list supports server-side count, search, filter, sort, page size, pagination, empty state, stale state, and safe error state. Every mutation has CSRF, authorization, rate limiting, target-specific confirmation, audit, and `Cache-Control: no-store`.

## Execution Phases And Stop Points

1. **Baseline:** inspect the current diff, schema, routes, workers, deployment files, and existing tests. Record the baseline test/static results. Do not rewrite working code or touch CashPilot.
2. **Read-only provider control center:** finish menu discovery, inventory sync, qualification, counts/filters, health, and redacted audit. Verify GET side-effect freedom before enabling any action button.
3. **Safe session boundary:** add encrypted write-only credentials, isolated persistent browser context, bounded hCaptcha handling, session renewal, and emergency pause. If the real browser adapter is unavailable or unreviewed, keep the visible state `manual_action_required`.
4. **Dry-run swap queue:** implement claim/revalidation/cooldown/mapping/retry behavior against fakes only. No provider mutation endpoint, browser click, purchase, billing, renewal, or subscription change is allowed in this phase.
5. **Distribution gate:** keep provider distribution disabled by default; prove raw/transfer output excludes every unsafe state and never affects contributor earnings, hours, or quota.
6. **Release gate:** run unit/integration/security/browser smoke and redacted preflight. Stop with a written blocker list if any gate fails, if `pip check` remains unresolved, or if browser automation cannot prove a stable authorized flow. Deployment and a one-assignment live pilot require a separate explicit approval.

Each phase must leave a reviewable artifact: tests, redacted report, or runbook update. A later phase cannot silently bypass an earlier failed gate.

## Provider Control-Center Requirements

The dedicated menu is an operational control center, not a second proxy list. It must provide:

- **Overview:** provider connection, API health, browser session, worker heartbeats, last successful sync/check, inventory totals, `Allow`/`Risk`/`Dead`/`Pending`, duplicate-egress, inconclusive, queued/blocked swap, manual-action counts, and one emergency automation pause control.
- **Inventory:** provider-scoped records with masked endpoint, subscription/assignment ID, protocol, country, live state, qualification, eligible count, connections, duplicate state, cooldown, and last probe. Never select or render encrypted secret columns.
- **Qualification:** check progress, bounded concurrency, last run, stale/error state, probe latency, and safe reason codes. `inconclusive` remains visible and is never silently converted to `Dead`.
- **Sync:** `Sync now`, progress, cancel, run history, idempotency result, retry state, and redacted provider errors. GET requests never start work.
- **Swap queue/history:** durable state, old/new masked mapping, guard result, attempt count, cooldown, retry/cancel/manual-action controls, and immutable outcome history. No blind retry.
- **Session/Credentials:** write-only email/password/API key/authorized CAPTCHA integration settings, encrypted at rest, explicit clear per secret, connection test, renewal status, and expiry. Never return plaintext, ciphertext, cookies, CAPTCHA tokens, CDP data, or raw fingerprint values.
- **Policy:** auto-swap default `OFF`, eligibility threshold default `1000`, connections ceiling `1000`, bounded concurrency/retry, cooldown minimum `60s`, and independent provider distribution toggle. Saving policy requires confirmation and audit.
- **Audit:** actor, action, safe target ID, result, timestamp, and redacted error code only.

Menu behavior rules:

1. Only authorized admins can discover or access the menu; non-admins receive the normal authorization response and no provider metadata.
2. Every state-changing action names the provider, target, and consequence before submit; buttons show disabled/loading/result states without locking the whole page.
3. Provider distribution, if enabled later, is fail-closed and separate from user earnings, online hours, quota, and provider inventory. It excludes dead, duplicate, ambiguous, cooldown, and active-swap records.
4. Provider IDs are scoped in every route, query, mutation, and audit lookup to prevent IDOR across providers or accounts.
5. Browser smoke must verify direct links, reload/back/forward, keyboard focus, mobile layout, filters, pagination, no horizontal overflow, no secret leakage, and no unexpected network mutation.

## Remaining Implementation Tasks

### Task 1: Fresh execution-time swap guards

**Files:** `app/proxiware_swap_service.py`, `app/services/proxiware_swap.py`, `tests/test_proxiware_swap_service.py`, `tests/test_proxiware_swap.py`

- [ ] Add a failing test proving a queued job is rejected if it becomes `Allow`, `Dead`, duplicate, cooldown, or over-threshold before execution.
- [ ] Re-read assignment, qualification, provider counters, quota, active jobs, and policy inside the claim/execution transaction.
- [ ] Return durable safe reason codes; never execute on stale queue-time decisions.
- [ ] Add tests for duplicate workers, lease expiry, retry bounds, manual-action pause, and restart recovery.

### Task 2: Distribution and cooldown safety

**Files:** `app/services/proxiware_swap.py`, `app/routes/internal_api.py`, `tests/test_proxiware_distribution.py`, `tests/test_proxiware_swap.py`

- [ ] Clear `distribution_enabled` on successful swap until the replacement is requalified.
- [ ] Exclude records with future `replacement_ready_at`, active swap jobs, ambiguous qualification, or duplicate egress from internal distribution.
- [ ] Add fail-closed tests for unknown provider state, stale probes, and concurrent swap claims.

### Task 3: Durable sync/qualification workers

**Files:** `app/proxiware_sync_service.py`, `app/services/proxiware_qualification_service.py`, `docker-compose.yml`, `deploy/earn-proxy-proxiware.service`, `deploy/earn-proxy-proxiware-qualification.service`, `tests/test_proxiware_sync.py`, `tests/test_proxiware_qualification_service.py`

- [ ] Move long sync work off the request path or implement a durable bounded handoff with progress polling.
- [ ] Enforce one active run per provider, finite retries, cancellation, lease recovery, idle sleep, bounded batches, and concurrency suitable for 30,000 records.
- [ ] Persist heartbeat, last success, queue depth, stale/error state, and healthcheck results.
- [ ] Ensure reboot/crash recovery does not duplicate jobs or spin CPU while idle.

### Task 4: Browser/session boundary

**Files:** `app/services/proxiware_browser.py`, `app/services/proxiware_credentials.py`, `app/routes/admin.py`, `tests/test_proxiware_browser.py`

- [ ] Add an injectable interface plus a dry-run adapter; unavailable real adapter returns `manual_action_required`.
- [ ] Persist only encrypted session material and expiry metadata; keep secrets write-only.
- [ ] Use `2Captcha` only for authorized hCaptcha challenges. Handle fingerprint continuity with the same isolated persistent browser profile; never claim CAPTCHA solving bypasses fingerprint checks.
- [ ] Auto-renew an expired session through the bounded login flow; pause auto-swap after provider rejection, CSRF, CAPTCHA, fingerprint, or repeated session errors.
- [ ] Add redaction tests for HTML, logs, audit, exceptions, and database output.

### Task 5: Dedicated admin workspace UX

**Files:** `app/routes/admin.py`, `app/templates/base.html`, `app/templates/admin_proxiware.html`, `app/templates/_proxiware_pagination.html`, `app/static/app.css`, `app/static/app.js`, `tests/test_admin_proxiware_workspace.py`, `tests/test_admin_proxiware_actions.py`

- [ ] Make the menu and all routes direct-linkable, reload-safe, breadcrumbed, and independent of hash-only navigation.
- [ ] Render exactly one `Providers -> Proxiware` sidebar group; remove duplicate provider controls from `Distribution API`, `Transfer Proxy`, and contributor navigation.
- [ ] Link each overview health alert to the exact corrective page: inventory, qualification, sync, queue, session, credentials, policy, or audit.
- [ ] Keep provider pause/resume scoped to Proxiware; prove pausing it does not stop unrelated distribution workers or alter user earnings, uptime, or quota.
- [ ] Add overview cards for inventory, qualification, duplicate, sync, worker, session, queue, blocked, and manual-action states.
- [ ] Add working `Sync now`, `Cancel`, `Test connection`, `Renew session`, `Retry`, `Cancel swap`, and `Pause/Resume` controls with precise confirmations.
- [ ] Keep provider terminology and internal reason codes out of contributor/user pages.
- [ ] Smoke desktop/mobile through Chrome CDP 9222; verify keyboard focus, no horizontal overflow, filters, pagination, disabled states, console, network, and no secret leakage.

### Task 6: Documentation, security sweep, and gate

**Files:** `README.md`, `docs/runbooks/proxiware.md`, `scripts/proxiware_preflight.py`, `tests/test_proxiware_acceptance.py`, `docs/security-audits/run-4/architecture.md`, `docs/security-audits/run-4/REPORT.md`, `docs/security-audits/run-4/FINDINGS-DETAIL.md`, `docs/security-audits/run-4/findings.json`

- [ ] Update stale menu names and describe sync, session recovery, blocked swaps, rollback, and manual-action procedure.
- [ ] Sweep authorization, CSRF, IDOR/provider scoping, SSRF, XSS, SQL/command injection, secret redaction, cache headers, rate limits, distribution fail-closed behavior, and audit integrity.
- [ ] Produce redacted preflight and dry-run reports against a disposable database; prove no provider mutation.
- [ ] Run the complete verification gate:

```powershell
python -m pytest -p no:cacheprovider -q
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m compileall -q app tests scripts
python -m pip check
```

- [ ] Resolve or document the shared-environment `pip check` mismatch; do not hide it.
- [ ] Review diff and secret scan. Commit/push only after all gates pass. Do not deploy or perform a real swap in this plan.

### Task 7: Provider-menu acceptance walkthrough

**Files:** `tests/test_proxiware_acceptance.py`, `docs/runbooks/proxiware.md`, `README.md`

- [ ] Start from a disposable database with provider tables bootstrapped and auto-swap disabled.
- [ ] Walk every direct route in the menu as an admin: overview, inventory, qualification, sync, swaps, swap history, session, credentials, policy, and audit.
- [ ] Verify a non-admin cannot discover provider navigation, provider endpoints, provider identifiers, or internal qualification wording.
- [ ] Verify `Sync now`, `Test connection`, `Renew session`, `Cancel`, `Retry`, `Pause`, and `Resume` show target-specific confirmation, CSRF rejection without a token, bounded rate-limit behavior, safe result text, and audit entries.
- [ ] Verify the workspace remains usable when the API is unavailable, the session expires, a worker heartbeat is stale, a probe is inconclusive, or the browser adapter is unavailable.
- [ ] Verify no action calls purchase, billing, subscription creation, or real swap endpoints during the acceptance run.
- [ ] Record screenshots/log excerpts only after redaction; do not store credentials, cookies, CAPTCHA tokens, fingerprints, or raw provider responses.

## Definition Of Done

- Admin has one coherent, direct-linkable `Providers -> Proxiware` workspace with all ten areas.
- The sidebar has no duplicate or misplaced provider controls, and every alert links to the relevant provider-management page.
- Proxiware pause/resume is isolated from user earnings, online hours, quota, `Distribution API`, `Transfer Proxy`, and other providers.
- Sync, qualification, and swap workers are bounded, durable, observable, and restart-safe.
- Swap execution revalidates every guard immediately before mutation and fails closed on ambiguity.
- Distribution cannot expose duplicate, dead, ambiguous, cooldown, or actively swapping records.
- Credentials/session data never appears in UI, URL, logs, audit, exceptions, or Git.
- Full tests, static checks, browser smoke, security artifacts, and redacted preflight pass.
- No CashPilot change, provider purchase/billing action, VPS mutation, auto-swap enablement, or real swap occurs without separate approval.

## Required Final Report

The implementer must report, in this order: changed files; migrations/schema changes; commands and exact results; security findings by severity; known blockers; deployment status; and manual actions still required. Never report `production-ready` while any required gate is skipped or while the browser adapter remains an unverified mutation path.

## Explicit production gate

Production-ready means the code, tests, security artifacts, runbook, and health checks are complete. It does **not** mean a real provider swap has been executed. Before any live mutation, an operator must separately approve all of the following:

1. One-assignment pilot target and rollback owner.
2. Provider terms/limits and authorized account/session confirmation.
3. Auto-swap remains off until the pilot is reviewed.
4. Backup and rollback verification.
5. Live monitoring of queue, heartbeat, provider response, and distribution exclusion.

If the API has no supported swap endpoint and the browser adapter cannot prove a stable, authorized flow, the correct production state is `manual_action_required`, not a simulated success.
