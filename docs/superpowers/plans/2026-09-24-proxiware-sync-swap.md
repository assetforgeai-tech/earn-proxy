# Proxiware Static ISP Sync and Safe Swap Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Synchronize Proxiware static ISP inventory through the official API, qualify records with the existing checker, and queue provider swaps behind an authenticated session that can renew login automatically.

**Architecture:** Keep the official API client separate from provider inventory persistence. Public API sync owns subscriptions and proxy credentials; the existing health/qualification workers remain the source of live and eligibility truth. A swap job is durable and fail-closed: it can run only when the provider assignment is known, the record is live and risk-qualified, `eligible=true`, `connections<1000`, quota remains, and the replacement cooldown has elapsed. API calls use the official key. Login renewal uses a real browser context, obtains a fresh hCaptcha token through the user's 2Captcha account, obtains `fp`/`fpr` from the real FingerprintJS context (no spoofing), then stores the resulting session encrypted. Provider operations live in a dedicated admin control center (`Admin -> Providers -> Proxiware`) and remain separate from `Distribution API`. This plan assumes the account owner has authorized this automation; it performs swaps only and never purchases.

**Tech Stack:** Python 3.11, Flask, SQLite, `requests`, existing Fernet credential encryption, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never modify `CashPilot`.
- Never commit API keys, email/passwords, browser cookies, CDP state, or 2Captcha keys.
- 2Captcha is used only for the Proxiware login hCaptcha, under the account owner's authorization; never use it to access another account or to defeat unrelated anti-bot controls.
- Fingerprint values must come from the real Proxiware browser context; do not forge, replay, or randomize `fp`/`fpr`.
- Swap automation only. Never call purchase, credit, subscription, or billing mutation endpoints.
- Public Proxiware API authentication uses the `API-KEY` header.
- Do not mark a swap successful before persisting old/new assignment mapping.
- Wait at least 60 seconds after a successful swap before probing the replacement.
- Proxiware operations are admin-only, CSRF-protected, audited, and served with `Cache-Control: no-store`.
- Auto-swap is disabled by default; read-only sync, inspection, and test-connection actions must never mutate provider state.
- User/contributor pages must not expose Proxiware credentials, session details, provider account identifiers, internal qualification signals, or swap controls.

## Dedicated provider control center

The provider has its own operational surface, not a subsection of the distribution API:

| Area | Canonical route | Purpose |
| --- | --- | --- |
| Overview | `/admin/providers/proxiware` | Health, worker, sync, assignment, and swap summary |
| Inventory | `/admin/providers/proxiware/inventory` | Provider subscriptions/assignments with search, filters, sort, pagination |
| Eligibility | `/admin/providers/proxiware/eligibility` | Allow/Risk/Dead/Pending and block reasons |
| Swap queue | `/admin/providers/proxiware/swaps` | Durable swap jobs and guarded retry/cancel actions |
| Sync history | `/admin/providers/proxiware/sync-history` | Run metrics, latency, counts, and redacted errors |
| Credentials & Session | `/admin/providers/proxiware/credentials` | Write-only secrets, connection test, session renewal |
| Settings | `/admin/providers/proxiware/settings` | Auto-swap, threshold, concurrency, retry, cooldown |
| Audit | `/admin/providers/proxiware/audit` | Redacted actor/action/result trail |

Navigation requirements:

- Sidebar group: `Providers`; child item: `Proxiware`.
- `Proxiware` has a distinct active state and breadcrumb on every area.
- Do not duplicate provider actions under `Distribution API`, `Transfer Proxy`, or contributor navigation.
- Every destructive or state-changing action uses a confirmation dialog naming the target and consequence.
- Every list is server-rendered first; JavaScript only enhances filters, progress, and confirmation.
- Empty, loading, stale-session, blocked-worker, API-error, and no-permission states are explicit and actionable.

### Task 1: Official Proxiware API client

**Files:**
- Create: `app/services/proxiware.py`
- Create: `tests/test_proxiware_client.py`
- Modify: `.env.example`

**Interfaces:**
- `ProxiwareClient(api_key: str, base_url: str = "https://api.proxiware.com/v1", timeout: tuple[float, float] = (5, 20))`
- `get_account() -> dict`
- `list_subscriptions(network: str = "isp") -> list[dict]`
- `list_subscription_proxies(subscription_id: int) -> list[dict]`
- `load_api_key_file(path: str) -> str` accepts either raw key text or `PROXIWARE_API_KEY=...`, rejects empty/oversized/multiline values.

- [ ] Write tests for header/auth, response normalization, timeout/error mapping, and secret-safe key-file parsing.
- [ ] Run `python -m pytest tests/test_proxiware_client.py -q` and observe the expected failures.
- [ ] Implement the smallest client using `requests.Session`; never log request headers or response credentials.
- [ ] Re-run the focused tests, then `python -m ruff check app/services/proxiware.py tests/test_proxiware_client.py`.

### Task 2: Durable provider inventory and sync

**Files:**
- Modify: `app/db.py`
- Create: `tests/test_proxiware_sync.py`
- Modify: `app/services/proxiware.py`

**Interfaces:**
- Tables `provider_subscriptions`, `provider_assignments`, and `provider_sync_runs`.
- `sync_proxiware_inventory(db, client, *, now=None) -> SyncResult`.
- Sync is idempotent by `(provider, external_id)`; it updates endpoint metadata without duplicating rows and records counts/errors.

- [ ] Add failing tests for first sync, repeat sync, removed assignment, malformed provider rows, and transaction rollback.
- [ ] Run focused tests and confirm RED.
- [ ] Add schema/migration columns and implement one serialized sync transaction.
- [ ] Run focused tests plus migration tests.

### Task 3: Qualification and swap-job state machine

**Files:**
- Modify: `app/db.py`
- Create: `app/services/proxiware_swap.py`
- Create: `tests/test_proxiware_swap.py`

**Interfaces:**
- `queue_eligible_swaps(db, *, now=None, limit=20) -> int`.
- `SwapDecision` with explicit reasons: `not_live`, `not_risk`, `provider_ineligible`, `connections_limit`, `quota_exhausted`, `cooldown`, `manual_action_required`.
- `mark_swap_success(...)` persists old/new assignment mapping and sets `replacement_ready_at = success_at + 60s`.
- `mark_swap_blocked(...)` pauses retries for login/CAPTCHA/CSRF/quota/stock errors.

- [ ] Write tests for every guard, one active job per subscription, 60-second cooldown, and no blind retry on 409/CAPTCHA.
- [ ] Run focused tests and confirm RED.
- [ ] Implement state transitions only; no browser or CAPTCHA bypass code.
- [ ] Run focused tests and full service tests.

### Task 4: Provider credentials and authenticated browser renewal

**Files:**
- Modify: `app/routes/admin.py`
- Modify: `app/db.py`
- Modify: `app/crypto.py` only if the existing secret helper cannot cover integration settings
- Create: `tests/test_admin_proxiware.py`

**Interfaces:**
- Admin actions: save/clear credentials, test connection, renew session, pause/resume swap worker, and cancel a pending renewal.
- Admin credential form fields:
  - Proxiware login email.
  - Proxiware login password (not mailbox password).
  - Proxiware `API-KEY`.
  - 2Captcha API key.
  - `Enable auto swap`, default `off`.
- Store all four secrets encrypted at rest. Blank update fields preserve the current value; an explicit `Clear` action removes one secret. GET responses and HTML contain only `configured=true/false` and last-four metadata where safe, never plaintext or reversible ciphertext.
- `Test connection` checks the official API key, browser-session renewal prerequisites, and 2Captcha balance without syncing mutations, swapping, purchasing, or changing subscriptions.
- Record only redacted audit events: actor, action, result, timestamp, and safe error code.
- Browser adapter accepts an isolated browser profile/CDP endpoint, loads the login page, submits credentials, requests an hCaptcha solution from 2Captcha, injects only the returned hCaptcha response into the page, obtains `fp`/`fpr` from the page's real FingerprintJS promise, and submits login.
- The adapter stores only encrypted session cookies and expiry metadata; it never persists the CAPTCHA token, password, or raw fingerprint payload.
- CAPTCHA provider timeout, login failure, fingerprint failure, or unexpected challenge returns `manual_action_required` and pauses swaps; bounded retry prevents loops.

- [ ] Write route/service tests for admin-only access, secret redaction, blank-field preservation, explicit clear, default-off auto swap, blocked-state display, CSRF protection, test-connection no-mutation behavior, and renewal status.
- [ ] Run focused tests and confirm RED.
- [ ] Implement the smallest credential/session service and admin POST routes; keep GET handlers side-effect free.
- [ ] Run route/service tests and the full test suite.

### Task 5: Dedicated Proxiware provider workspace

**Files:**
- Modify: `app/routes/admin.py`
- Modify: `app/templates/base.html`
- Create: `app/templates/admin_proxiware.html`
- Modify: `app/static/app.css`
- Modify: `app/static/app.js` only for progressive enhancement; core navigation, filters, and forms must work without JavaScript
- Modify: `app/__init__.py`
- Create: `tests/test_admin_proxiware_workspace.py`

**Interfaces:**
- Add a distinct admin navigation group and item: `Providers` → `Proxiware`; do not place provider operations under `Distribution API`.
- Canonical route: `GET /admin/providers/proxiware` plus stable area URLs listed in the dedicated provider control-center contract; if a query-tab fallback is retained, accept only the fixed allow-list `overview`, `inventory`, `eligibility`, `swaps`, `history`, `credentials`, `settings`, `audit`.
- Overview shows session health, worker state, auto-swap state, last successful sync/check, assignment counts, queued/blocked swaps, last safe error, and badges `Healthy`, `Session expired`, `Blocked`, or `Needs attention`.
- Inventory supports count cards, search, server-side filters, sorting, pagination, and page-size selection. Filters cover subscription, live state, qualification, country, replacement readiness, and provider eligibility. Never select or render encrypted credential columns.
- Eligibility groups `Allow`, `Risk`, `Dead`, `Pending`, `Eligible < 1000`, cooldown, duplicate egress, and blocked reasons without exposing internal EarnApp wording to contributors.
- Swap queue shows old/new assignment mapping, pending/running/success/blocked state, attempts, cooldown/ready time, safe error code, and explicit confirmation for retry/cancel/manual-swap actions.
- Sync history shows added/updated/missing/error counts, duration, start/finish time, and redacted errors.
- Credentials & Session hosts the fields and actions from Task 4; secrets remain write-only.
- Settings exposes only required controls: auto-swap enabled, eligibility threshold default `1000`, worker concurrency, bounded retry count, and cooldown fixed to at least `60` seconds.
- Audit shows actor, action, safe target identifier, result, and timestamp; never request/response bodies or secrets.
- Add prominent read-only actions: `Sync now`, `Test connection`, and `Refresh status`; show progress/result inline without page-wide spinner lockups.
- Keep provider inventory separate from the platform's user proxy table; only normalized assignment IDs and safe operational fields may cross that boundary.
- Show a visible banner when the provider API exposes no swap endpoint and the browser-backed swap adapter is unavailable; fail closed with `manual_action_required`.
- Every page is admin-only, responsive, keyboard accessible, and uses `Cache-Control: no-store`.

- [ ] Write failing navigation, route, tab, count, filter, sort, pagination, no-secret-query, confirmation, responsive-contract, and accessibility tests.
- [ ] Run `python -m pytest tests/test_admin_proxiware_workspace.py -q` and confirm RED.
- [ ] Add the `Providers` navigation item and minimal server-rendered workspace using existing TailAdmin visual patterns.
- [ ] Implement one shared validated query/pagination helper; do not add a client-side data grid or new UI dependency.
- [ ] Verify every tab, empty state, error state, and dangerous action confirmation.
- [ ] Re-run focused tests, browser smoke at desktop/mobile widths, then the full UI test set.

### Task 6: Worker wiring and deployment configuration

**Files:**
- Create: `app/proxiware_sync_service.py`
- Create: `deploy/earn-proxy-proxiware.service`
- Modify: `docker-compose.yml`
- Modify: `.env.example`
- Modify: `README.md`
- Create: `tests/test_proxiware_service.py`

- [ ] Add failing tests for one-shot sync, graceful API failure, stop/restart, renewal retry bounds, 2Captcha response handling, fingerprint handoff, and no secret output.
- [ ] Implement restartable worker with bounded interval and durable claims.
- [ ] Add systemd/Compose configuration with least privilege and no browser cookie mounts by default.
- [ ] Run full verification: `python -m pytest -q`, `python -m ruff check app tests scripts`, `python -m ruff format --check app tests scripts`, `python -m compileall -q app tests scripts`, `python -m pip check`.

### Task 7: End-to-end audit and production gate

**Files:**
- Create: `docs/runbooks/proxiware.md`
- Create: `tests/test_proxiware_acceptance.py`
- Modify: `README.md`

**Interfaces:**
- `run_proxiware_preflight(app) -> PreflightReport` returns only safe checks and redacted findings.
- `run_proxiware_dry_run(app) -> DryRunReport` exercises sync, qualification, queue guards, UI route access, and worker restart without calling a swap mutation.

- [ ] Write acceptance tests proving the complete admin navigation path, all eight provider areas, secret redaction, no user-page leakage, idempotent sync, one active job per subscription, threshold/cooldown guards, and auto-swap default OFF.
- [ ] Add a runbook covering environment variables, migrations, service start/stop, health checks, rollback, session renewal, blocked-state recovery, and the explicit approval required before the first real swap.
- [ ] Run preflight and dry-run against a disposable SQLite database with mocked Proxiware, 2Captcha, and browser adapters.
- [ ] Run browser smoke tests at desktop/mobile widths; verify keyboard navigation, focus order, confirmation dialogs, no-store headers, and no secret values in HTML, logs, or query strings.
- [ ] Only after all checks pass, produce a deployment checklist. Do not perform a production swap as part of this task.

## Explicit non-goals

- No purchase or billing automation.
- No fingerprint spoofing or CAPTCHA handling for accounts without owner authorization.
- No automatic production swap until one assignment is piloted and provider quota/terms are confirmed in writing.
- No deployment or VPS mutation in this plan.

## Acceptance criteria

- [ ] `Admin -> Providers -> Proxiware` is visible only to admins and is independent from `Distribution API`.
- [ ] Admin can inspect provider health, inventory, eligibility, swap queue, sync history, credentials/session, settings, and audit from dedicated areas.
- [ ] Sync is idempotent, restart-safe, transactionally consistent, and never logs secrets.
- [ ] A swap is queued only when all live/qualification/provider/quota/connection/cooldown guards pass; otherwise a durable safe reason is shown.
- [ ] Auto-swap defaults to OFF and any session/CAPTCHA/CSRF/fingerprint failure pauses it without an infinite retry loop.
- [ ] No purchase, billing, subscription creation, renewal, CashPilot modification, or real production swap occurs during implementation or dry-run.

## Execution Addendum (continuation checkpoint)

This addendum is the authoritative continuation order for the current working tree. Existing implementation may be incomplete; do not assume a green focused test means the feature is production-ready.

### Task 8: Bootstrap schema and normalize settings

**Files:**
- Modify: `app/db.py`
- Modify: `app/services/proxiware.py`
- Modify: `app/services/proxiware_swap.py`
- Modify: `app/services/proxiware_credentials.py`
- Create: `tests/test_proxiware_bootstrap.py`

**Required outcome:** every application/worker initialization path creates or migrates all Proxiware tables before the first query. Use only these canonical keys: `proxiware_auto_swap`, `proxiware_eligible_threshold`, `proxiware_worker_concurrency`, `proxiware_retry_limit`, and `proxiware_cooldown_seconds`. Read legacy keys only during a one-time migration, then stop writing them.

- [ ] Test a fresh database, an existing database with only legacy keys, and a partially created schema.
- [ ] Make initialization idempotent and transactional; no request may fail because a provider table is absent.
- [ ] Verify `python -m pytest tests/test_proxiware_bootstrap.py -q` before continuing.

### Task 9: Complete safe admin actions and sync execution

**Files:**
- Modify: `app/routes/admin.py`
- Modify: `app/proxiware_sync_service.py`
- Create: `tests/test_admin_proxiware_actions.py` (extend existing tests)
- Create: `tests/test_proxiware_sync_route.py`

**Required outcome:** implement `POST /admin/providers/proxiware/sync` as an admin-only, CSRF-protected, explicit read-only sync action. GET requests must never create a run, claim a job, or call the provider. `Test connection` must call only read-only dependency checks. `Renew session` must use the injected browser adapter or return durable `manual_action_required`; never return a fake success.

- [ ] Test CSRF, authorization, redirect/error behavior, no-mutation GET, idempotent repeated sync, and redacted errors.
- [ ] Use a bounded request/worker handoff; a second sync for the same provider returns a safe `already_running` result instead of spawning a loop.
- [ ] Keep action results visible in the workspace without a page-wide spinner lockup.

### Task 10: Connect provider assignments to qualification truth

**Files:**
- Modify: `app/services/proxiware.py`
- Modify: existing checker/qualification integration module identified by repository search
- Modify: `app/routes/admin.py`
- Create: `tests/test_proxiware_qualification_integration.py`

**Required outcome:** each normalized provider assignment receives a durable live state and qualification state from the existing checker. Map only safe public classes (`Allow`, `Risk`, `Dead`, `Pending`) to the provider workspace. `Allow` is never queued for swap; `Risk` may be queued only when every guard passes; `Dead`, `Pending`, inconclusive, duplicate-egress, and unknown results are not auto-swappable.

- [ ] Test stale probe, timeout, captive portal, duplicate egress, inconclusive result, and provider `eligible < 1000`.
- [ ] Preserve provider inventory when a probe is inconclusive; do not silently delete or mark it `Dead`.
- [ ] Ensure contributor/user pages cannot infer the internal checker/provider name from HTML, JSON, logs, or error text.

### Task 11: Implement the authorized browser/session boundary

**Files:**
- Create: `app/services/proxiware_browser.py`
- Modify: `app/services/proxiware_credentials.py`
- Modify: `app/routes/admin.py`
- Create: `tests/test_proxiware_browser.py`

**Required outcome:** provide an injectable interface for an isolated, headless browser context. The real adapter may log in only to the configured account, use the configured 2Captcha account for the provider's hCaptcha challenge, obtain `fp`/`fpr` from the real page context, and persist only encrypted session cookies plus expiry metadata.

- [ ] Test successful renewal with a fake adapter, timeout, provider rejection, missing fingerprint, expired session, and CAPTCHA failure.
- [ ] Fail closed to `manual_action_required`; pause auto-swap; enforce bounded retries and a cooldown.
- [ ] Never persist or log password, CAPTCHA token, raw fingerprint payload, CDP state, or cookie plaintext.

### Task 12: Finish guarded swap execution

**Files:**
- Modify: `app/services/proxiware_swap.py`
- Create: `app/proxiware_swap_service.py`
- Modify: `docker-compose.yml`
- Create: `tests/test_proxiware_swap_service.py`

**Required outcome:** a restart-safe worker executes only an already-approved swap job through an injected browser/provider adapter. It must not purchase, renew, create subscriptions, change billing, or call undocumented mutation endpoints. Persist old/new mapping before `success`; set replacement readiness to `success_at + 60s` (or the configured value, never below 60s).

- [ ] Test one active job per subscription, claim recovery, retry limit, cancellation, pause/resume, provider 409/quota/stock, and process restart.
- [ ] On session/CSRF/CAPTCHA/fingerprint errors, mark `manual_action_required`, disable auto-swap, and stop retrying.
- [ ] Add a dry-run adapter that records intended calls without reaching Proxiware.

### Task 13: Complete the dedicated provider control center

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin_proxiware.html`
- Modify: `app/static/app.css`
- Modify: `app/static/app.js`
- Modify: `app/routes/admin.py`
- Create/extend: `tests/test_admin_proxiware_workspace.py`

**Required outcome:** `Admin -> Providers -> Proxiware` is a first-class menu with eight stable areas, not a tab hidden inside `Distribution API`. Inventory, eligibility, swap queue, sync history, credentials/session, settings, and audit all support server-side count, filter, sort, pagination, and explicit empty/error/stale/blocked states.

- [ ] Add working `Sync now`, `Test connection`, `Renew session`, `Retry`, `Cancel`, and `Pause/Resume` actions with target-specific confirmation dialogs.
- [ ] Ensure action buttons are usable with keyboard and without JavaScript where safe; state-changing actions remain disabled until confirmation is available.
- [ ] Verify desktop and mobile layouts, no-store headers, no secret values in HTML/query strings, and no internal provider terminology on user pages.

### Task 14: Acceptance, security sweep, and deployment gate

**Files:**
- Modify: `docs/runbooks/proxiware.md`
- Create: `tests/test_proxiware_acceptance.py`
- Create: `scripts/proxiware_preflight.py`
- Modify: `README.md`

**Required outcome:** produce a redacted preflight report and a dry-run report before any production mutation. The reports must cover schema, settings, credentials configuration state, API read access, worker health, route authorization, secret redaction, and rollback readiness.

- [ ] Run focused tests, then the complete suite and static checks:
  `python -m pytest -q`
  `python -m ruff check app tests scripts`
  `python -m ruff format --check app tests scripts`
  `python -m compileall -q app tests scripts`
  `python -m pip check`
- [ ] Run browser smoke tests at desktop/mobile widths and inspect logs for credentials, cookies, CAPTCHA tokens, API keys, and fingerprint payloads.
- [ ] Commit only after all checks pass; push the feature branch; provide a deployment checklist and stop before real swap/purchase/billing/VPS mutation.

### Continuation completion gate

The continuation is complete only when all tasks above are checked, the full verification commands pass, the provider workspace is reachable through the dedicated menu, the worker can stop/restart without duplicate jobs, and the dry-run proves that no provider mutation is made. A production swap requires a separate explicit approval after the dry-run and a single-assignment pilot.
