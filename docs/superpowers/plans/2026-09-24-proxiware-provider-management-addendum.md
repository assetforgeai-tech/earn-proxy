# Proxiware Provider Management Addendum Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the dedicated Proxiware admin workspace, safe provider actions, guarded swap automation, verification, and production gate without changing CashPilot.

**Architecture:** Keep `Providers -> Proxiware` separate from `Distribution API` and contributor pages. Use the official API for read-only inventory sync; use injected browser/CAPTCHA adapters only for the configured account session and authorized swap flow. Keep durable SQLite state, encrypted secrets, bounded retries, fail-closed errors, and explicit operator controls.

**Tech Stack:** Python 3.11, Flask, SQLite, requests, existing Fernet helpers, pytest, existing TailAdmin-compatible HTML/CSS/JavaScript.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never modify `D:\1. WORK_true\CashPilot`.
- Continue the current dirty feature branch; inspect and preserve all existing work. Never reset, checkout, or overwrite unrelated changes.
- Never commit or display Proxiware email/password, API keys, 2Captcha key, cookies, CAPTCHA tokens, CDP data, or raw fingerprint values.
- Auto-swap defaults to OFF. GET requests remain side-effect free.
- Official API sync is read-only. Never automate purchase, billing, renewal, subscription creation, or account changes.
- Browser session renewal may use 2Captcha only for the configured owner's Proxiware login. Obtain fingerprint values from the real page context; never forge, randomize, or replay them.
- A real provider swap is outside this implementation run. Stop after mocked dry-run and deployment readiness; require separate explicit approval for a single-assignment pilot.
- Follow TDD: failing focused test, minimal implementation, passing focused test, then broader verification.

---

## Menu And Route Contract

| Area | Canonical route | Required behavior |
| --- | --- | --- |
| Overview | `/admin/providers/proxiware` | Health, last sync/check, worker/session state, counts, safe error |
| Inventory | `/admin/providers/proxiware/inventory` | Search, filters, sort, count, page size, pagination |
| Eligibility | `/admin/providers/proxiware/eligibility` | Allow/Risk/Dead/Pending, provider eligibility, duplicate egress, cooldown, block reason |
| Swap queue | `/admin/providers/proxiware/swaps` | Durable state, old/new mapping, attempts, retry/cancel confirmation |
| Sync history | `/admin/providers/proxiware/sync-history` | Start/end, duration, added/updated/missing/errors, redacted result |
| Credentials & session | `/admin/providers/proxiware/credentials` | Write-only secrets, connection test, session renewal, status |
| Settings | `/admin/providers/proxiware/settings` | Threshold, concurrency, retry, cooldown, auto-swap |
| Audit | `/admin/providers/proxiware/audit` | Actor/action/target/result/time; no secret payload |

### Task 1: Complete Safe Admin Actions

**Files:**
- Modify: `app/routes/admin.py`
- Test: `tests/test_admin_proxiware_actions.py`

**Interfaces:**
- `POST /admin/providers/proxiware/sync`
- `POST /admin/providers/proxiware/test-connection`
- `POST /admin/providers/proxiware/renew-session`

- [ ] Run `python -m pytest tests/test_admin_proxiware_actions.py -q` and preserve the current failing evidence.
- [ ] Implement sync using only `get_provider_secret(db, "api_key")`, `ProxiwareClient`, and `sync_proxiware_inventory`; missing keys fail closed.
- [ ] Wire connection tests through `current_app.extensions["proxiware_api_client_factory"]` and `current_app.extensions["proxiware_captcha_adapter_factory"]`; return only `api_ok`, `captcha_ok`, `captcha_balance`, and safe `error_code`.
- [ ] Wire session renewal through injected browser/CAPTCHA adapters; missing adapters return HTTP 503 and `manual_action_required`, never fake success.
- [ ] Require admin authorization and CSRF; audit only safe action/result/error metadata; set `Cache-Control: no-store`.
- [ ] Re-run the focused test until PASS.
- [ ] Commit: `feat: complete safe Proxiware admin actions`.

### Task 2: Normalize Schema And Settings Bootstrap

**Files:**
- Modify: `app/db.py`
- Modify: `app/services/proxiware.py`
- Modify: `app/services/proxiware_swap.py`
- Modify: `app/services/proxiware_credentials.py`
- Create: `tests/test_proxiware_bootstrap.py`

**Interfaces:**
- One idempotent bootstrap path for every Proxiware table and index.
- Canonical settings: `proxiware_auto_swap`, `proxiware_eligible_threshold`, `proxiware_worker_concurrency`, `proxiware_retry_limit`, `proxiware_cooldown_seconds`.

- [ ] Test fresh, legacy, and partially migrated databases.
- [ ] Remove dual writes to legacy setting names after a one-time compatibility read/migration.
- [ ] Ensure app and worker startup complete schema creation before queries.
- [ ] Run `python -m pytest tests/test_proxiware_bootstrap.py tests/test_proxiware_swap.py -q`.
- [ ] Commit: `fix: normalize Proxiware bootstrap state`.

### Task 3: Connect Inventory To Existing Qualification Truth

**Files:**
- Modify: `app/services/proxiware.py`
- Modify: the existing checker integration located by repository search
- Modify: `app/routes/admin.py`
- Create: `tests/test_proxiware_qualification_integration.py`

**Interfaces:**
- Safe admin states: `Allow`, `Risk`, `Dead`, `Pending`.
- Auto-swap candidate: live + `Risk` + provider eligible + eligible count below configured threshold + connections below 1000 + quota + cooldown.

- [ ] Test live, timeout, captive portal, duplicate egress, inconclusive, stale probe, unknown, and provider eligibility edge cases.
- [ ] Preserve inventory on inconclusive probes; never convert inconclusive directly to `Dead`.
- [ ] Prove `Allow` never queues; `Dead`, `Pending`, duplicate egress, inconclusive, and unknown never auto-swap.
- [ ] Verify no Proxiware/checker/internal qualification wording leaks to user pages, JSON, or logs.
- [ ] Commit: `feat: connect Proxiware qualification state`.

### Task 4: Implement The Authorized Session Boundary

**Files:**
- Create: `app/services/proxiware_browser.py`
- Modify: `app/services/proxiware_credentials.py`
- Modify: `app/routes/admin.py`
- Create: `tests/test_proxiware_browser.py`

**Interfaces:**
- Browser adapter renews only the configured account session.
- CAPTCHA adapter solves only the current login challenge.
- Persistence contains encrypted session cookies and expiry metadata only.

- [ ] Test successful fake renewal, timeout, provider rejection, CAPTCHA failure, missing real-page fingerprint, expired session, and unexpected challenge.
- [ ] Use an isolated headless browser context; obtain `fp`/`fpr` from the page's own runtime.
- [ ] Enforce bounded retries and cooldown. Any CAPTCHA/CSRF/login/session/fingerprint failure sets `manual_action_required`, disables auto-swap, and stops the loop.
- [ ] Scan logs, database rows, HTML, and exceptions for password, keys, tokens, cookies, CDP data, and fingerprint payloads.
- [ ] Commit: `feat: add guarded Proxiware session renewal`.

### Task 5: Finish Restart-Safe Swap Worker

**Files:**
- Modify: `app/services/proxiware_swap.py`
- Create: `app/proxiware_swap_service.py`
- Modify: `docker-compose.yml`
- Modify: `deploy/earn-proxy-proxiware.service`
- Create: `tests/test_proxiware_swap_service.py`

**Interfaces:**
- Durable claim token and lease.
- One active job per subscription.
- Old/new mapping persisted before success.
- Replacement probe readiness at least 60 seconds after success.

- [ ] Test claim recovery, stale worker rejection, retry limit, cancel, pause/resume, process restart, quota/stock/conflict/session/CAPTCHA failures, and duplicate worker startup.
- [ ] Execute swaps only through an injected adapter. Never call undocumented purchase/billing/subscription mutations.
- [ ] Add dry-run mode recording intended operations without contacting the provider mutation flow.
- [ ] Verify systemd/Compose restart policy avoids duplicate workers and crash loops.
- [ ] Commit: `feat: add restart-safe Proxiware swap worker`.

### Task 6: Finish Dedicated Provider Workspace UX

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin_proxiware.html`
- Modify: `app/templates/_proxiware_pagination.html`
- Modify: `app/static/app.css`
- Modify: `app/static/app.js`
- Modify: `app/routes/admin.py`
- Test: `tests/test_admin_proxiware_workspace.py`

**Interfaces:**
- First-class sidebar group `Providers` and item `Proxiware`.
- Eight stable areas from the route contract.
- One validated server-side search/filter/sort/pagination model.

- [ ] Test active navigation, breadcrumb, all routes, counts, search, filters, sorting, page size, pagination, preserved query state, empty/error/stale/blocked states, and secret-free SELECT/rendering.
- [ ] Add working `Sync now`, `Test connection`, `Renew session`, `Retry`, `Cancel`, and `Pause/Resume` actions with target-specific confirmations.
- [ ] Show inline progress/result; never lock the page with a global spinner.
- [ ] Verify keyboard operation, focus visibility, labels, responsive tables, desktop/mobile layout, and safe no-JavaScript degradation.
- [ ] Keep provider operations absent from `Distribution API`, `Transfer Proxy`, and contributor navigation.
- [ ] Commit: `feat: finish Proxiware provider workspace`.

### Task 7: Audit, Dry-Run, Commit, And Deployment Gate

**Files:**
- Modify: `docs/runbooks/proxiware.md`
- Create: `scripts/proxiware_preflight.py`
- Create: `tests/test_proxiware_acceptance.py`
- Modify: `README.md`

**Interfaces:**
- Redacted preflight report.
- Mocked dry-run report proving no provider mutation.
- Deployment checklist; no real swap.

- [ ] Run focused tests, then `python -m pytest -q`.
- [ ] Run `python -m ruff check app tests scripts`.
- [ ] Run `python -m ruff format --check app tests scripts`.
- [ ] Run `python -m compileall -q app tests scripts`.
- [ ] Run `python -m pip check`.
- [ ] Browser-smoke every Proxiware area at desktop and mobile widths; inspect browser console and server logs.
- [ ] Scan repository and generated output for secrets, cookies, CAPTCHA tokens, CDP data, and fingerprint payloads.
- [ ] Run preflight and mocked dry-run against a disposable database. Prove GET is side-effect free, auto-swap defaults OFF, worker restart does not duplicate jobs, and no provider mutation occurs.
- [ ] Review the complete diff, commit in logical units, push the feature branch, and report exact verification evidence.
- [ ] Stop before VPS deployment or real swap unless separately authorized. If deployment is later authorized, deploy with auto-swap OFF, verify health/rollback, then stop before the single-assignment pilot.

## Acceptance Criteria

- [ ] Dedicated `Providers -> Proxiware` menu works for admins only.
- [ ] All eight areas are functional, responsive, searchable/filterable where relevant, and secret-safe.
- [ ] Read-only sync is idempotent; GET never mutates.
- [ ] Credential/session values remain encrypted and write-only.
- [ ] Guarded queue logic never swaps Allow, Dead, Pending, duplicate-egress, inconclusive, or unknown records.
- [ ] Worker is restart-safe, bounded, auditable, and cannot report success without old/new mapping.
- [ ] Full tests/static checks/browser smoke/security scan pass.
- [ ] No CashPilot edit, purchase, billing change, subscription mutation, VPS change, or real swap occurs without separate approval.
