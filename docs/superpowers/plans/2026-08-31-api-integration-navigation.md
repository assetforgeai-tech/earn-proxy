# API Integration and Admin Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Give external systems a clear, stable proxy API endpoint and replace the admin long-page/fragment experience with professional route-based navigation while preserving existing API and form compatibility.

**Architecture:** Keep the current authenticated distribution query and response formats in one shared view function. Expose `/api/v1/proxies` as the canonical machine endpoint and retain `/internal/api/v1/proxies` as a compatibility alias. Add an admin-only integration page that documents authentication, text/JSON formats, filtering, freshness, and safe copyable examples; add route-based admin pages for checker, users, and payouts while retaining `/admin` as the existing overview/backward-compatible page.

**Tech Stack:** Flask blueprints, Jinja2 templates, vanilla CSS/JavaScript, pytest Flask test client.

## Global Constraints

- Preserve the existing `/internal/api/v1/proxies` URL, `X-API-Key` authentication, newline-delimited text response, and JSON response fields.
- Never render the real API key, proxy credentials, wallet addresses, or other secrets in HTML, logs, tests, or documentation.
- Canonical API output remains limited to active users, online canonical proxies, enabled `Allow`/`Risk` classes, and fresh successful health checks.
- Admin pages remain protected by `admin_required`; anonymous and contributor users must not see integration details.
- Keep changes confined to `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; do not change CashPilot or production data directly during local implementation.
- Use semantic labels, keyboard-accessible controls, visible focus, responsive layout, and no new frontend framework/dependency.

### Task 1: Define API and navigation contracts with failing tests

**Files:**
- Modify: `tests/test_internal_api.py`
- Create: `tests/test_admin_integrations.py`
- Modify: `tests/test_ui_hardening.py`

**Interfaces:**
- `/api/v1/proxies` must return the same payload as `/internal/api/v1/proxies` for the same key and query string.
- `/admin/integrations`, `/admin/checker`, `/admin/users`, and `/admin/payouts` must require an admin session and render route-specific headings.
- Admin navigation must use route URLs and expose an `API & integrations` link; no new navigation link may target `#checker-policy`.

- [ ] **Step 1: Write failing tests**

Add assertions for canonical/legacy API parity, unauthorized canonical API access, admin-only integration access, integration-page endpoint/header/format guidance without a literal configured key, route-specific headings, and clean navigation links.

- [ ] **Step 2: Run focused tests to verify RED**

Run: `python -m pytest tests/test_internal_api.py tests/test_admin_integrations.py tests/test_ui_hardening.py -q`

Expected: failures report the missing canonical route, integration page, route-specific pages, and navigation contract.

### Task 2: Add canonical API alias and shared API metadata

**Files:**
- Modify: `app/routes/internal_api.py`
- Modify: `app/__init__.py` only if blueprint registration is required
- Modify: `README.md`

**Interfaces:**
- `GET /api/v1/proxies` and `GET /internal/api/v1/proxies` call the same authenticated implementation.
- `X-API-Key` remains the only credential; invalid/missing keys return HTTP 401.
- `format=json` continues to return the existing list fields; default format remains newline-delimited text.

- [ ] **Step 1: Implement one shared view across both prefixes**

Register a canonical `/api/v1` blueprint and a legacy `/internal/api/v1` blueprint around the same function, preserving query filtering and response MIME types. Add `Cache-Control: no-store` to distribution responses so credentials are not cached by intermediaries.

- [ ] **Step 2: Update API documentation**

Document the canonical endpoint first, mark the internal path as a compatibility alias, and show redacted curl/Python examples that use an environment variable for the key.

- [ ] **Step 3: Run API tests to verify GREEN**

Run: `python -m pytest tests/test_internal_api.py -q`

Expected: all existing API tests plus the canonical parity tests pass.

### Task 3: Add admin route pages and integration documentation

**Files:**
- Modify: `app/routes/admin.py`
- Modify: `app/templates/admin_dashboard.html`
- Create: `app/templates/admin_integrations.html`
- Create: `app/templates/admin_section.html` if route-specific rendering needs a shared shell

**Interfaces:**
- `admin.integrations`, `admin.checker`, `admin.users`, and `admin.payouts` are GET endpoints protected by `admin_required`.
- Integration page receives the canonical endpoint URL, legacy endpoint URL, and safe example snippets; it never receives `INTERNAL_API_KEY`.
- Existing `/admin` continues to render all legacy sections so existing bookmarks/tests remain valid.

- [ ] **Step 1: Add failing-page data contract and route handlers**

Create route handlers that load only the data needed by each page and build the endpoint from `request.host_url` plus `/api/v1/proxies`; use HTTPS-aware URL construction behind the reverse proxy.

- [ ] **Step 2: Add integration page content**

Render a clear “API & integrations” page with endpoint, required header, text/JSON format cards, `Allow`/`Risk` behavior, freshness rule, a redacted curl example, and copy buttons that copy only examples/URLs.

- [ ] **Step 3: Replace fragment-only admin links**

Change the admin navigation to link to `/admin`, `/admin/checker`, `/admin/users`, `/admin/payouts`, and `/admin/integrations`; retain section IDs in the legacy full page for old bookmarks but do not use them as primary navigation.

- [ ] **Step 4: Verify focused UI tests**

Run: `python -m pytest tests/test_admin_integrations.py tests/test_ui_hardening.py tests/test_admin_ui.py tests/test_browser_forms.py -q`

Expected: route protection, headings, forms, existing controls, and navigation assertions pass.

### Task 4: Polish integration-page interaction and responsive presentation

**Files:**
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`
- Modify: `app/templates/base.html`

**Interfaces:**
- Copy controls expose accessible labels and announce success/failure through an `aria-live` status region.
- Copy behavior degrades gracefully when the Clipboard API is unavailable.
- Layout remains usable at 375px and desktop widths without horizontal overflow.

- [ ] **Step 1: Add copy interaction tests/contracts**

Assert copy buttons have `type="button"`, `data-copy-target`, accessible labels, and a live status region; preserve existing form/dialog behavior.

- [ ] **Step 2: Implement minimal copy helper and styles**

Use the existing vanilla script, avoid exposing secrets, style endpoint/code cards, and add reduced-motion-safe feedback.

- [ ] **Step 3: Run UI smoke checks**

Run: `python -m pytest tests/test_ui_hardening.py tests/test_admin_integrations.py -q` and `python scripts/smoke_ui.py` against the local app.

### Task 5: Full verification, browser audit, and deployment decision

**Files:**
- No additional files unless a narrowly scoped verification regression is found.

- [ ] **Step 1: Run complete verification**

Run: `python -m pytest -q`, `python -m ruff check app tests scripts`, `python -m ruff format --check app tests scripts`, `python -m compileall -q app tests scripts`, `python -m pip check`, and `git diff --check`.

- [ ] **Step 2: Audit with Chrome Profile 40**

Open the admin dashboard and `/admin/integrations`, verify route URLs, copy controls, access restrictions, console errors, mobile/desktop overflow, and that no secret appears in rendered HTML.

- [ ] **Step 3: Review deployment boundary**

Inspect the final diff and report local evidence separately from production status. Deploy only through the existing release/rollback procedure, then verify `/api/v1/proxies`, the legacy alias, and the production integration page before claiming production completion.
