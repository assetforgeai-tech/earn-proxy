# UI/UX Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the Earn Proxy contributor and admin dashboards clearer, safer, accessible, and usable on small screens without changing proxy, earnings, or authentication business rules.

**Architecture:** Keep Flask routes and SQLite domain services intact. Add a small presentation layer for request error metadata, shared accessible confirmation dialogs, and progressive form feedback; expose only existing safe fields plus check freshness timestamps. Use semantic HTML and a token-based responsive stylesheet, with JavaScript limited to form state/focus/dialog behavior and graceful no-JS fallbacks.

**Tech Stack:** Flask/Jinja2, vanilla JavaScript, CSS, pytest, Flask test client, Playwright smoke script.

## Global Constraints

- Preserve credential masking; never render proxy usernames, passwords, raw wallet addresses, or internal eligibility details to contributor users.
- Preserve JSON/API response contracts and existing proxy/earnings/authentication behavior.
- Keep production changes confined to `D:\1. WORK_true\Tranfer Proxy\earn-proxy`.
- Use semantic labels, keyboard access, visible focus, and WCAG AA-compatible contrast.
- Destructive actions must have an accessible in-page confirmation dialog and remain safe when JavaScript is unavailable.
- Do not add a frontend framework or backend dependency.

### Task 1: Define presentation contracts with failing tests

**Files:**
- Create: `tests/test_ui_hardening.py`
- Modify: `tests/test_registration_pages.py`

**Interfaces:**
- Tests define the required response status/page structure for branded errors, field-level error metadata, form busy state, confirmation dialogs, table semantics, freshness labels, and dashboard navigation anchors.

- [x] **Step 1: Write failing tests**

Add tests that request missing pages and unauthorized/forbidden routes, submit invalid browser forms, and inspect dashboard HTML for semantic and interaction contracts. Assert, at minimum, that 401/403/404 responses contain a branded heading and a route-appropriate recovery link; invalid login/register pages contain an error summary plus `aria-invalid` and `aria-describedby`; forms expose `data-loading-label` and a submit guard hook; destructive forms use `data-confirm-dialog` and no inline `confirm(`; tables contain captions and scoped headers; dashboards contain `Last checked`, `Next check`, stale-state markup, and navigation anchors.

- [x] **Step 2: Run the focused tests and verify RED**

Run `pytest tests/test_ui_hardening.py tests/test_registration_pages.py -q`.
Expected result: the new assertions fail because the current templates and error handlers do not provide these contracts.

### Task 2: Add branded errors and browser form error metadata

**Files:**
- Create: `app/templates/error.html`
- Modify: `app/__init__.py`
- Modify: `app/routes/forms.py`
- Modify: `app/routes/auth.py`

**Interfaces:**
- `form_error()` continues returning the same JSON status/payload for non-browser callers.
- Browser redirects carry a flash message and query-safe `error_field`/`error_focus` metadata consumed by the form templates.
- Error handlers render `error.html` with `status_code`, `title`, `message`, and `recovery_endpoint`.

- [x] **Step 1: Implement status handlers**

Register handlers for 401, 403, and 404 that render the branded error template. Preserve JSON responses for requests advertising JSON.

- [x] **Step 2: Implement field metadata**

Extend browser error redirects with optional `field` and `focus` values. Update auth validation/authentication branches to identify the relevant field while preserving existing messages and API status codes.

- [x] **Step 3: Add the shared error template and verify focused tests**

Render a clear heading, explanation, status code, recovery link, and `role="alert"` message. Run `pytest tests/test_ui_hardening.py -q` and confirm the new error/form assertions pass.

### Task 3: Harden forms, confirmations, navigation, and freshness presentation

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/login.html`
- Modify: `app/templates/register.html`
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/templates/admin_dashboard.html`
- Create: `app/static/app.js`
- Modify: `app/__init__.py`

**Interfaces:**
- Base layout provides `#main-content`, a skip link, flash error summary, and a single reusable confirmation dialog.
- All state-changing UI forms use `data-submit-once`; buttons expose `data-loading-label` and restore their label after navigation/error.
- `app.js` enhances forms/dialogs only when JavaScript is available; it must not alter JSON/API requests.

- [x] **Step 1: Add semantic labels and error anchors**

Replace screen-reader-only primary labels with visible labels, associate help/error text through `aria-describedby`, and apply `aria-invalid` when a field is the focus target from a browser redirect.

- [x] **Step 2: Add progressive loading and duplicate-submit protection**

Add `data-submit-once`, `aria-busy`, and explicit loading labels to login, registration, wallet, payout, proxy, and admin forms. Disable only the submitted form's controls after validation succeeds.

- [x] **Step 3: Replace native confirmations**

Add one accessible `<dialog>` with cancel/confirm buttons. Destructive forms point to it using `data-confirm-dialog` and carry a descriptive confirmation message; the script submits the original form only after confirmation.

- [x] **Step 4: Add navigation and freshness UI**

Add dashboard section navigation/anchors, explanatory metric text, semantic table captions/scoped headers, and per-proxy `Last checked`/`Next check` labels with a stale class when the stored health result is old or absent. Keep contributor-facing labels limited to safe status/protocol fields.

- [x] **Step 5: Run focused tests and refactor only while green**

Run `pytest tests/test_ui_hardening.py tests/test_browser_forms.py tests/test_ui_contract.py tests/test_admin_stats.py -q`.

### Task 4: Improve responsive visual system

**Files:**
- Modify: `app/static/app.css`

**Interfaces:**
- Preserve the existing green/ink visual language while introducing readable tokens, responsive cards/tables, clear disabled/focus states, and reduced-motion behavior.

- [x] **Step 1: Replace the one-line stylesheet with formatted tokenized CSS**

Keep the current palette and typography direction, but add styles for skip links, error pages, form hints/errors, navigation chips, stat explanations, dialog scrim, responsive table cards, status freshness, and disabled controls.

- [x] **Step 2: Verify responsive constraints**

Run `python scripts/smoke_ui.py` with the configured local app, plus a Playwright check at 375px and 1440px that `document.documentElement.scrollWidth <= window.innerWidth` and all primary controls remain visible.

### Task 5: Full verification and audit handoff

**Files:**
- No additional production files unless a verification regression requires a narrowly scoped correction.

- [x] **Step 1: Run the complete test suite**

Run `pytest -q` and record the exact pass/fail count.

- [x] **Step 2: Run lint and browser smoke checks**

Run `ruff check app tests` and `python scripts/smoke_ui.py` with the local service. If a check cannot run because the service or credentials are unavailable, report that explicitly instead of inferring success.

- [x] **Step 3: Inspect the final diff and repository state**

Run `git diff --check`, `git status --short`, and review all changed files for accidental credential exposure, inline native confirmations, broken labels, or unrelated backend changes.

- [x] **Step 4: Report deployment boundary**

Report local verification separately from production deployment. Do not claim the production site changed unless a fresh deployment command and post-deploy browser check both succeed.

## Verification Record

- `pytest -q`: 220 passed.
- Ruff check/format, compileall, pip dependency check, JavaScript syntax check, and `git diff --check`: passed.
- `scripts/smoke_ui.py`: desktop and mobile smoke passed against an isolated local instance.
- `scripts/audit_ui_interactions.py`: validation, loading, confirmation, credential masking, and responsive audit passed.
- Chrome Profile 40: admin and contributor dashboards, error recovery, confirmation focus restoration, console errors, and horizontal overflow inspected.
- Production remains unchanged until the VPS SSH host fingerprint is independently confirmed.
