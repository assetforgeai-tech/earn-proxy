# TailAdmin Production Redesign Implementation Plan

> **For agentic workers:** Execute this plan task-by-task with verification after each task. Keep all changes inside `D:\1. WORK_true\Tranfer Proxy\earn-proxy`.

**Goal:** Replace the current visual shell with the approved TailAdmin-inspired Earn Proxy workspace while preserving all existing routes, security controls, API contracts, and contributor privacy.

**Architecture:** Keep Flask/Jinja and vanilla CSS/JavaScript. Add one responsive application shell in `base.html`, expose route-aware navigation through template context, and restyle existing panels/tables/forms rather than introducing a frontend build dependency. Backend behavior and URLs remain unchanged unless a template requires an existing endpoint.

**Tech Stack:** Flask, Jinja2, semantic HTML, vanilla CSS, vanilla JavaScript, pytest, Playwright/Chromium, Docker Compose, Caddy.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never edit `D:\1. WORK_true\CashPilot`.
- Preserve CSRF, confirmation dialogs, one-submit guards, masked credentials, API-key one-time reveal, and existing route names.
- Use a light TailAdmin-inspired visual system: fixed sidebar, compact topbar, white cards, gray canvas, indigo primary, semantic status colors.
- Keep body text readable, focus-visible states, keyboard navigation, 44px touch targets, reduced-motion support, and no horizontal page overflow.
- Do not add a JavaScript framework or remote runtime dependency.
- Do not deploy until tests, browser checks, Docker build, and production smoke checks pass.

### Task 1: Establish UI contracts before implementation

**Files:**
- Modify: `tests/test_ui_contract.py`
- Modify: `tests/test_ui_hardening.py`
- Create: `tests/test_tailadmin_shell.py`

- [ ] Add failing assertions for the new shell landmarks (`app-shell`, `sidebar`, `topbar`, `main-content`), active admin navigation, mobile menu button, and preserved security markers (`data-submit-once`, `data-confirm-dialog`, `aria-live`).
- [ ] Run the focused tests and confirm they fail because the new shell is not present.

### Task 2: Implement the shared application shell

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/routes/admin.py`
- Modify: `app/routes/dashboard.py`

- [ ] Add route-aware `active_nav`/`shell_title` context without changing endpoint names or response contracts.
- [ ] Render semantic sidebar groups for Overview, Proxy pool, Earnings, Wallet & payouts, Users, Health checker, Duplicate exits, Distribution API, and Transfer Proxy.
- [ ] Render topbar search, mobile menu button, notification/theme controls with accessible labels, account identity, and secure sign-out form.
- [ ] Keep flash notices and confirmation dialog inside the main landmark.

### Task 3: Convert the admin workspaces to the approved hierarchy

**Files:**
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/templates/admin_integrations.html`
- Modify: `app/templates/admin_api_keys.html`
- Modify: `app/templates/admin_transfer_proxy.html`

- [ ] Keep all existing form actions, hidden CSRF fields, labels, error IDs, table captions, and confirmation attributes.
- [ ] Add TailAdmin KPI cards to overview using existing `stats` values.
- [ ] Present checker policy, users, payouts, API feeds, API keys, and relay handoff as focused cards/tables with one primary action per view.
- [ ] Preserve the raw/transfer API distinction and the one-time token reveal wording.

### Task 4: Convert contributor and auth screens

**Files:**
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/templates/login.html`
- Modify: `app/templates/register.html`
- Modify: `app/templates/error.html`

- [ ] Use the same tokens and responsive shell for contributor pages while retaining masked host:port only.
- [ ] Keep payout minimum/fee/SLA copy and all current forms unchanged semantically.
- [ ] Keep auth pages centered, lightweight, and visibly branded without exposing admin navigation.

### Task 5: Replace visual tokens and interaction polish

**Files:**
- Modify: `app/static/app.css`
- Modify: `app/static/app.js`

- [ ] Introduce semantic TailAdmin tokens, fixed sidebar/topbar layout, card/table/form styles, responsive breakpoints at approximately 1180/900/680/420px, and reduced-motion behavior.
- [ ] Add mobile drawer overlay behavior and active navigation styling.
- [ ] Keep existing confirmation, copy-to-clipboard, payout quote, and submit-once behavior; add switch semantics only where a switch is rendered.
- [ ] Ensure focus-visible outlines and controls meet 44px minimum touch target.

### Task 6: Regression and browser verification

**Files:**
- Create: `scripts/audit_tailadmin_ui.py`

- [ ] Run the complete pytest suite and focused UI tests.
- [ ] Use Playwright/Chromium at `1440x900`, `1024x768`, and `375x812` to verify no horizontal overflow, sidebar drawer behavior, active nav, forms, confirmation dialog, API-key reveal, and no console/page errors.
- [ ] Capture screenshots in `docs/ui-audit/tailadmin/` and record the checks.

### Task 7: Build, release, and production smoke test

**Files:**
- Modify only if required by verification: `Dockerfile`, `docker-compose.yml`, `deploy/*`, `README.md`

- [ ] Build the production image and run the existing test/smoke commands.
- [ ] Inspect the diff and confirm no files under `CashPilot` changed.
- [ ] Deploy the verified commit using the existing release procedure, preserve the previous release for rollback, and run authenticated/unauthenticated HTTP smoke checks for `/`, `/login`, `/dashboard`, `/admin`, `/admin/integrations`, and `/admin/integrations/api-keys`.
- [ ] Report the commit, release path, health results, and any residual risks with evidence.
