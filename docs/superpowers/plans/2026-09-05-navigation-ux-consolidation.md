# Navigation and UX Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Earn Proxy sidebar the single source of navigation, split the contributor workspace into clear routes, and ship a responsive, accessible production UI without changing proxy, payout, API, or relay business behavior.

**Architecture:** Keep the Flask/Jinja application and its existing security controls. Add four contributor GET routes backed by one shared dashboard context builder, render the existing contributor sections conditionally, and derive the active sidebar item and topbar title from the endpoint. Remove duplicate horizontal menus and the non-functional search field, then harden the vanilla JavaScript drawer and CSS breakpoints for keyboard, tablet, mobile, light, and dark modes.

**Tech Stack:** Python 3.11, Flask, Jinja2, SQLite, vanilla JavaScript, CSS, pytest, Playwright/Chromium, systemd, Caddy.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never modify `D:\1. WORK_true\CashPilot`.
- Preserve CSRF, one-submit guards, confirmation dialogs, masked proxy credentials, one-time API-key reveal, and all existing API contracts.
- Keep the sidebar as the only top-level workspace navigation and use these admin labels exactly: Overview, Health checker, Users, Payouts, Distribution API, API keys, Transfer Proxy.
- Contributor routes are `/dashboard`, `/dashboard/proxies`, `/dashboard/earnings`, and `/dashboard/wallet`.
- Keep legacy `/dashboard` fragment links usable by redirecting recognized fragments client-side to the matching route.
- Do not add a frontend framework, remote runtime dependency, email flow, or new infrastructure.
- Support keyboard operation, visible focus, minimum 44px controls, reduced motion, no hidden off-canvas focus targets, and no page-level horizontal overflow.
- Do not deploy until the full test/lint/format/compile/dependency suite and browser audits pass.

---

### Task 1: Lock the navigation and authentication contracts with failing tests

**Files:**
- Modify: `tests/test_tailadmin_shell.py`
- Modify: `tests/test_ui_hardening.py`
- Modify: `tests/test_auth_users.py`

**Interfaces:**
- Produces route expectations for `dashboard.dashboard`, `dashboard.proxies`, `dashboard.earnings`, and `dashboard.wallet`.
- Produces markup expectations for a single workspace navigation, route-aware `aria-current`, no fake search field, and an inert-capable mobile drawer.

- [x] **Step 1: Add contributor route tests**

  Add assertions that the four contributor URLs return `200`, render only their intended major sections, and mark exactly one matching sidebar item with `aria-current="page"`.

- [x] **Step 2: Add single-navigation and naming tests**

  Assert that every admin workspace omits `.section-nav`, uses the seven exact sidebar labels, and that contributor pages omit the old `#dashboard-nav` horizontal menu.

- [x] **Step 3: Add authentication and drawer contract tests**

  Assert that authenticated GET requests to `/login` redirect by role, the topbar omits `data-page-search`, the overlay starts hidden, and the JavaScript contains inert/focus-restoration behavior.

- [x] **Step 4: Run the focused tests and verify RED**

  Run: `python -m pytest tests/test_tailadmin_shell.py tests/test_ui_hardening.py tests/test_auth_users.py -q`

  Expected: failures for missing contributor routes, duplicate section navigation, the fake search control, login rendering while authenticated, and incomplete drawer focus behavior.

### Task 2: Add route-aware contributor workspaces and authenticated login redirects

**Files:**
- Modify: `app/routes/dashboard.py`
- Modify: `app/routes/auth.py`
- Modify: `app/__init__.py`
- Modify: `app/routes/proxies.py`
- Modify: `app/routes/wallets.py`

**Interfaces:**
- Produces `GET /dashboard` through endpoint `dashboard.dashboard`.
- Produces `GET /dashboard/proxies` through endpoint `dashboard.proxies`.
- Produces `GET /dashboard/earnings` through endpoint `dashboard.earnings`.
- Produces `GET /dashboard/wallet` through endpoint `dashboard.wallet`.
- Produces template values `dashboard_section`, `active_nav`, and `shell_title`.

- [x] **Step 1: Implement one shared dashboard renderer**

  Extract the current contributor queries into `_render_dashboard(section: str)` and keep credentials masked by continuing to pass database rows only to the existing safe template fields.

- [x] **Step 2: Add the three new contributor routes**

  Route Proxies, Earnings, and Wallet to the shared renderer and keep `/dashboard` as Overview and the post-login landing page.

- [x] **Step 3: Redirect authenticated login GET requests**

  Return admin users to `/admin` and contributor users to `/dashboard` before rendering the login form.

- [x] **Step 4: Route browser form results to the focused workspace**

  Send proxy create/replace/delete browser results to `/dashboard/proxies` and wallet/payout browser results to `/dashboard/wallet`, without changing JSON responses.

- [x] **Step 5: Run the focused route tests and verify GREEN**

  Run: `python -m pytest tests/test_auth_users.py tests/test_browser_forms.py tests/test_wallet_routes.py tests/test_proxy_inventory.py -q`

  Expected: all tests pass with the new route expectations.

### Task 3: Consolidate templates around the sidebar

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/templates/admin_integrations.html`
- Modify: `app/templates/admin_api_keys.html`
- Modify: `app/templates/admin_transfer_proxy.html`
- Modify: `app/templates/user_dashboard.html`

**Interfaces:**
- Consumes `active_nav`, `shell_title`, and `dashboard_section` from Task 2.
- Preserves all existing form actions, CSRF fields, confirmation attributes, captions, labels, and masked endpoint rendering.

- [x] **Step 1: Make the sidebar canonical**

  Replace contributor fragment links with the four route URLs, apply endpoint-driven `aria-current`, keep the seven standardized admin labels, and remove every horizontal `.section-nav` block.

- [x] **Step 2: Replace fake search with useful page context**

  Render the current workspace and `shell_title` in the topbar, keep theme/account controls, and add a mobile-only account/sign-out block in the drawer.

- [x] **Step 3: Split contributor content by route**

  Render overview statistics on Overview, proxy add/whitelist/status on Proxies, balance and earning policy on Earnings, and wallet/request/history on Wallet & payouts.

- [x] **Step 4: Keep quick links only on Admin Overview**

  Expand the existing admin overview cards to the focused admin workspaces and use the exact sidebar naming; do not render quick-link grids on other pages.

- [x] **Step 5: Complete form and timestamp accessibility**

  Add helper text and `aria-describedby` to both retry inputs, render API-key timestamps as readable UTC labels while preserving machine-readable `<time datetime>`, and retain live-region copy feedback.

- [x] **Step 6: Run template contract tests and verify GREEN**

  Run: `python -m pytest tests/test_tailadmin_shell.py tests/test_ui_contract.py tests/test_ui_hardening.py tests/test_admin_integrations.py -q`

  Expected: all tests pass.

### Task 4: Harden responsive layout, dark mode, and drawer interaction

**Files:**
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`

**Interfaces:**
- Consumes `#app-sidebar`, `#mobile-menu-toggle`, and `#sidebar-overlay` markup from Task 3.
- Produces an off-canvas drawer below 1100px that cannot receive focus while closed and restores focus to its trigger when dismissed.

- [x] **Step 1: Implement explicit drawer state helpers**

  Add `openSidebar`, `closeSidebar`, and `syncSidebarMode`; toggle `hidden`, `aria-hidden`, `aria-expanded`, and the native `inert` property according to viewport and open state.

- [x] **Step 2: Add keyboard containment and restoration**

  Trap Tab within the open mobile drawer, close on Escape/overlay, restore focus to the hamburger, and close without restoration after a real navigation click.

- [x] **Step 3: Add legacy fragment compatibility**

  Map `/dashboard#add-proxy` and `#proxy-status` to `/dashboard/proxies`, and wallet/payout fragments to `/dashboard/wallet` with `location.replace`.

- [x] **Step 4: Rebalance tablet and mobile CSS**

  Collapse the fixed sidebar below 1100px, preserve 44px touch targets, keep the topbar uncluttered, remove unused search and horizontal-nav rules from authenticated pages, and ensure data cards/tables fit 375px through 1024px.

- [x] **Step 5: Complete dark-mode surface coverage**

  Theme quick links, integration cards, code/copy fields, empty states, callouts, notices, table cards, and drawer account controls with semantic tokens.

- [x] **Step 6: Run focused UI tests and static checks**

  Run: `python -m pytest tests/test_tailadmin_shell.py tests/test_ui_hardening.py tests/test_browser_forms.py -q`

  Run: `python -m ruff check app tests scripts`

  Expected: both commands pass.

### Task 5: Expand browser audit coverage

**Files:**
- Modify: `scripts/smoke_ui.py`
- Modify: `scripts/audit_ui_interactions.py`
- Create: `scripts/audit_navigation_ux.py`

**Interfaces:**
- Uses `EARN_PROXY_SMOKE_URL`, `EARN_PROXY_ADMIN_EMAIL`, and `EARN_PROXY_ADMIN_PASSWORD` without printing their values.
- Produces deterministic assertions for navigation, responsive overflow, drawer state/focus, route content, dark mode, and console/page errors.

- [x] **Step 1: Update existing scripts for the route and label changes**

  Replace horizontal-menu selectors and old API endpoint expectations with the canonical sidebar and split raw/transfer feeds.

- [x] **Step 2: Add a navigation-specific Playwright audit**

  Check all seven admin pages plus all four contributor pages at 1440x900, 1024x768, and 375x812; assert exactly one active sidebar link, no page overflow, correct section content, and zero console/page errors.

- [x] **Step 3: Verify drawer and accessibility behavior**

  At tablet/mobile widths assert closed drawer inertness, open focus placement, Tab containment, Escape focus restoration, overlay dismissal, and readable retry helper associations.

- [x] **Step 4: Run local browser audits**

  Start the app with a disposable database and run all three Playwright scripts against it.

  Expected: each script exits `0` and prints its success marker.

### Task 6: Full verification, release, and production audit

**Files:**
- Modify only if verification exposes a real issue: `README.md`, `deploy/*`, `Dockerfile`, `docker-compose.yml`

**Interfaces:**
- Produces a pushed Git commit, a versioned `/opt/earn-proxy-<commit>` production release, preserved rollback release, and verified `https://proxy.acacondos.com` behavior.

- [x] **Step 1: Run the complete verification gate**

  Run: `python -m pytest -q`

  Run: `python -m ruff check app tests scripts`

  Run: `python -m ruff format --check app tests scripts`

  Run: `python -m compileall -q app tests scripts`

  Run: `python -m pip check`

  Expected: every command exits `0` with no failures.

- [x] **Step 2: Inspect scope and commit**

  Confirm `git diff` contains no CashPilot path or secret, commit the navigation/UX consolidation, and push the branch and public repository default branch as appropriate.

- [x] **Step 3: Deploy a versioned release with rollback preserved**

  Back up the production database/configuration, copy only tracked release files to a new `/opt/earn-proxy-<commit>` directory, update the current symlink/service working directory using the established deployment procedure, and restart only the Earn Proxy services.

- [x] **Step 4: Smoke production**

  Verify `/healthz`, anonymous redirects, authenticated admin/contributor routes, Caddy TLS, service status, recent journals, raw/transfer API authentication behavior, and the isolated Transfer Proxy handoff page.

- [x] **Step 5: Audit Chrome Profile 40**

  Use the already authenticated `AssetForge AI` Chrome profile to click every admin and contributor menu at desktop, tablet, and mobile dimensions; verify route highlighting, content hierarchy, drawer focus, no overflow, light/dark mode, and no console errors.

- [x] **Step 6: Report evidence**

  Report the commit, release directory, previous rollback directory, test counts, service health, browser audit results, and any residual risk without exposing credentials.
