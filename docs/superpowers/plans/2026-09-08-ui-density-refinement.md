# UI Density Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make authenticated Earn Proxy screens compact and scannable, with proxy actions moved out of every table row while preserving behavior, security, accessibility, and responsive layout.

**Architecture:** Keep the existing server-rendered Jinja pages and TailAdmin-inspired shell. Add one shared native dialog for replacement actions, compact table modifiers for data-heavy views, and small CSS-only density/layout adjustments. No new dependency or backend route unless the existing replacement form cannot be reused.

**Tech Stack:** Flask, Jinja2, vanilla JavaScript, CSS, pytest, Playwright.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; do not edit CashPilot.
- Preserve masked credentials, CSRF, destructive confirmations, keyboard focus, reduced motion, and mobile no-overflow behavior.
- Use existing TailAdmin visual language and dependencies.
- Add focused regression coverage before production edits.

### Task 1: Capture the compact table contract

**Files:**
- Modify: `tests/test_ui_contract.py`
- Modify: `tests/test_tailadmin_shell.py`

- [x] Add assertions that the proxy table renders a compact action trigger, a single replacement dialog/form, and no repeated replacement input in each row.
- [x] Run the focused tests and confirm they fail against the current repeated-row form.

### Task 2: Refine user proxy workspace

**Files:**
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/templates/base.html`
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`

- [x] Replace each row's replacement form with a compact `Replace` trigger carrying the existing endpoint id and a hidden/native dialog form.
- [x] Keep the existing POST action, CSRF token, validation/error focus, loading state, and remove confirmation.
- [x] Reduce table cell padding, reserve sensible column widths, shorten repeated freshness copy without removing accessible full timestamps, and keep endpoint text readable.
- [x] Add dialog open/close/focus restoration behavior with Escape and reduced-motion-safe styles.
- [x] Tighten import, count, filter, and pagination spacing without changing labels or query semantics.

### Task 3: Apply compact data layout to admin workspaces

**Files:**
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/templates/admin_api_keys.html`
- Modify: `app/templates/admin_integrations.html`
- Modify: `app/templates/admin_egress_duplicates.html`
- Modify: `app/static/app.css`

- [x] Add compact table classes and action stacks for users, payouts, API keys, and duplicate groups.
- [x] Keep confirmation dialogs, transaction validation, and credential-safe text intact.
- [x] Ensure long metadata uses wrapping or disclosure rather than increasing row height.

### Task 4: Verify responsive and visual behavior

**Files:**
- Modify: `tests/test_ui_contract.py` only if regression coverage needs adjustment.

- [x] Run focused pytest, full pytest, scoped lint/compile checks.
- [x] Run local Playwright navigation, interaction, and responsive audits at desktop/tablet/mobile and light/dark modes.
- [x] Recheck the authenticated Chrome profile visually, including proxy, admin, duplicate, API key, and wallet pages.
- [x] Review the final diff for unrelated changes and deployment readiness.
