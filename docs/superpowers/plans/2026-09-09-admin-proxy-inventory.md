# Admin Proxy Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an admin-only, credential-safe inventory page for every non-archived proxy with server-side counts, filtering, sorting, and pagination.

**Architecture:** Keep the existing contributor inventory unchanged. Add a small admin-scoped query/view in `app/routes/admin.py`, render it in a dedicated template, and reuse the existing authenticated shell and compact table styles. The page is read-only in this increment; proxy mutations remain in their existing, separately protected workflows.

**Tech Stack:** Flask, SQLite, Jinja2, existing vanilla CSS/JavaScript, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; never modify `CashPilot`.
- Never render or decrypt proxy usernames/passwords.
- Use parameterized SQL and allowlisted query controls.
- Exclude archived rows from the default inventory while exposing an explicit archived filter.
- Preserve `Cache-Control: no-store` on the admin inventory response.
- Keep page sizes bounded to `25`, `50`, and `100`.

### Task 1: Query contract

**Files:**
- Modify: `app/routes/admin.py`
- Test: `tests/test_admin_proxy_inventory.py`

Add an admin query parser and server-side inventory builder covering owner, endpoint, status, protocol, eligibility, identity, country, freshness, archived state, search, sort, direction, counts, and pagination. Write failing route tests first, then implement the minimal query contract.

### Task 2: Admin page and navigation

**Files:**
- Create: `app/templates/admin_proxies.html`
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/__init__.py`
- Modify: `app/static/app.css`
- Modify: `tests/test_admin_proxy_inventory.py`
- Modify: `tests/test_tailadmin_shell.py`

Add the `/admin/proxies` route, sidebar/overview links, a compact responsive table, filter controls, count cards, safe detail disclosure, and accessible empty/loading states. Verify desktop/mobile-safe controls and active navigation.

### Task 3: Verification

Run focused tests, full pytest, Ruff, format, compile, dependency, and diff checks. Review the rendered route for credential leakage, unbounded SQL, and broken links.
