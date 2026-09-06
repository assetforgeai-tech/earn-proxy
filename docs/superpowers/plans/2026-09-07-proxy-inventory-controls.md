# Proxy Inventory Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with test checkpoints.

**Goal:** Give contributors a scalable proxy inventory page with counts, server-side pagination, rows-per-page selection, search, filters, and safe sorting.

**Architecture:** Parse and normalize inventory controls from query parameters, build a parameterized allow-listed SQL query, and return only one page of proxy rows. Keep aggregate counts separate from the page query so the UI can expose clickable status/protocol/eligibility filters without rendering the full inventory. Preserve all existing credential masking, replacement, deletion, and checker behavior.

**Tech Stack:** Flask, SQLite, Jinja templates, existing CSS/JS, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; do not modify `CashPilot`.
- Never expose proxy credentials or raw proxy values in the contributor UI.
- Use parameterized SQL for all user-controlled query values; interpolate only fixed allow-listed SQL fragments.
- Keep filter, sort, search, and page state in the URL so navigation and refresh preserve the view.
- Render at most the selected page size (10–100 rows) per request.
- Preserve existing API routes and checker scheduling semantics.

### Task 1: Inventory query contract and tests

**Files:**
- Modify: `app/routes/dashboard.py`
- Modify: `app/db.py`
- Test: `tests/test_ui_contract.py`
- Test: `tests/test_browser_forms.py`

- [ ] Add failing tests for counts, page size, search, status/protocol/eligibility filters, stable sort, invalid parameter normalization, and page links.
- [ ] Add a query helper that returns aggregate counts, filtered count, one page of rows, and pagination metadata.
- [ ] Add indexes supporting user-scoped status/protocol/date queries.

### Task 2: Contributor inventory UI

**Files:**
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/static/app.css`

- [ ] Add total/filtered/page counts and clickable count cards for status, protocol, and eligibility.
- [ ] Add GET search field, filter selects, rows-per-page select, and reset action.
- [ ] Add sortable table headers with `aria-sort`, preserving active query state.
- [ ] Add accessible pagination controls and a compact mobile layout without credential exposure.

### Task 3: Verification and release

**Files:**
- Modify: `README.md`
- Test: full existing suite plus focused inventory tests.

- [ ] Document inventory URL parameters and server-side behavior.
- [ ] Run focused tests, full pytest, Ruff, format, compileall, pip check, and diff check.
- [ ] Commit/push, deploy via the existing release script, and verify production counts/routes/health.
