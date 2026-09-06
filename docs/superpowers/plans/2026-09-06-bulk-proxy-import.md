# Bulk Proxy Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with test checkpoints.

**Goal:** Allow contributor users to import multiple proxies from a multiline text area or a text file, with explicit supported-format guidance, per-line validation, duplicate protection, quota enforcement, and useful import feedback.

**Architecture:** Add a bounded bulk-import service that parses each non-empty line using the existing `parse_proxy` contract, inserts valid rows atomically under one SQLite write transaction, and returns categorized per-line results. Add a browser/API route that accepts textarea and multipart file input, then render a dedicated import workspace with a format guide, file picker, multiline editor, summary, and detailed errors. Keep single-proxy add/replace behavior unchanged and preserve global credential-fingerprint duplicate protection.

**Tech Stack:** Flask, SQLite, Jinja templates, existing proxy parser/crypto/services, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; do not modify `CashPilot`.
- Preserve encrypted credential storage and global `credential_fingerprint` duplicate protection.
- Do not expose proxy passwords in rendered HTML, flash messages, logs, or import result details.
- Accept UTF-8 text files only; enforce bounded request/file size and bounded line count.
- Keep JSON/API responses backward-compatible for `POST /proxies`; add a separate bulk endpoint.
- Treat blank lines as ignored, not errors; report line numbers for invalid and duplicate rows.

### Task 1: Bulk service contract and tests

**Files:**
- Modify: `app/services/proxies.py`
- Test: `tests/test_proxy_inventory.py`

- [x] Add `BulkImportResult` and `bulk_add_proxies(db, user_id, raw_lines, *, max_active_proxies=None, max_lines=5000)`.
- [x] Return counts plus bounded lists of `{line, reason, value}` where `value` is credential-safe (host/port only or a redacted label).
- [x] Parse each non-empty line with `parse_proxy`; classify `ProxyParseError`, duplicate credential, and quota exhaustion without leaking secrets.
- [x] Use one `BEGIN IMMEDIATE` transaction; check global duplicates against the database and duplicates within the same batch; insert valid rows with the same encrypted fields and timestamps as `add_proxy`.
- [x] Write failing tests for multiline success, file-equivalent lines, invalid lines, duplicate lines against DB, duplicate lines within batch, quota/partial behavior, blank lines, and secret redaction.

### Task 2: Bulk route and request limits

**Files:**
- Modify: `app/routes/proxies.py`
- Test: `tests/test_browser_forms.py`, `tests/test_security.py`

- [x] Add `POST /proxies/import`, requiring an authenticated user role.
- [x] Read `raw_proxies` textarea and optional `proxy_file`; reject missing input with a browser flash or JSON `400`.
- [x] Decode uploaded bytes as UTF-8, reject invalid encoding and non-text content, combine textarea and file lines deterministically, and enforce maximum lines/bytes before service invocation.
- [x] Enforce the configured per-user quota through the bulk service, return `201` JSON with counts/details, and redirect browser submissions with a summary flash and error focus.
- [x] Add tests for browser multipart import, JSON import, missing input, invalid UTF-8, and quota behavior.

### Task 3: Contributor import UI and copy

**Files:**
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/static/app.css`
- Test: `tests/test_ui_contract.py`, `tests/test_browser_forms.py`

- [x] Replace the single-only add panel with a bulk import panel containing a multiline textarea, file input accepting `.txt,.csv`, explicit supported formats, examples, limits, and a single import action.
- [x] Keep a compact single-line add option only if it reduces friction; otherwise make multiline input the primary path and explain one proxy per line.
- [x] Include accessible labels, `aria-describedby`, upload feedback, and a no-JavaScript-safe submit path.
- [x] Render import result flashes without raw credentials; preserve the existing masked endpoint table and replacement form.
- [x] Add responsive styles for the two-column import layout and mobile stacking, respecting the existing TailAdmin shell.

### Task 4: Documentation and verification

**Files:**
- Modify: `README.md`
- Test: existing full suite

- [x] Document supported formats, line rules, duplicate behavior, limits, and endpoint contract.
- [x] Run focused red/green tests, then full Earn Proxy suite, Ruff, format check, compileall, pip check, and git diff check.
- [x] Audit generated HTML for password/credential leakage and verify the worktree contains no changes outside the Transfer Proxy repo.
