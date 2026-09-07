# Egress Duplicate Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make global egress-IP deduplication visible and actionable without exposing user proxy credentials or changing the asynchronous checker architecture.

**Architecture:** Keep immediate global credential-fingerprint rejection at import. Keep trusted egress reconciliation in the health/EarnApp workers. Add derived identity states to the contributor inventory, plus an admin-only aggregate page for trusted duplicate egress groups.

**Tech Stack:** Python 3.11, Flask, SQLite, Jinja, existing TailAdmin-style CSS, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`.
- Do not expose proxy usernames, passwords, raw credentials, exit IPs, or canonical IDs to contributors.
- Only `https_quorum` and `earnapp_tls` evidence may establish egress identity.
- Do not probe synchronously during import.
- Preserve existing API and earnings exclusion using `duplicate_of IS NULL`.

---

### Task 1: Contributor egress identity controls

**Files:**
- Modify: `app/routes/dashboard.py`
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/static/app.css`
- Test: `tests/test_proxy_inventory_controls.py`

**Interfaces:**
- Consumes: existing `proxies.exit_ip`, `proxies.egress_attestation_source`, and `proxies.duplicate_of` fields.
- Produces: `identity` query control, `identity_counts`, and a contributor-safe identity label per row.

- [x] **Step 1: Write the failing inventory test**

```python
def test_proxy_inventory_filters_and_labels_global_egress_identity(app, client):
    user_id = _activate_user(app, client, "inventory-egress@example.com")
    with app.app_context():
        db = get_db()
        canonical = add_proxy(db, user_id, "egress-a.example:9000:u-a:p-a")
        duplicate = add_proxy(db, user_id, "egress-b.example:9001:u-b:p-b")
        awaiting = add_proxy(db, user_id, "egress-c.example:9002:u-c:p-c")
        db.execute(
            "UPDATE proxies SET status='online', exit_ip='198.51.100.10', "
            "egress_attestation_source='https_quorum' WHERE id=?",
            (canonical,),
        )
        db.execute(
            "UPDATE proxies SET status='online', exit_ip='198.51.100.10', "
            "egress_attestation_source='earnapp_tls', duplicate_of=? WHERE id=?",
            (canonical, duplicate),
        )
        db.commit()
    all_rows = client.get("/dashboard/proxies").get_data(as_text=True)
    duplicate_rows = client.get("/dashboard/proxies?identity=duplicate").get_data(as_text=True)
    assert "Canonical" in all_rows and "Duplicate egress" in all_rows and "Awaiting probe" in all_rows
    assert "198.51.100.10" not in all_rows
    assert "egress-b.example:9001" in duplicate_rows
    assert "egress-a.example:9000" not in duplicate_rows
```

- [x] **Step 2: Verify RED**

Run: `python -m pytest tests/test_proxy_inventory_controls.py -q`

Expected: FAIL because the `identity` filter and labels do not exist.

- [x] **Step 3: Implement the minimum derived identity state**

```python
trusted = "p.egress_attestation_source IN ('https_quorum','earnapp_tls')"
# canonical: trusted IP plus duplicate_of IS NULL
# duplicate: duplicate_of IS NOT NULL
# awaiting: no trusted canonical identity yet
```

Render `Canonical`, `Duplicate egress`, or `Awaiting probe`; state explicitly that duplicate egress does not earn or distribute. Keep exit IP and canonical row IDs out of contributor HTML.

- [x] **Step 4: Verify GREEN**

Run: `python -m pytest tests/test_proxy_inventory_controls.py -q`

Expected: PASS.

### Task 2: Honest import feedback

**Files:**
- Modify: `app/routes/proxies.py`
- Modify: `app/templates/user_dashboard.html`
- Modify: `README.md`
- Test: `tests/test_browser_forms.py`
- Test: `tests/test_ui_contract.py`

**Interfaces:**
- Consumes: existing `BulkImportResult` credential-duplicate counts.
- Produces: copy distinguishing immediate credential dedupe from post-probe global egress dedupe.

- [x] **Step 1: Write failing copy tests**

```python
page = client.get("/dashboard/proxies").get_data(as_text=True)
assert "Egress duplicates are detected after the first trusted probe" in page
```

- [x] **Step 2: Verify RED**

Run: `python -m pytest tests/test_browser_forms.py tests/test_ui_contract.py -q`

Expected: FAIL because current copy describes credential duplicates only.

- [x] **Step 3: Add concise staged-dedupe copy**

Explain: credentials are checked immediately; trusted egress is checked globally after the first probe; duplicate egress remains visible but cannot earn or enter API distribution.

- [x] **Step 4: Verify GREEN**

Run: `python -m pytest tests/test_browser_forms.py tests/test_ui_contract.py -q`

Expected: PASS.

### Task 3: Admin duplicate egress groups

**Files:**
- Modify: `app/routes/admin.py`
- Modify: `app/templates/base.html`
- Modify: `app/__init__.py`
- Create: `app/templates/admin_egress_duplicates.html`
- Modify: `app/static/app.css`
- Create: `tests/test_admin_egress_duplicates.py`

**Interfaces:**
- Consumes: trusted, non-archived egress rows.
- Produces: admin-only `GET /admin/egress-duplicates`, aggregate groups, server-side search and pagination.

- [x] **Step 1: Write failing admin route tests**

```python
def test_admin_egress_duplicate_groups_are_global_and_credential_safe(app, client):
    login_admin(client)
    with app.app_context():
        db = get_db()
        user_id = create_user(db, "egress-admin@example.com", "password", status="active")
        first = add_proxy(db, user_id, "admin-a.example:9000:secret-user-a:secret-pass-a")
        second = add_proxy(db, user_id, "admin-b.example:9001:secret-user-b:secret-pass-b")
        reconcile_exit_ip(db, first, "198.51.100.20")
        reconcile_exit_ip(db, second, "198.51.100.20", attestation_source="earnapp_tls")
    page = client.get("/admin/egress-duplicates").get_data(as_text=True)
    assert "198.51.100.20" in page
    assert "admin-a.example:9000" in page
    assert "secret-pass-a" not in page and "secret-pass-b" not in page
```

- [x] **Step 2: Verify RED**

Run: `python -m pytest tests/test_admin_egress_duplicates.py -q`

Expected: FAIL with 404.

- [x] **Step 3: Implement one aggregate query and TailAdmin table**

```sql
SELECT exit_ip, COUNT(*) AS proxy_count,
       SUM(duplicate_of IS NOT NULL) AS duplicate_count,
       COUNT(DISTINCT user_id) AS account_count
FROM proxies
WHERE archived_at IS NULL
  AND egress_attestation_source IN ('https_quorum','earnapp_tls')
GROUP BY exit_ip
HAVING COUNT(*) > 1
```

Add a sidebar item, page count, IP search, 25/50/100 page size, canonical endpoint, and no credentials.

- [x] **Step 4: Verify GREEN**

Run: `python -m pytest tests/test_admin_egress_duplicates.py tests/test_tailadmin_shell.py -q`

Expected: PASS.

### Task 4: Regression, UI audit, release

**Files:**
- Verify only unless a failing check identifies a scoped defect.

- [x] **Step 1: Run complete verification**

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m compileall -q app deploy integrations tests
python -m pip check
git diff --check
```

- [x] **Step 2: Run UI scripts and browser smoke**

```powershell
python scripts/audit_navigation_ux.py
python scripts/audit_ui_interactions.py
python scripts/smoke_ui.py
```

Verified against an isolated local instance with relay configuration present: navigation UX, interaction/responsive, and desktop/mobile smoke audits passed.

- [x] **Step 3: Commit, push, deploy, verify production**

Use the existing release script. Confirm services active, `/healthz` healthy, contributor counts equal production DB identity counts, admin group totals match, and the raw API returns only canonical rows.

Production verification: release `7cb647e21f7a04c7c0dc57e4d37fb23b4e652e3a` is active on the VPS; all five services are enabled/active; `/healthz` is healthy; the database reports 2,056 active proxies, 88 canonical rows, 1,968 duplicate rows, 88 duplicate groups, and zero identity mismatches; the authenticated raw API returns 88 canonical rows.
