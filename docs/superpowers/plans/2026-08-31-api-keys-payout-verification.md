# API Key Management and Payout Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add secure administrator-managed API keys and automatic USDT BEP20 payout verification without placing a wallet private key on the VPS.

**Architecture:** Store only a SHA-256 digest of high-entropy API tokens in SQLite, with a one-time reveal response after creation. The canonical proxy API authenticates against active database keys and imports the existing environment key as a legacy record during migration. Payouts use an explicit state machine (`requested -> approved -> verifying -> confirmed|failed`); an independent verifier worker reads public BSC JSON-RPC data and checks receipt success, USDT contract, destination wallet, exact amount, and confirmation depth.

**Tech Stack:** Python 3.11, Flask 3.1, SQLite WAL, requests, Gunicorn/systemd or Docker Compose, server-rendered HTML/CSS/vanilla JavaScript.

## Global Constraints

- Never store or log plaintext API keys, proxy credentials, wallet private keys, or RPC authentication secrets.
- Keep the existing `/api/v1/proxies` and `/internal/api/v1/proxies` response contracts compatible.
- Preserve the existing environment API key during migration by importing it as a revocable legacy key.
- Do not let a user or contributor approve, verify, or mutate another user's payout.
- No automatic blockchain transfer is added; administrators still send USDT externally.
- All state-changing browser forms require the existing CSRF protection and destructive/financial actions require confirmation UI.
- Every production behavior change must have a failing test first, then a passing regression test.

### Task 1: API key persistence and authentication

**Files:**
- Modify: `app/db.py`
- Create: `app/services/api_keys.py`
- Modify: `app/routes/internal_api.py`
- Modify: `app/__init__.py`
- Test: `tests/test_api_keys.py`
- Test: `tests/test_internal_api.py`

**Interfaces:**
- `create_api_key(db, name, *, created_by_user_id, source="managed") -> tuple[int, str]`
- `revoke_api_key(db, key_id) -> None`
- `rotate_api_key(db, key_id, *, created_by_user_id) -> tuple[int, str]`
- `authenticate_api_key(db, supplied) -> row | None`
- `list_api_keys(db) -> list[sqlite3.Row]`

- [ ] Add a migration/table with `id`, random public `key_id`, `name`, `token_prefix`, `token_hash`, `source`, `created_by_user_id`, `created_at`, `last_used_at`, and `revoked_at`; index the hash and enforce unique public ID/hash.
- [ ] Write tests proving generated tokens are shown only from the creation return value, hashes are stored instead of plaintext, revoked keys fail, and the legacy configured key is imported idempotently.
- [ ] Update API authentication to use database keys, update `last_used_at` after successful authentication, return the same 401 for missing/invalid/revoked keys, and retain the legacy route alias.
- [ ] Run focused API-key tests and the existing internal API tests before moving on.

### Task 2: Administrator key-management workspace

**Files:**
- Modify: `app/routes/admin.py`
- Create: `app/templates/admin_api_keys.html`
- Modify: `app/templates/admin_integrations.html`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/static/app.css`
- Modify: `app/static/app.js`
- Test: `tests/test_admin_api_keys.py`
- Test: `tests/test_browser_forms.py`

**Interfaces:**
- `GET /admin/integrations/api-keys`
- `POST /admin/integrations/api-keys`
- `POST /admin/integrations/api-keys/<int:key_id>/revoke`
- `POST /admin/integrations/api-keys/<int:key_id>/rotate`

- [ ] Write failing route/UI tests for admin-only access, one-time token reveal, masked key listing, revoke/rotate confirmation attributes, and route-based navigation with no hash fragments.
- [ ] Implement the workspace with clear `Create key`, `Copy once`, `Rotate`, and `Revoke` actions; do not render token values from persisted data.
- [ ] Add `Cache-Control: no-store` to one-time reveal responses and prevent token values from appearing in flash messages, URLs, logs, or page titles.
- [ ] Update integrations documentation to link to key management and explain that existing clients continue working until the legacy key is revoked.
- [ ] Run focused route and browser tests plus an HTML secret-leak assertion.

### Task 3: Payout verification domain and state machine

**Files:**
- Modify: `app/db.py`
- Create: `app/services/payout_verification.py`
- Modify: `app/services/payouts.py`
- Modify: `app/routes/admin.py`
- Modify: `app/routes/wallets.py`
- Test: `tests/test_payout_verification.py`
- Modify: `tests/test_payout_lifecycle.py`

**Interfaces:**
- `verify_bsc_payout(payout, *, rpc_url, token_contract, min_confirmations, rpc_call=None) -> VerificationResult`
- `submit_payout_transaction(db, payout_id, tx_hash, *, now=None) -> None`
- `apply_payout_verification(db, payout_id, result, *, now=None) -> None`

- [ ] Add migration columns for verification status/error/attempts/timestamps/block metadata and a partial unique index for non-empty transaction hashes.
- [ ] Write failing tests for malformed hashes, reverted receipts, wrong contract, wrong recipient, wrong amount, insufficient confirmations, exact valid transfer events, duplicate transaction reuse, and retryable RPC errors.
- [ ] Implement strict JSON-RPC validation against the configured HTTPS BSC endpoint; decode only the canonical USDT `Transfer` event and compare normalized addresses and integer token units.
- [ ] Change admin submission from `Mark sent` to `Submit for verification`; only the verifier can move a payout to `confirmed`.
- [ ] Include `requested`, `approved`, `verifying`, `confirmed`, and `failed` in reservation/accounting rules; failed payouts release the reservation and confirmed payouts remain reserved.
- [ ] Run focused payout tests and all existing earnings/wallet tests.

### Task 4: Verifier worker and deployment

**Files:**
- Create: `app/payout_verifier_service.py`
- Modify: `docker-compose.yml`
- Create: `deploy/earn-proxy-payout-verifier.service`
- Modify: `.env.example`
- Modify: `README.md`
- Test: `tests/test_payout_verifier_service.py`

- [ ] Write failing runner tests for durable claim/release, retry scheduling, shutdown, and no-RPC-config behavior.
- [ ] Implement a bounded worker with one verifier concurrency slot, short request timeout, durable claims, configurable interval, max age, confirmation depth, token contract, and RPC URL.
- [ ] Add restartable Compose/systemd definitions and document required `EARN_PROXY_BSC_RPC_URL`, `EARN_PROXY_BSC_MIN_CONFIRMATIONS`, and related settings.
- [ ] Ensure the worker never receives or needs a private key and never logs full RPC bodies.
- [ ] Run worker tests and deployment configuration validation.

### Task 5: Full verification, deployment, and audit

**Files:**
- Create: `docs/security-audits/<run>/REPORT.md`
- Create: `docs/security-audits/<run>/FINDINGS-DETAIL.md`
- Create: `docs/security-audits/<run>/findings.json`
- Create: `docs/security-audits/<run>/architecture.md`

- [ ] Run the complete pytest suite, Ruff check/format, compileall, pip check, git diff check, and UI/browser smoke tests at desktop and 375px widths.
- [ ] Inspect headers, authentication failures, key leakage, state transitions, replay/duplicate transaction attempts, and production health without printing secrets.
- [ ] Run the security-audit workflow (recon, hunt, validate, report, structured schema validation, independent verification) and record only exploitable findings with concrete evidence.
- [ ] Deploy through the existing release/rollback procedure, verify service status and public routes, then perform a post-deploy smoke test.
- [ ] Report residual risks separately from confirmed findings; do not claim completion without fresh command output.

## Self-review checklist

- [ ] Every requested feature maps to at least one task and test.
- [ ] No task relies on an undefined function or placeholder.
- [ ] API key rotation cannot reveal old plaintext tokens.
- [ ] Payout confirmation cannot be achieved by merely entering a non-empty string.
- [ ] Existing API consumers and legacy route remain compatible.
