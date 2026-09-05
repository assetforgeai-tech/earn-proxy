# Payout, Domain, and Transfer API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `proxy.acacondos.com` the primary Earn Proxy application, add safe payout fees and a 48-hour processing SLA, expose separate raw and fixed-transfer API feeds, and surface the VPS whitelist hostname/IP to contributors.

**Architecture:** Earn Proxy remains the authentication, contributor, payout, and API authority on port 8100. The existing Proxy Relay manager remains an isolated service on port 8000, is mounted below `/admin/transfer-proxy/`, accepts short-lived signed admin SSO, and exposes a loopback-only authenticated transfer feed consumed by Earn Proxy. Caddy performs the domain cutover while keeping legacy API clients on `earn.proxy.acacondos.com` operational.

**Tech Stack:** Python 3.11, Flask, SQLite, Gunicorn, systemd, Caddy, pytest, existing Go relay engine.

## Global Constraints

- Work only under `D:\1. WORK_true\Tranfer Proxy`; never modify CashPilot.
- Preserve both production databases, proxy credentials, listener mappings, and existing API keys.
- Minimum payout is `$10.00` gross.
- Fee is `10%` for `$10.00 <= gross < $50.00` and `2%` for `gross >= $50.00`.
- Every payout snapshots gross, fee basis points, fee, net amount, and a 48-hour processing deadline.
- Existing payout rows remain verifiable at their original amount with a zero-fee legacy snapshot.
- `/api/v1/proxy-raw` and `/api/v1/proxy-transfer` are separate authenticated feeds; `/api/v1/proxies` remains a raw-feed compatibility alias.
- `whitelist.proxy.acacondos.com` resolves to the VPS and the UI also displays the current IPv4 fallback.
- The Transfer Proxy UI is admin-only and must use a distinct cookie name/path from Earn Proxy.
- All secrets remain server-side and all credential-bearing responses use `Cache-Control: no-store`.

---

### Task 1: Payout policy and immutable accounting snapshots

**Files:**
- Modify: `app/db.py`
- Modify: `app/services/payouts.py`
- Modify: `app/services/payout_verification.py`
- Modify: `app/routes/wallets.py`
- Test: `tests/test_payout_lifecycle.py`
- Test: `tests/test_payout_verification.py`
- Test: `tests/test_migrations.py`

**Interfaces:**
- Produces: `quote_payout(amount_micro_usd) -> PayoutQuote`
- Produces payout columns: `fee_bps`, `fee_micro_usd`, `net_micro_usd`, `processing_due_at`
- Verification consumes `net_micro_usd`, while balance reservation continues to consume `amount_micro_usd`.

- [ ] Add failing boundary tests for `$9.999999`, `$10`, `$49.999999`, and `$50`.
- [ ] Add failing migration test proving legacy payouts receive fee `0`, net equal to gross, and a derived deadline.
- [ ] Implement quote calculation, minimum validation, immutable snapshots, and net on-chain verification.
- [ ] Run payout and migration tests until green.
- [ ] Commit the payout policy change.

### Task 2: Payout and whitelist user experience

**Files:**
- Modify: `app/__init__.py`
- Modify: `app/routes/dashboard.py`
- Modify: `app/templates/user_dashboard.html`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/static/app.js`
- Modify: `app/static/app.css`
- Modify: `.env.example`
- Test: `tests/test_payout_ui.py`
- Test: `tests/test_browser_forms.py`
- Test: `tests/test_ui_contract.py`

**Interfaces:**
- Consumes payout snapshot fields from Task 1.
- Produces clear gross/fee/net previews and `whitelist_host`/`whitelist_ip` template values.

- [ ] Add failing UI tests for the `$10` minimum, fee tiers, net amount, separate wallet lock language, and 48-hour processing language.
- [ ] Add failing UI tests for hostname/IP whitelist copy controls and provider compatibility guidance.
- [ ] Implement server-rendered payout summaries, a client-side quote preview, admin overdue labels, and accessible copy controls.
- [ ] Run the focused UI tests until green.
- [ ] Commit the payout and whitelist UI change.

### Task 3: Separate raw and transfer API feeds

**Files:**
- Modify: `app/routes/internal_api.py`
- Modify: `app/routes/admin.py`
- Modify: `app/templates/admin_integrations.html`
- Modify: `.env.example`
- Test: `tests/test_internal_api.py`
- Test: `tests/test_admin_integrations.py`

**Interfaces:**
- Produces: `GET /api/v1/proxy-raw`
- Produces: `GET /api/v1/proxy-transfer`
- Keeps: `GET /api/v1/proxies` and `GET /internal/api/v1/proxies` as raw aliases.
- Consumes the loopback relay feed using `X-Relay-Feed-Key`.

- [ ] Add failing authentication, text, JSON, failure, no-cache, and compatibility tests for both feed types.
- [ ] Implement shared API-key authentication and raw selection without changing current distribution policy.
- [ ] Implement bounded loopback transfer-feed retrieval and safe `503` behavior.
- [ ] Update the integrations workspace with distinct endpoint and format cards.
- [ ] Run focused API/integration tests until green.
- [ ] Commit the split API feeds.

### Task 4: Admin Transfer Proxy menu and isolated SSO

**Files:**
- Create: `app/services/relay_sso.py`
- Create: `app/templates/admin_transfer_proxy.html`
- Modify: `app/routes/admin.py`
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin_dashboard.html`
- Modify: `app/templates/admin_integrations.html`
- Modify: `app/templates/admin_api_keys.html`
- Test: `tests/test_admin_integrations.py`
- Test: `tests/test_security.py`

**Interfaces:**
- Produces short-lived HMAC-signed SSO tokens.
- Produces exact route `GET /admin/transfer-proxy`, which posts the token to `/admin/transfer-proxy/sso` without placing it in URL history.

- [ ] Add failing tests for admin-only access, no-store headers, token expiry/tamper rejection, and menu visibility.
- [ ] Implement signed tokens and the auto-submit handoff page with a no-JavaScript fallback.
- [ ] Add the Transfer Proxy menu consistently to all admin workspaces.
- [ ] Run focused auth/navigation tests until green.
- [ ] Commit the admin relay entry point.

### Task 5: Relay prefix, SSO, CSRF, and internal transfer feed

**Files:**
- Create: `integrations/proxy-relay/app.py`
- Create: `integrations/proxy-relay/checker.py`
- Create: `integrations/proxy-relay/templates/index.html`
- Create: `integrations/proxy-relay/templates/duplicates.html`
- Create: `integrations/proxy-relay/templates/login.html`
- Create: `integrations/proxy-relay/static/app.css`
- Create: `integrations/proxy-relay/tests/test_app.py`
- Create: `integrations/proxy-relay/tests/test_checker.py`
- Create: `integrations/proxy-relay/requirements.txt`

**Interfaces:**
- Consumes `RELAY_URL_PREFIX=/admin/transfer-proxy` and `RELAY_SHARED_SECRET`.
- Produces `POST /admin/transfer-proxy/sso` and loopback-only `GET /internal/feed`.
- Transfer feed returns only fixed client endpoint data and never upstream credentials.

- [ ] Port current production relay source into the repository and prove its existing tests pass.
- [ ] Add failing tests for prefixed URLs, distinct scoped cookies, signed SSO, CSRF on mutations, and authenticated internal feed output.
- [ ] Implement the minimum prefix/security/feed changes without altering proxy mappings or checker logic.
- [ ] Run all relay Python and Go tests until green.
- [ ] Commit the integrated relay source.

### Task 6: Durable runtime and production routing

**Files:**
- Modify: `app/__init__.py`
- Modify: `deploy/earn-proxy-web.service`
- Modify: `deploy/earn-proxy-checker.service`
- Modify: `deploy/earn-proxy-earnapp.service`
- Modify: `deploy/earn-proxy-maintenance.service`
- Modify: `deploy/earn-proxy-payout-verifier.service`
- Modify: `deploy/Caddyfile`
- Modify: `.env.example`
- Test: `tests/test_hardening.py`
- Test: `tests/test_ui_contract.py`

**Interfaces:**
- Consumes `EARN_PROXY_INSTANCE_PATH=/var/lib/earn-proxy/instance`.
- Routes `proxy.acacondos.com` to Earn Proxy except the prefixed relay workspace.
- Keeps legacy API paths on `earn.proxy.acacondos.com`; browser traffic redirects to the primary domain.
- Serves `whitelist.proxy.acacondos.com` as the stable whitelist hostname.

- [ ] Add failing configuration/routing tests.
- [ ] Move the production instance path outside immutable release directories.
- [ ] Implement Caddy routing and legacy API compatibility.
- [ ] Run configuration and full application tests until green.
- [ ] Commit routing/runtime hardening.

### Task 7: Full verification, deployment, and rollback checks

**Files:**
- Modify: `README.md`
- Modify: `scripts/smoke_ui.py`
- Modify: `scripts/audit_ui_interactions.py`

**Interfaces:**
- Produces a versioned Earn Proxy release and a backed-up relay application update.
- Preserves rollback symlinks, both SQLite databases, environment files, and Caddy configuration.

- [ ] Run full pytest, Ruff, format, compile, package, and dependency checks.
- [ ] Run security audit checks over authentication, payout math, API secrets, SSO, CSRF, and reverse-proxy boundaries.
- [ ] Commit and push the verified repository.
- [ ] Back up production DBs/configs, deploy both applications, create the whitelist DNS record, and validate Caddy before reload.
- [ ] Verify all services, public health, old/new API compatibility, payout pages, relay listeners, and journals.
- [ ] Audit desktop/mobile UI in Chrome profile 40 and confirm no console errors or horizontal overflow.

