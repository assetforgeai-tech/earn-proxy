# Proxiware Auto-Renew and Auto-Swap Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Renew Proxiware sessions automatically through the configured 2Captcha hCaptcha solver and keep auto-swap polling/requalification correct after replacements.

**Architecture:** Add a small 2Captcha HTTP adapter, encrypt provider login secrets into the worker-only key, and let the browser worker renew sessions through the existing CDP browser. Preserve auto-swap intent across transient session failures; never mutate without an active session. Make replacement qualification retry on a short bounded interval instead of waiting an hour.

**Tech Stack:** Python 3.11, Flask, SQLite, requests, Playwright CDP, pytest.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`.
- Never log or return provider credentials, CAPTCHA keys, tokens, cookies, or fingerprints.
- Keep provider mutation fail-closed when session/login/reconciliation evidence is unavailable.
- Keep auto-swap and distribution independently controlled.
- No new runtime dependency; use existing `requests`.

### Task 1: Worker credential and 2Captcha adapter

**Files:**
- Modify: `app/services/proxiware_crypto.py`
- Modify: `app/services/proxiware_credentials.py`
- Create: `app/services/proxiware_captcha.py`
- Test: `tests/test_proxiware_crypto.py`
- Test: `tests/test_proxiware_captcha.py`

- [ ] Add worker-only encrypted credential storage/migration and a read helper.
- [ ] Add bounded `TwoCaptchaAdapter.solve_hcaptcha()` and `get_balance()` with redacted errors.
- [ ] Add tests for migration, success polling, timeout, malformed responses, and key non-disclosure.

### Task 2: CDP login renewal

**Files:**
- Modify: `app/services/proxiware_browser.py`
- Modify: `app/services/proxiware_credentials.py`
- Test: `tests/test_proxiware_browser.py`
- Test: `tests/test_admin_proxiware.py`

- [ ] Implement login-page navigation, fingerprint collection, `/api/auth/login` POST, and cookie extraction.
- [ ] Keep origin/path/response validation and reject missing fingerprint/cookies.
- [ ] Make renewal load worker-only secrets in worker profile while preserving web tests.

### Task 3: Automatic renewal and swap-state recovery

**Files:**
- Modify: `app/proxiware_browser_service.py`
- Modify: `app/proxiware_swap_service.py`
- Modify: `app/services/proxiware_credentials.py`
- Modify: `app/routes/admin.py`
- Test: `tests/test_proxiware_browser_service.py`
- Test: `tests/test_proxiware_swap_service.py`
- Test: `tests/test_admin_proxiware_actions.py`

- [ ] Renew inactive sessions once per bounded cooldown using 2Captcha.
- [ ] Preserve explicit auto-swap intent and restore it only after successful renewal.
- [ ] Keep mutation worker idle until renewal succeeds; do not perform blind retries.

### Task 4: Replacement qualification retry

**Files:**
- Modify: `app/services/proxiware_qualification.py`
- Test: `tests/test_proxiware_qualification_integration.py`
- Test: `tests/test_proxiware_qualification_service.py`

- [ ] Use a short bounded retry interval for fresh post-swap assignments while result is pending/inconclusive.
- [ ] Return to the normal hourly interval after a conclusive allow/risk/dead result.

### Task 5: Verification and deployment

- [ ] Run focused RED/GREEN tests, full pytest, Ruff, compile checks.
- [ ] Commit and push `main`.
- [ ] Deploy production release with site key/runtime settings, preserve mutation permission.
- [ ] Verify worker env, service health, CDP, renewal heartbeat, auto-swap state, and zero unintended swap jobs.
