# Prox.io Egress Probe Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `api.prox.io.vn` as an independently parsed HTTPS egress observation while preserving multi-provider quorum and failure-safe proxy health decisions.

**Architecture:** Treat every probe endpoint as a typed source instead of assuming that every successful body is a bare IP literal. Prox.io contributes the JSON `ip` field to the same two-independent-host HTTPS quorum used today; its Cloudflare socket address (`curl %{remote_ip}`) is transport metadata only and never becomes proxy identity. Existing endpoint circuit breakers and `inconclusive` handling isolate third-party failures.

**Tech Stack:** Python 3.11+, curl subprocess probes, pytest, Flask checker service, standalone Transfer Proxy integration.

## Global Constraints

- Work only in `D:\1. WORK_true\Tranfer Proxy\earn-proxy`; do not modify CashPilot.
- Use only `GET https://api.prox.io.vn/v1/check/whoami`; do not submit fingerprints or create reports.
- Never use curl `%{remote_ip}`, DNS answers, or Cloudflare edge addresses as `exit_ip`.
- Prox.io is one observation source, not a single source of truth; strong checks still require two matching independent HTTPS hosts.
- A Prox.io timeout, malformed payload, `429`, or `5xx` must remain a probe-endpoint failure and must not independently mark a proxy dead.
- Keep credentials out of command arguments and logs.

---

### Task 1: Define typed response parsing

**Files:**
- Modify: `tests/test_checker.py`
- Modify: `integrations/proxy-relay/tests/test_checker.py`
- Modify: `app/checker.py`
- Modify: `integrations/proxy-relay/checker.py`

**Interfaces:**
- `parse_probe_exit_ip(probe: str, body: str) -> str` returns a normalized literal IP or an empty string.
- Text endpoints continue accepting bare IPv4/IPv6 bodies.
- `/v1/check/whoami` accepts only a JSON object containing a valid `ip` field.

- [ ] Write regression tests proving JSON `ip` is accepted and JSON metadata, malformed JSON, markup, and socket metadata are rejected.
- [ ] Run focused tests and observe the expected missing-function/failed-parse result.
- [ ] Implement the smallest endpoint-aware parser in both checker runtimes.
- [ ] Run focused tests and confirm they pass.

### Task 2: Add Prox.io to HTTPS quorum and rotation

**Files:**
- Modify: `app/checker.py`
- Modify: `integrations/proxy-relay/checker.py`
- Modify: `tests/test_checker.py`
- Modify: `integrations/proxy-relay/tests/test_checker.py`

**Interfaces:**
- `PROBE_URLS` contains four independent HTTPS hosts including `https://api.prox.io.vn/v1/check/whoami`.
- Fast checks rotate through the new endpoint normally.
- Strong checks accept Prox.io only as one member of a two-host matching quorum.

- [ ] Write tests for two-host quorum with one Prox.io response and for a Prox.io-only disagreement.
- [ ] Run the tests and observe RED.
- [ ] Route quorum parsing through `parse_probe_exit_ip` and add the endpoint.
- [ ] Run checker and runner suites and confirm GREEN.

### Task 3: Verify, commit, deploy, and observe

**Files:**
- Modify: `README.md` with the probe policy and observed capped test result.

**Interfaces:**
- Native Earn Proxy deploy uses `deploy/release.sh <commit>` and automatic rollback.
- Transfer Proxy deploy updates only the checked-in integration files and restarts its manager after backup.

- [ ] Run complete pytest, Ruff, format check, compileall, pip check, and `git diff --check`.
- [ ] Commit and push the tested revision.
- [ ] Deploy Earn Proxy through the versioned release script, then update the Transfer Proxy checker with a timestamped backup.
- [ ] Verify systemd services, local/public health, a direct Prox.io observation, and representative proxy observations.
- [ ] Confirm no production check-all job was started and report observed API performance separately from any SLA claim.
