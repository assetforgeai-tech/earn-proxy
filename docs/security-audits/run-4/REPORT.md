# Security Audit Report: Run 4

## Executive summary

Run 4 reviewed the Proxiware provider control plane after lease fencing,
identity fencing, egress safety, provider-scoped administration, and emergency
pause changes. Focused tests, adversarial disposable-database checks, static
analysis, and secret-redaction checks found no confirmed exploitable issue. The
real browser mutation adapter is still fail-closed and unverified; therefore
live swap automation remains `manual_action_required` and is not production
approved.

## Scope and evidence

- Admin routes, CSRF, admin authorization, provider scoping, rate limits, and
  direct-linkable workspace routes.
- Read-only official API client, payload validation, timeout/redirect behavior,
  encrypted credentials, session metadata, and audit redaction.
- Sync lease reclaim/fencing, qualification claim/generation fencing, duplicate
  egress, cooldown, distribution exclusion, and swap revalidation.
- Worker heartbeat, bounded retry, idle behavior, restart recovery, and global
  Proxiware automation pause.
- Disposable preflight with auto-swap/distribution disabled and no provider or
  swap calls.

## Findings

| Severity | Result |
|---|---|
| Critical/High/Medium/Low | None confirmed |

`findings.json` is an empty array. No purchase, billing, renewal,
subscription mutation, real swap, VPS command, or CashPilot operation was
performed.

## Positive controls

- Every Proxiware read/mutation path is admin-only and provider-scoped.
- State-changing forms use CSRF and provider action rate limits; responses are
  no-store.
- Provider secrets and session cookies are encrypted/write-only; audit and error
  values are allowlisted/redacted.
- Official API calls use bounded timeouts, no redirects, and read-only methods.
- Sync and qualification stale workers cannot finalize over a reclaimed lease or
  changed assignment identity.
- Private, loopback, link-local, multicast, unspecified, and test egress values
  are rejected outside explicit test fixtures.
- Distribution excludes stale, dead, ambiguous, duplicate, cooldown, and active
  swap records.
- Browser adapter absence fails closed as `manual_action_required`.
- Emergency pause covers sync, qualification, and automatic swap workers while
  preserving distribution and contributor accounting.

## Hardening notes

- Keep the browser adapter disabled until a separately reviewed, authorized,
  persistent-profile flow is proven against the provider UI.
- Keep API keys and Fernet keys outside Git and rotate them through deployment
  secret storage.
- Add edge rate limiting and metrics for very large inventories before scaling
  beyond the tested SQLite workload.
- Treat the disposable preflight as a release gate; never run it against a
  production database with provider credentials.
