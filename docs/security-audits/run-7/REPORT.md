# Security Audit Report: Run 7

## Executive summary

Run 7 found no new confirmed exploitable vulnerability in the Proxiware admin,
API, dashboard, or guarded swap paths. Authorization, CSRF, rate limiting,
provider scope validation, typed observations, mutation fencing, uncertain
outcome reconciliation, and distribution exclusion remained intact. The audit
did identify excessive secret exposure as a hardening gap: browser/swap workers
received the global application Fernet key. The current worktree replaces that
with a dedicated Proxiware worker key and independently encrypted worker copies
of session and assignment credentials. This is defense in depth, not a reported
vulnerability, because no demonstrated path let an external attacker first
compromise the worker account.

## Findings

No new findings met the exploitability and impact threshold.

## Rejected candidates

- Auth/API bypass: rejected; admin role, CSRF, confirmation, rate-limit, and
  provider-scope controls block the claimed paths.
- Duplicate/unguarded swap: rejected; mutation requires a durable claim and
  immutable `mutating` fence; uncertain outcomes cannot auto-retry.
- Distribution during mutation: rejected; pending, mutating,
  provider-applied, reconciliation-required, stale, duplicate, and disabled
  assignments are excluded.
- Worker global-key exposure as a standalone vulnerability: rejected; it
  requires prior local worker compromise and therefore lacks an independent
  external exploitation path. Retained as a remediated hardening note.

## Hardening completed in the worktree

- Separate worker app profile omits admin/API initialization requirements.
- Browser, swap, and qualification workers use minimal environment files.
- Dedicated Proxiware worker Fernet key; global Fernet key removed from worker
  environments.
- Additive worker ciphertext columns for provider cookies and assignment
  credentials; startup migration preserves original ciphertext.
- Release backup and rollback cover worker environment and key files with
  `root:root 0600` checks.

## Canary status

The approved canary ran once and did not prove swap success. Provider response:
`provider_error`; no replacement evidence; original mapping unchanged. Job 3
is blocked; no retry occurred. Read-only browser inspection later confirmed the
dashboard selection flow posts a numeric `assignment_id`; the deployed adapter
had incorrectly sent the UI-only `ip:` row-key prefix. The worktree now strips
that prefix and rejects non-numeric identities before provider I/O. Auto-swap
and distribution remain off; the failed canary was not retried.

## Positive controls

- Official API remains read-only.
- CDP remains loopback-only with an owner ACL.
- Mutation defaults off and is isolated from observation.
- Raw provider payloads, cookies, tokens, and credentials are not logged or
  rendered.
- Reconciliation uses fresh official sync plus dashboard evidence before any
  success state.

## Residual gate

The hardening diff still requires the complete test/static/dependency gate,
commit/push, release deployment, environment inspection, heartbeat/health
verification, and a read-only observation soak. Automatic swap must stay off;
the failed canary cannot authorize enablement.
