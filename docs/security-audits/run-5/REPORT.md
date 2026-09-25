# Security Audit Report: Run 5

## Executive summary

Run 5 found one confirmed LOW-severity input/resource issue: an unauthenticated
caller could submit a nearly 1 MiB registration email, persist it in SQLite,
and make the unpaginated admin user page load/render oversized values. The
issue was reproduced against a disposable database, then fixed in this
worktree with a shared 254-character limit, route checks, service-boundary
validation, and HTML `maxlength` attributes. No confirmed auth bypass, IDOR,
SSRF, XSS, provider-scope bypass, swap replay, secret disclosure, or browser
mutation vulnerability was found.

## Findings

| Severity | Finding | State |
|---|---|---|
| LOW | Oversized registration email causes storage/admin-rendering DoS | Fixed in worktree |

### LOW — Oversized registration email causes storage/admin-rendering DoS

Before the fix, `POST /register` accepted a unique value of approximately
900 KB because validation checked only for `@` and password length. The value
was inserted into the unbounded SQLite `users.email` TEXT column. The admin
`/admin/users` route selected every user and the template rendered every email.
The disposable-database reproduction returned HTTP 201 and stored an email of
length 900006. With the configured registration buckets, a distributed caller
could sustain storage and admin-rendering pressure. Impact is limited to
resource exhaustion, so severity is LOW.

The fix validates normalized email length before `create_user`, enforces the
same limit in `create_user` for non-HTTP callers, and adds client-side
`maxlength="254"` hints. The admin list remains a pagination hardening item
for large legitimate inventories; it is not needed to close the reproduced
oversized-input path.

## Hardening notes

- Add pagination to `/admin/users` before inventories become very large.
- Keep browser/CDP bound to loopback and run it under the dedicated
  `earnproxy-browser` account.
- Keep the Chrome launcher on its separate `earnproxy-chrome` account and
  Chrome-only environment file; never grant it the application secret file.
- Keep automatic swap and Proxiware distribution disabled until a separately
  approved canary has fresh production browser/session evidence.
- The automatic queue caller is intentionally not enabled in this release;
  manual swap and observation remain fail-closed.

## Positive controls

- Auth paths use dummy password verification and shared rate limiting.
- API keys are stored as digests and reveal tokens are one-time/no-store.
- Provider actions are admin-only, CSRF-protected, rate-limited, and audited.
- Dashboard snapshots enforce fixed origin, subscription scope, freshness, and
  atomic replacement of observed rows.
- The Chrome launcher receives only browser-specific configuration, uses a
  separate Unix account, and cannot read the application database path.
- Swap mutation enters a durable non-reclaimable state and uncertain outcomes
  require read-only reconciliation; no automatic retry is performed.
- Distribution excludes stale, duplicate, ambiguous, pending, and active
  mutation records.

## Conclusion

The confirmed Run 5 issue is fixed and regression-tested. Browser/session
production evidence and a canary are still intentionally absent; therefore
this audit does not authorize automatic swap or production mutation.
