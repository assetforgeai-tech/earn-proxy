# Security Audit Run 7: Proxiware Auth, Mutation, and Secret Boundaries

## Scope

Run 7 reviewed the Earn Proxy Proxiware admin routes, internal distribution
API, dashboard adapter, guarded swap state machine, systemd identities, and
release environment handling. `CashPilot` was out of scope and untouched.

## Trust boundaries

- Anonymous and contributor requests are separated from admin/provider actions
  by session authorization, CSRF checks, confirmation inputs, and rate limits.
- Official Proxiware API access remains read-only.
- Browser observation and swap execution run as `earnproxy-browser`; isolated
  Chrome runs as `earnproxy-chrome`; CDP is loopback plus owner-ACL protected.
- Provider mutations require fresh typed dashboard evidence, an active session,
  an explicit mutation flag, a durable job claim, and a non-reclaimable
  mutation fence.
- SQLite contains globally encrypted application secrets plus dedicated
  worker-key ciphertext for the Proxiware session and assignment credentials.

## Prior audit coverage

Runs 1-6 already covered authentication, CSRF, IDOR, distribution filtering,
browser origin/scope checks, CDP local-user takeover, and root release path
races. Run 7 targeted residual auth/API/swap logic and worker secret exposure.

## Result

No new exploitable auth, API, or swap vulnerability survived independent
validation. One defense-in-depth gap was confirmed before remediation: the
browser/swap workers loaded the global application Fernet key through
`/etc/earn-proxy.env`. The current worktree introduces a dedicated Proxiware
worker key, additive worker ciphertext columns, migration/backfill, worker app
profiles, and minimal worker environment files. This hardening must pass the
full release gate and production deployment verification before it is treated
as active.

## Canary evidence

The separately approved canary for `82.39.234.38:1337`, owner `kalinh`, window
15 minutes, executed once. The provider returned `provider_error`; no provider
success or replacement evidence was recorded. Job 3 is blocked after read-only
reconciliation proved no provider change. The original assignment remains;
auto-swap, distribution, and browser mutation remain disabled. No retry is
authorized because provider mutation is non-idempotent. Subsequent read-only
inspection of the provider UI captured the exact request contract: selecting
the row with UI key `ip:141952` sends numeric assignment ID `141952`. The
worktree corrects that boundary and adds regression coverage without executing
another provider mutation.
