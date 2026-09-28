# Security Audit Run 8: Proxiware Production Verification

## Scope

Run 8 reviewed commit `37fec2e5fb957abc9d85dc69d385f3a56a7eb028`
after deployment. The scope covered the Proxiware browser adapter, dashboard
observation, account and subscription scope, guarded swap state machine,
timeout handling, distribution exclusion, service isolation, and production
release evidence. `CashPilot` remained out of scope and untouched.

## Trust boundaries

- Official Proxiware API operations remain read-only.
- Dashboard observation uses the fixed HTTPS Proxiware origin and exact API
  paths through an isolated Chrome profile.
- CDP listens only on `127.0.0.1:9222` and is restricted to the dedicated
  browser worker identity.
- A provider mutation requires explicit mutation enablement, fresh typed
  dashboard evidence, subscription and assignment scope validation, a durable
  claim, and a non-reclaimable mutation fence.
- Timeout or uncertain provider outcomes enter reconciliation-required state,
  disable automatic swap, and cannot be retried automatically.
- Provider assignments remain excluded from distribution while disabled,
  stale, duplicate, pending, mutating, or awaiting reconciliation.

## Production evidence

- Active release: `/opt/earn-proxy-37fec2e`.
- Rollback release: `/opt/earn-proxy-c1c041d`.
- All 11 service units are enabled and active; `NRestarts=0`.
- Local and public `/healthz` return HTTP 200.
- Automatic swap and Proxiware distribution remain disabled.
- Two dashboard observations more than one configured worker interval apart
  completed successfully. The second snapshot was newer than the first and no
  qualification or swap claim remained stranded.
- The browser session is active. A read-only `/api/account` request returned a
  verified, non-suspended account. Its normalized email hash matched the
  configured account email hash without exposing either value.
- Subscription `39277` and its ten current assignments were observed with
  typed assignment IDs, eligibility, connection counts, and fresh timestamps.

## Prior audit coverage

Runs 1-7 covered application authentication, CSRF, IDOR, proxy parsing,
distribution policy, local CDP takeover, root release path races, worker secret
isolation, and guarded mutation behavior. Run 8 concentrated on deployed
browser/account scope and timeout/state-machine residual risk.

## Result

No new exploitable vulnerability survived validation. Two independent review
tracks inspected browser/account scope and timeout/state-machine behavior, then
ran focused regression suites. The only incomplete production gate is a
successful provider canary: the previously approved canary returned
`provider_error`, was reconciled as no provider change, and was not retried.
