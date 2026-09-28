# Security Audit Report: Run 8

## Executive summary

Run 8 found no new confirmed exploitable vulnerability in the deployed
Proxiware browser, dashboard, account-scope, swap, timeout, or distribution
paths at commit `37fec2e5fb957abc9d85dc69d385f3a56a7eb028`.
Production verification confirms the release is healthy, isolated, read-only
by default, and fail-closed around uncertain mutations. Automatic swap and
Proxiware distribution remain off because the prior approved canary did not
prove a successful provider swap.

## Findings

No finding met the exploitability and impact threshold.

## Rejected candidates

- **Wrong provider account or subscription:** rejected. The active browser
  session returned a verified, non-suspended account whose normalized email
  hash matched the configured account. Dashboard observations and swap scope
  checks bind subscription `39277` and require exactly one matching numeric
  assignment before any mutation request.
- **Duplicate mutation after timeout:** rejected. A job enters a durable,
  non-reclaimable mutation fence before provider I/O. Timeout or uncertain
  completion moves it to reconciliation-required state, disables automatic
  swap, and prevents reclaim, cancel, retry, or stale success completion.
- **Late detached adapter result marks success:** rejected. The detached call
  cannot write database state; only the runner can persist the result, and it
  freezes the job after the bounded wait expires.
- **Browser GET/POST race as an external exploit:** rejected. Fresh provider
  scope is checked immediately before mutation, response identity is checked
  after mutation, and no concrete attacker path to alter the authenticated
  provider account or response between those boundaries was identified.

## Verification results

- Full suite: `751 passed, 1 skipped in 648.07s`.
- Focused production gate: `171 passed in 120.02s`.
- Independent browser/scope review: `133 passed`.
- Independent timeout/state review: `76 passed`.
- Final acceptance/browser/swap subset in clean gate venv: `58 passed`.
- Ruff check: `All checks passed!`.
- Ruff format: `119 files already formatted`.
- Compileall: passed.
- Clean gate venv `pip check`: `No broken requirements found.`.
- Production release `pip check`: `No broken requirements found.`.
- `git diff --check`: passed.
- Secret scan of tracked source found no private key or credential literal.

## Production evidence

- Release `/opt/earn-proxy-37fec2e`; rollback `/opt/earn-proxy-c1c041d`.
- Redacted production preflight: every check true; `provider_mutation_calls=0`.
- All 11 service units enabled and active; `NRestarts=0`.
- Local and public health HTTP 200.
- CDP bound to `127.0.0.1:9222`; web bound to `127.0.0.1:8100`.
- Browser and qualification workers sleeping with fresh heartbeats; no active
  qualification or swap claims.
- Two fresh dashboard observations completed more than one configured browser
  interval apart.
- Account read-only evidence: verified, non-suspended, configured-email hash
  match. No email, cookie, token, API key, or password was recorded.
- `proxiware_auto_swap=0`; `proxiware_distribution_enabled=0`; browser mutation
  disabled.

## Canary status

The approved canary for `82.39.234.38:1337`, owner `kalinh`, 15-minute window,
ran once and returned `provider_error`. Read-only reconciliation confirmed no
provider change. Job 3 is blocked with one attempt; no replacement mapping was
created and no retry occurred. Jobs 1 and 2 are also blocked historical failed
attempts. A new provider mutation requires a new explicit target approval.

## Hardening notes

- Keep automatic swap and distribution off until one newly approved canary
  proves provider success, fresh read-only reconciliation, replacement
  readiness, and requalification.
- Keep the CDP ACL coupled to Chrome and browser-worker units.
- Treat a mutation timeout as an unknown provider outcome; reconcile read-only
  before any operator decision.
- The generic workstation Python environment has unrelated package conflicts;
  use the repository gate venv and production venv as authoritative dependency
  environments.

## Positive controls

- Browser origin, endpoint, subscription, assignment, response identity, and
  response address are validated.
- Session cookies and assignment credentials are encrypted with dedicated
  worker material and are absent from logs and UI.
- Mutation is disabled by default and isolated from observation.
- Unsafe provider states are excluded from distribution.
- Release backup, rollback, service health, heartbeat, and dependency checks
  are automated and redacted.

## Conclusion

The deployed read-only Proxiware integration and guarded mutation code pass the
current test, static, dependency, security, preflight, and observation gates.
The system is not approved for automatic swapping: a successful separately
approved canary remains mandatory.

