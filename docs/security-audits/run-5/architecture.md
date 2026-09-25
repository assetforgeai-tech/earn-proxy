# Security Audit Run 5: Proxiware Release Boundary

## Scope

Run 5 reviewed the `earn-proxy` Flask application and the Proxiware control
plane on branch `fix/proxiware-dashboard-observation`. `CashPilot` was out of
scope and was not read, modified, or deployed. The review covered auth and
registration input limits, internal API distribution, dashboard observation,
isolated browser/CDP boundaries, swap fencing, worker lifecycle, release
units, secret handling, and the existing migration/deployment checks.

## System and trust model

The application is a Flask 3 service backed by SQLite. Anonymous callers can
register or sign in. Contributors can manage only their own proxy, wallet,
and earnings data. Admins can manage provider settings and queues. Separate
workers perform read-only provider sync, qualification, dashboard observation,
and guarded swap execution. The official Proxiware API is read-only; browser
mutation is disabled by default and fails closed without a valid adapter,
session, fresh evidence, and mutation fence.

## Key trust boundaries

1. HTTP input to auth/admin routes: CSRF, rate limits, normalized values, and
   role checks.
2. Provider API/dashboard to local state: typed payload validation, fixed
   origin/path, provider/subscription scope, freshness, and atomic snapshots.
3. Qualification to distribution: trusted egress attestation, duplicate
   exclusion, health freshness, policy, and active-swap exclusion.
4. Browser/session to swap: encrypted opaque cookies, loopback CDP, explicit
   adapter capability, durable mutation states, and reconciliation on uncertain
   outcomes.
5. Release to services: versioned release directories, DB backup, preflight,
   systemd restart/health verification, and rollback symlink.

## Audit coverage

Runs 1–4 previously found no confirmed vulnerabilities. Run 5 added focused
auth/API and browser/swap review plus dynamic registration input testing. The
only confirmed issue was a low-severity storage/admin-rendering denial of
service caused by oversized registration email values; the worktree now caps
emails at 254 characters at both route and service boundaries.
