# Proxiware Operations Runbook

## Scope

This runbook covers the Proxiware provider integration in `earn-proxy`. It does
not authorize purchase, billing, subscription creation, renewal, or changes to
CashPilot.

## Required configuration

Keep values in the deployment secret file, never in Git:

- `EARN_PROXY_PROXIWARE_API_BASE_URL`
- `EARN_PROXY_PROXIWARE_API_KEY_FILE`
- `EARN_PROXY_PROXIWARE_SYNC_INTERVAL_SECONDS`
- `EARN_PROXY_PROXIWARE_SYNC_RETRY_LIMIT`
- `EARN_PROXY_PROXIWARE_SYNC_RETRY_BACKOFF_SECONDS`

Browser/session credentials are entered from the admin provider workspace and
are encrypted at rest. They are write-only in the UI.

## Preflight

1. Run migrations against a disposable database.
2. Run `python -m pytest -q`.
3. Run the lint, format, compile, and dependency checks from `README.md`.
4. Run the Proxiware worker with `--once` using mocked provider responses.
5. Confirm auto-swap is `OFF`.
6. Confirm no credentials appear in HTML, logs, SQL results, or query strings.

## Normal operation

Use `Admin -> Providers -> Proxiware`:

- `Overview`: inspect session, worker, sync, and queue health.
- `Inventory`: search/filter normalized subscriptions and assignments.
- `Qualification`: review live and qualification states.
- `Swap queue`: inspect durable jobs and safe error codes.
- `Sync`: inspect counts, latency, cancellation, and redacted failures.
- `Session`: inspect expiry and connection state without rendering cookies.
- `Credentials`: update write-only encrypted credentials.
- `Policy`: change bounded worker controls; auto-swap and provider distribution are
  independent and default `OFF`.
- `Swap history`: inspect immutable old/new mapping metadata.
- `Audit`: inspect redacted operator actions.

The `Pause Proxiware automation` control stops automatic sync, qualification, and
swap workers. It does not change provider distribution, contributor earnings,
online hours, quota, or another provider. Resume only after the incident is
understood. A separate swap-worker pause remains available for narrower queue
maintenance.

## Incident handling

- `manual_action_required`: leave auto-swap paused; inspect `Session` and
  `Credentials`, then renew only after verifying the provider account and
  challenge state.
- repeated `provider_timeout`: inspect provider availability and network path;
  do not increase retry limits blindly.
- stale inventory: run a read-only sync and inspect `Sync` before taking
  any swap action.
- duplicate active swap: stop the worker and inspect the durable job claim;
  never run a second process against the same SQLite database.

## Rollback

Pause Proxiware automation first, then stop the Proxiware workers, preserve the
database and Fernet key together, and
roll back to the previous application release using the existing release
script. Keep auto-swap disabled until a fresh dry-run passes.

## Failure and recovery states

- `stale`: follow the linked `Sync` or worker health page; do not infer that
  inventory is current from a successful HTTP response alone.
- `blocked`: inspect `Swap queue`, `Session`, and `Policy`; never blind-retry a
  provider or challenge error.
- `inconclusive` or `unknown`: keep the assignment out of distribution and swap
  until a bounded qualification run produces a trusted result.
- `manual_action_required`: the browser adapter is unavailable or the provider
  rejected a session/challenge flow. The safe outcome is manual review, not a
  simulated success.

## Production gate

The first real swap requires a separately recorded pilot approval. The
implementation and dry-run must never perform a production swap.
