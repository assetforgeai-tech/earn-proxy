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

Browser observation is separate from the official API sync. Keep these values
disabled until the isolated browser profile is provisioned and manually
verified:

- `EARN_PROXY_PROXIWARE_CHROME_ENABLED=0`
- `EARN_PROXY_PROXIWARE_BROWSER_ENABLED=0`
- `EARN_PROXY_PROXIWARE_BROWSER_ALLOW_MUTATION=0`
- `EARN_PROXY_PROXIWARE_CDP_URL=http://127.0.0.1:9222`
- `EARN_PROXY_PROXIWARE_CHROME_PROFILE_DIR=/run/earn-proxy-browser/profile`

Put Chrome-only values in `/etc/earn-proxy-browser.env` with mode `0600`.
Do not reuse `/etc/earn-proxy.env`; the Chrome process must not receive the
database, Fernet, API, or admin secrets. The Chrome unit runs as the separate
`earnproxy-chrome` account, uses an ephemeral systemd runtime profile, and
binds CDP to loopback. It does not log in, solve challenges, spoof a
fingerprint, or perform a provider mutation. A missing binary/profile/session
keeps the observer `manual_action_required` or disabled.

Browser/session credentials are entered from the admin provider workspace and
are encrypted at rest. They are write-only in the UI.

### Operator-assisted session import

When the provider requires hCaptcha, do not automate or bypass the challenge.
Open the provider in the approved operator Chrome profile, complete the login
and challenge manually, then pipe only the current Proxiware cookie JSON over
the existing SSH channel. The importer validates the `app.proxiware.com`
origin, encrypts the cookie blob immediately, stores only safe expiry metadata,
and prints no cookie value:

```powershell
agent-browser --cdp 9222 cookies get --json |
  powershell -NoProfile -Command '$x = $input | ConvertFrom-Json; $c = if ($x.data.cookies) { $x.data.cookies } elseif ($x.cookies) { $x.cookies } else { $x }; @($c | Where-Object { $_.domain -and ($_.domain -eq "app.proxiware.com" -or $_.domain -eq ".proxiware.com" -or $_.domain -like "*.proxiware.com") }) | ConvertTo-Json -Compress' |
  ssh -p 26266 kalinh@42.96.12.142 "sudo -n bash -lc 'set -a; . /etc/earn-proxy.env; set +a; cd /opt/earn-proxy; /opt/earn-proxy/.venv/bin/python scripts/proxiware_session_import.py --database /var/lib/earn-proxy/earn-proxy.db'"
```

Verify the admin Session page reports `active`, then enable only the isolated
Chrome and browser observer units for a read-only soak. Keep swap mutation and
provider distribution disabled. If the session is rejected, the worker returns
`manual_action_required`; clear the session and repeat the manual login.

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
- `degraded`: a bounded transport/provider read failed. The observer records a
  safe error code and schedules that subscription with exponential backoff;
  it does not invalidate an otherwise active session.
- `reconciliation_required`: a swap response was not enough to prove the new
  provider assignment. Do not retry the mutation. Run official read-only sync,
  wait for a fresh dashboard observation, and resolve the replacement by
  subscription plus address before any later action.
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

## Release and observation rollout

Run the redacted preflight against a disposable database first, then collect
the production report without provider calls:

```bash
python scripts/proxiware_preflight.py --database /var/lib/earn-proxy/earn-proxy.db --production
```

The report includes branch/release and rollback paths, service state, safe
heartbeat ages, session state, local/public health, adapter flags, and backup
presence. It never prints credentials, cookies, CAPTCHA tokens, or provider
payloads. Deploy with `deploy/release.sh <commit-sha>`, keep swap and
distribution `0`, enable only Chrome plus dashboard observation, and observe
at least two scheduled intervals before requesting any mutation approval.
