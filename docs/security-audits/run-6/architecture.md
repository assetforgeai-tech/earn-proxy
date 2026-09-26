# Security Audit Run 6: Release and Browser Boundaries

## Scope

Run 6 reviewed the `earn-proxy` Flask application, its systemd workers, the
isolated Proxiware Chromium boundary, and the versioned release script. The
separate `CashPilot` repository was out of scope and was not modified. Provider
mutation and distribution remained disabled during the audit.

## Trust model

- `earnproxy` runs the web app and ordinary workers and can write the runtime
  SQLite database.
- `earnproxy-browser` runs the read-only dashboard observer and guarded swap
  worker; it shares the database group but is the only approved CDP client.
- `earnproxy-chrome` owns the isolated, ephemeral Chromium profile and serves
  the loopback CDP endpoint.
- Root runs release installation and systemd management.
- Anonymous users, contributors, admins, provider APIs, and browser state are
  separate trust boundaries enforced by Flask auth, typed provider adapters,
  systemd identities, filesystem modes, and release preflight.

## Key paths

- `app/proxiware_chrome_service.py` — Chromium command and loopback CDP bind.
- `app/services/proxiware_browser.py` — Playwright CDP client and provider
  origin/path checks.
- `deploy/release.sh` — root release, backup, permission, and rollback flow.
- `deploy/secure_runtime_permissions.py` — descriptor-safe DB permission update.
- `app/proxiware_cdp_acl.py` and
  `deploy/earn-proxy-proxiware-cdp-acl.service` — local owner ACL for CDP.
- `deploy/earn-proxy-proxiware-{chrome,browser,swap}.service` — privilege and
  lifecycle separation.

## Run-6 evidence

Before remediation, a local unprivileged `nobody` process opened
`127.0.0.1:9222`, obtained the CDP WebSocket, and could read/evaluate browser
state. Loopback binding alone did not provide a user boundary. The release
script also used path-based root `chown`/`chmod` on a database path inside a
group-writable runtime directory; a compromised `earnproxy` process could race
that path with a symlink during deployment. Legacy backup DB files were also
found with mode `0644` and were secured in place without deletion.

The remediation adds a nftables owner ACL before the CDP service, moves the
swap client to the dedicated browser identity, uses `O_NOFOLLOW` plus file
descriptor ownership/mode operations, and runs the helper from the archived
revision rather than the mutable checkout.
