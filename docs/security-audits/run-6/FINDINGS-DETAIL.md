# Run-6 Finding Details

## MEDIUM — Local users can take over loopback CDP

### Pre-fix data flow

1. `deploy/earn-proxy-proxiware-chrome.service` launched Chrome as
   `earnproxy-chrome` with TCP CDP on `127.0.0.1:9222`.
2. `app/services/proxiware_browser.py:CdpProxiwareBrowser` called
   `connect_over_cdp` without an OS-user authentication boundary.
3. Any local user connected to the loopback socket and obtained the browser
   context, cookies, and JavaScript execution capability.

### Reproduction

From an unprivileged local account:

```text
GET http://127.0.0.1:9222/json/version
GET ws://127.0.0.1:9222/devtools/page/<target>
Runtime.evaluate(document.cookie)
```

The dynamic proof succeeded as `nobody` before remediation.

### Remediation

`app/proxiware_cdp_acl.py` installs a nftables owner rule before UFW output
accepts. Only `earnproxy-browser` may initiate TCP connections to port 9222.
Chrome requires the ACL service; browser and swap units use the dedicated UID.

## HIGH — Root release follows a raceable DB path

### Pre-fix data flow

1. A compromised `earnproxy` process could write inside
   `/var/lib/earn-proxy`.
2. `deploy/release.sh` passed `$database_path` to root path-based `chown` and
   `chmod`.
3. Leaving `earn-proxy.db` as a symlink before the release redirected root
   metadata changes to the symlink target; a narrow race was unnecessary.

### Remediation verification

`deploy/secure_runtime_permissions.py` opens the path with `O_NOFOLLOW`, checks
`fstat` for a regular file, and applies `fchown`/`fchmod` to the descriptor.
The release invokes this helper from the archived revision, pins the SQLite
backup source through `/proc/self/fd`, and restricts production to the direct
`/var/lib/earn-proxy/earn-proxy.db` path. Tests cover regular files, main DB
and sidecar symlinks, optional sidecars, and removal of direct path operations.
