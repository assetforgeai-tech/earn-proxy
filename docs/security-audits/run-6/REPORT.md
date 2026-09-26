# Security Audit Report: Run 6

## Executive summary

Run 6 confirmed two deployment-boundary vulnerabilities. A loopback-only CDP
listener was reachable by every local user, allowing a local unprivileged
process to read the Proxiware browser session and evaluate JavaScript. The
root release script also followed a replaceable database path while changing
ownership and mode, creating a symlink/TOCTOU path to root file metadata
changes. Both issues are fixed in the current worktree: CDP access is limited
by a nftables owner ACL and dedicated systemd identities; DB permission and
backup reads use descriptor-safe `O_NOFOLLOW` operations from the immutable
release, with the production database path fixed under `/var/lib/earn-proxy`.
The
stored browser session was invalidated before remediation. Legacy world/group
readable backup DB files were tightened to `root:root 0600`.

## Findings

| Severity | Finding | State |
|---|---|---|
| MEDIUM | Local users can take over loopback CDP | Fixed and verified in production |
| HIGH | Root release follows a raceable DB path | Fixed and verified in production |

### MEDIUM — Local users can take over loopback CDP

The pre-fix Chrome unit bound CDP to `127.0.0.1:9222`. `connect_over_cdp` then
attached the observer to that endpoint. A dynamic proof run as `nobody` reached
the endpoint and demonstrated CDP access. Any local account able to execute a
process could therefore read cookies, inspect pages, or evaluate JavaScript in
the provider session. This is a credential/session disclosure and provider
control-plane takeover risk, not merely a port-discovery issue.

The fix installs a high-priority nftables output rule that accepts port 9222
only for `earnproxy-browser` and rejects other local UIDs. Chrome requires and
binds to the ACL service; the observer and guarded swap worker use the dedicated
browser identity. A temporary production probe verified `nobody` was rejected
while `earnproxy-browser` received HTTP 200 from a test listener.

### HIGH — Root release follows a raceable DB path

Release `3082daf` called root `chown` and `chmod` directly on
`$database_path` and its SQLite sidecars. The runtime directory is writable by
the `earnproxy` service account. A compromised process could leave the final
path as a symlink before a release, redirecting ownership or mode changes to a
selected root-owned target; no narrow timing race was required.

The fix extracts the helper from the selected Git revision, opens each file with
`O_NOFOLLOW|O_CLOEXEC`, requires a regular file, then uses `fchown`/`fchmod` on
the already-open descriptor. The SQLite backup also keeps a pinned source FD
through `/proc/self/fd`; missing WAL/SHM sidecars remain optional; the main DB
is required. Regression tests prove symlink targets are not changed.

## Production verification (2026-09-26)

- Release `/opt/earn-proxy-4970e92` is active; rollback `/opt/earn-proxy-96547a2`
  is present.
- All 11 Earn Proxy units are enabled and active with no current restart loop;
  local and public `/healthz` both returned HTTP 200.
- The live owner ACL allowed `earnproxy-browser` to reach a temporary loopback
  9222 listener and rejected `nobody` and `root`; the listener and probe files
  were removed afterward.
- The production database passed SQLite `quick_check`; the latest DB/env backup
  is root-owned with mode `0600`.
- `proxiware_auto_swap=0`, `proxiware_distribution_enabled=0`, browser mutation
  is disabled, and the stored provider session is `manual_action_required`.

Fresh manual session provisioning and the read-only browser observation soak are
still intentionally pending. No provider mutation was performed.

## Hardening notes

- Keep `proxiware_auto_swap=0` and `proxiware_distribution_enabled=0` until a
  fresh manual session and read-only observation soak are approved.
- Keep the CDP ACL and Chrome units enabled together; do not expose 9222 through
  SSH forwarding or a public bind.
- Retain backup directories as root-owned and backup DB/env files as `0600`.
- Repeat the local-user isolation probe after every systemd or firewall change.

## Positive controls

- Browser mutation remains disabled by default and fails closed.
- Provider dashboard requests enforce fixed origin, endpoint path, and
  subscription scope.
- Release directories are immutable to service users and health-checked before
  activation, with a rollback symlink.
- Session cookies are encrypted at rest and the pre-fix session was invalidated.
- SQLite sidecar permissions and worker umasks preserve group access without
  broadening world access.

## Conclusion

The two confirmed run-6 findings are fixed and deployment-verified. The safe
production state remains paused for Proxiware browser automation until an
operator provisions a fresh manual session and approves a read-only observation
soak. No provider mutation is authorized by this audit.
