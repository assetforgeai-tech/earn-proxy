# Security Audit Run 4: Proxiware Control Plane

## Scope

This run covers the Proxiware provider control plane in `earn-proxy` only. It
does not cover or execute `CashPilot`, provider purchase/billing/renewal, live
swap mutation, or VPS deployment. Prior runs covered the contributor/auth/API,
payout, relay, and transfer boundaries; this run concentrates on provider
scoping, durable workers, browser/session fail-closed behavior, and the new
admin workspace.

## System and trust model

The target is a Flask 3 web application backed by SQLite, with separate sync,
qualification, and swap worker processes. Admin-only routes under
`/admin/providers/proxiware/*` are the control plane. The official provider API
client is read-only. Browser/session mutation is behind an injected adapter;
the shipped adapter is unavailable/dry-run and returns `manual_action_required`.

Actors:

- Anonymous users: public pages and authentication only.
- Contributors: their own proxy, wallet, and earnings views; no provider menu.
- Admins: provider workspace, credentials, policy, sync, qualification, and
  durable queue controls.
- Workers: provider-scoped database claims; no user earnings or quota writes.

## Trust boundaries and controls

1. Browser -> Flask: `admin_required`, global CSRF, no-store responses for the
   provider workspace, and bounded action rate limits.
2. Admin/API input -> SQLite: parameterized queries, allowlisted provider and
   action values, provider-specific unique indexes, and durable leases.
3. Provider API -> inventory: read-only `ProxiwareClient`, bounded timeouts,
   no redirects, payload shape validation, encrypted assignment credentials,
   and claim-token fencing.
4. Probe -> qualification/distribution: trusted global egress IP validation,
   identity fingerprint/generation fencing, duplicate egress reconciliation,
   stale/inconclusive fail-closed states, and independent distribution gate.
5. Browser/session -> swap: encrypted write-only secrets, isolated adapter
   boundary, hCaptcha-only contract, no fingerprint spoofing, and
   `manual_action_required` on unavailable or ambiguous flows.
6. Worker lifecycle -> SQLite: bounded batches, heartbeats, lease recovery,
   cancellation, finite retries, idle sleep, and provider-scoped emergency
   pause. The pause leaves distribution, earnings, hours, and quota unchanged.

## Audited input/sink surfaces

- Admin GET pages and filters: `app/routes/admin.py` and
  `app/templates/admin_proxiware.html`.
- Admin POST actions: credentials, policy, sync/cancel, session checks, queue
  actions, and provider automation pause/resume.
- Internal raw/transfer feeds: `app/routes/internal_api.py`.
- Official API response normalization: `app/services/proxiware.py`.
- Qualification and egress trust: `app/services/proxiware_qualification.py`.
- Durable swap state machine: `app/services/proxiware_swap.py` and
  `app/proxiware_swap_service.py`.
- Browser/session boundary: `app/services/proxiware_browser.py` and
  `app/services/proxiware_credentials.py`.

## Audit conclusion

No confirmed exploitable vulnerability was established in this run. The
browser mutation path remains intentionally unavailable, so no claim is made
that a real provider swap is production-authorized.
