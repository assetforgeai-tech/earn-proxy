# Security Audit Run 3: Architecture and Trust Boundaries

## Scope and prior coverage

This source-first audit covers the Earn Proxy application and its local Transfer
Proxy relay after the split distribution API, whitelist-host presentation, Caddy
route correction, and responsive navigation changes. Runs 1 and 2 reported no
confirmed exploitable vulnerabilities after covering registration/login abuse,
API-key lifecycle, payout verification, egress attestation, proxy ownership,
worker claims, and relay exposure. This run revisited those boundaries and
focused on the public API feeds, SSO/relay handoff, user-visible whitelist data,
and deployment routing.

## Application and trust model

Earn Proxy is a Flask multi-tenant contributor portal backed by SQLite. Users
submit encrypted HTTP/SOCKS5 proxy credentials, see only masked host:port
identifiers, and receive earnings. Administrators approve users, manage checker
policy and API keys, and operate payouts. An authenticated internal consumer
uses either the raw feed (provider credentials) or the transfer feed (fixed VPS
listeners). Caddy terminates TLS and routes the application, relay, and a
read-only whitelist hostname.

Actors and intended capabilities:

- Anonymous visitors can view public pages and attempt registration/login.
- Active contributors can manage only their own proxy, wallet, and payout data.
- Administrators can manage users, policy, keys, payouts, and relay access.
- Internal API clients with an active bearer key can read eligible proxy feeds.
- Background workers check health, classify egress/EarnApp state, accrue
  earnings, archive persistently dead rows, and verify payout transactions.

## Key code and deployment paths

- `app/__init__.py`: production secret gate, blueprint registration, ProxyFix,
  domain and whitelist defaults.
- `app/auth.py`, `app/security.py`, `app/routes/auth.py`: sessions, roles, CSRF,
  login and registration controls.
- `app/routes/internal_api.py`: authenticated `/api/v1/proxy-raw` and
  `/api/v1/proxy-transfer` feeds and compatibility aliases.
- `app/routes/dashboard.py`, `app/templates/user_dashboard.html`: masked user
  display and whitelist hostname/IP guidance.
- `app/routes/admin.py`, `app/templates/admin_integrations.html`: API endpoint
  and key-management UI.
- `integrations/proxy-relay`: relay authentication, import/check/export paths.
- `deploy/Caddyfile`: primary, legacy, transfer, and whitelist host routing.
- `deploy/*.service`: restartable, restricted native services.

## Trust boundaries and controls reviewed

1. Internet -> Caddy -> Flask/Gunicorn: TLS edge headers, route ordering, auth,
   CSRF, and security headers.
2. Bearer API key -> credential export: digest lookup, revocation, active-user
   and freshness filters, canonical duplicate filtering, and no-store output.
3. Browser -> relay SSO: signed short-lived token, CSRF-protected state changes,
   loopback feed/HMAC boundary, and internal-only listener.
4. User proxy input -> workers: parser validation, encrypted persistence,
   bounded probes, claims, and duplicate/egress reconciliation.
5. User wallet -> payout verifier: state machine, reservation, chain/RPC
   validation, and no private-key signing.
6. Caddy whitelist host -> provider onboarding: static public hostname response
   containing only the configured relay IP; no application secret is exposed.

## Audit conclusion

The three independent focused reviews found no confirmed exploitable
vulnerability. Remaining observations are defense-in-depth recommendations,
not findings: make relay SSO nonces one-time-use, run relay services as a
dedicated unprivileged account, sanitize trusted forwarded-address handling,
add explicit no-store to authenticated relay HTML/export responses, and add
edge rate limiting/pagination before very large inventories.
