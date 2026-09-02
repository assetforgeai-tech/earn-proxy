# Security Audit Run 1: Architecture and Trust Boundaries

## Scope and baseline

Earn Proxy is a self-hosted, multi-tenant Flask web application and internal
proxy-distribution API. Contributors submit HTTP/SOCKS5 proxy credentials;
background workers check reachability and EarnApp eligibility, accrue earnings,
and expose selected live proxies to approved internal clients. Administrators
approve users, tune checker policy, manage API keys, and approve/manual-transfer
payouts. This run audits the current worktree before release, including the
database-backed API-key lifecycle and read-only BSC payout verifier.

There are no prior security-audit runs under `docs/security-audits/`; findings
from this run are the new baseline and should be revisited after deployment.
The closest comparable is a small Flask/Gunicorn admin portal with SQLite-backed
Celery-style workers and a Caddy TLS reverse proxy. The intentional tradeoff is
single-node SQLite WAL and bearer API keys rather than a distributed queue or
mTLS integration network.

## Actors and intended capabilities

- **Anonymous visitor:** read login/registration/health pages and submit
  registration or login forms. Pending contributors cannot authenticate.
- **Active contributor:** manage only their own proxies, wallet, and payout
  requests. Proxy credentials are encrypted at rest and masked in the UI.
- **Active administrator:** manage contributor lifecycle, checker settings,
  API-key lifecycle, payout approval, and transaction submission.
- **Internal integration client:** present an active `X-API-Key` to read the
  canonical raw proxy feed (`/api/v1/proxies`) or compatibility alias
  (`/internal/api/v1/proxies`). The feed intentionally contains raw proxy
  credentials for the consuming internal system.
- **Background workers:** health, EarnApp, maintenance, and payout-verifier
  processes share the SQLite database and are deployed as restartable,
  unprivileged services.

## Application and deployment map

- Flask factory, production secret gate, blueprint registration, ProxyFix, and
  health endpoint: `app/__init__.py`.
- Session loading/decorators: `app/auth.py`; CSRF hook: `app/security.py`.
- SQLite schema, migrations, WAL/busy timeout: `app/db.py`.
- User/proxy/wallet/payout routes: `app/routes/*.py`.
- API-key generation/authentication/reveal vault: `app/services/api_keys.py`.
- Distribution API: `app/routes/internal_api.py`.
- Proxy parser, encryption, duplicate/egress reconciliation:
  `app/proxy_parser.py`, `app/crypto.py`, `app/services/proxies.py`.
- Health and EarnApp state machines: `app/checker.py`, `app/check_service.py`,
  `app/services/checks.py`, `app/earnapp_probe.py`.
- Earnings and payout accounting: `app/services/earnings.py`,
  `app/services/payouts.py`, `app/services/wallets.py`.
- BSC verification and worker: `app/services/payout_verification.py`,
  `app/payout_verifier_service.py`.
- Container/systemd isolation and TLS edge: `Dockerfile`, `docker-compose.yml`,
  `deploy/*.service`, `deploy/Caddyfile`.

Docker runs web, health-checker, EarnApp-checker, maintenance, payout-verifier,
and Caddy as separate restartable services. Native units run as `earnproxy`,
set `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`,
and allow writes only to `/var/lib/earn-proxy`. Caddy terminates TLS and the
  Flask app trusts one forwarded client-address and proto hop from Caddy.

## Trust boundaries and input surfaces

1. **Internet -> Caddy -> Flask/Gunicorn.** Public HTTP requests enter auth,
   contributor, admin, and health routes. All non-safe methods pass the global
   CSRF check before route logic.
2. **Browser -> persistence.** Registration is admitted through shared
   per-client/global SQLite rate buckets before password hashing. Proxy raw text, wallet addresses,
   payout amounts/transaction hashes, admin settings, user actions, and API-key
   names are validated before SQLite writes. Jinja templates escape stored text.
3. **API bearer token -> credential export.** A valid active DB key authorizes
   raw proxy credential export. Responses are marked `Cache-Control: no-store`.
4. **Worker -> user-supplied proxy endpoints.** Checker code resolves and pins
   public proxy hosts, invokes bounded curl/async probes, and records results
   through generation/claim-aware state transitions.
5. **Worker -> BSC RPC.** The payout verifier accepts only HTTPS RPC URLs that
   resolve to public IPs, pins one resolved address, preserves the original TLS
   hostname/SNI, disables redirects/retries, bounds response bytes, and parses
   JSON-RPC responses. It never signs or sends a transaction.
6. **Environment/bootstrap -> application.** Production refuses placeholder
   session/Fernet/API/admin secrets; startup imports the configured legacy API
   token as a digest-only revocable key and creates the configured admin.

## Authentication, authorization, and state controls

Session auth reloads the user from SQLite for every request and rejects missing,
inactive, or stale `session_version` records. `admin_required` requires the
exact `admin` role. CSRF tokens are random session values compared in constant
time for every state-changing request. API keys use `ep_live_` high-entropy
tokens; SQLite stores SHA-256 digests, prefixes, random public IDs, timestamps,
and revocation state. Browser one-time reveals use a short-lived server-side
encrypted vault and a consume-once random URL nonce; plaintext is not stored in
the session cookie or database.

Public registration returns the same accepted/pending response for a new or
existing email. Approved contributors are also bounded by a configurable active
proxy quota before parsing/encryption, preventing one account from creating an
unbounded durable checker backlog.

Payouts follow `requested -> approved -> verifying -> confirmed|failed`.
Reservations include all pending/approved/verifying/confirmed (and legacy
`sent`) states. Only an admin can submit a transaction hash; only the verifier
worker can apply a matching on-chain result, with a durable claim token to stop
stale workers from applying results after a replacement/retry.

## High-value review targets

- API-key bearer authentication, public-ID routing, one-time secret handling,
  revocation/rotation races, and last-used telemetry writes.
- RPC URL validation, DNS rebinding, TLS hostname verification, redirects,
  response-size limits, JSON-RPC parsing, and false confirmation states.
- Payout reservation, duplicate transaction replay, claim-token races,
  replacement of stuck verification, and legacy migration/index behavior.
- Proxy checker subprocess/network boundaries, scheduler claims, egress
  canonicalization, earnings accrual, and user/admin ownership checks.
- Template escaping, CSRF coverage, response caching, error disclosure,
  deployment restart/isolation settings, and 30k-row API load behavior.
