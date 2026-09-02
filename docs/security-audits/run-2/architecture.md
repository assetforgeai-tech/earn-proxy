# Security Audit Run 2: Architecture and Trust Boundaries

## Scope and prior coverage

This second source-first audit covers the current Earn Proxy worktree after the
API-key lifecycle, payout verification, egress attestation, rate-limit, and
checker hardening changes. Earn Proxy is a self-hosted, multi-tenant Flask web
application with a small internal proxy-distribution API and SQLite-backed
workers. Contributors submit HTTP/SOCKS5 proxy credentials; workers check
reachability, egress identity, and EarnApp eligibility; earnings are accrued;
administrators manage users, policy, API keys, and payout review.

Run 1 documented and fixed three pre-release abuse paths: public registration
resource exhaustion, registration email enumeration, and an unbounded
per-contributor checker backlog. Run 2 specifically revisited those fixes and
expanded coverage across API-key rotation/revocation, one-time secret reveals,
payout state transitions and BSC verification, migration/rollback behavior,
egress attestation trust, proxy ownership, internal API exposure, and worker
claim races. No confirmed exploitable vulnerability remains in the reviewed
revision.

The closest baseline is a small Flask/Gunicorn administration portal behind a
Caddy TLS reverse proxy, with SQLite WAL and restartable background workers.
The intentional tradeoff is a single-node database and bearer API keys for an
internal integration rather than a distributed queue or mTLS service mesh.

## Actors and intended capabilities

- **Anonymous visitor:** view login/registration/health pages and submit a
  registration or login attempt. New accounts remain pending until approval.
- **Active contributor:** manage only their own proxy rows, wallet, and payout
  requests. Credentials are encrypted at rest and masked in the UI.
- **Active administrator:** approve/block users, tune checker and distribution
  policy, manage API keys, and approve/submit payout transactions.
- **Internal integration client:** present an active `X-API-Key` to read the
  canonical raw proxy feed at `/api/v1/proxies` (or its compatibility alias).
- **Background workers:** health, EarnApp, maintenance, and payout-verifier
  services share the SQLite database and use durable claims.

## Application and deployment map

- Flask factory, production secret gate, blueprint registration, forwarded
  header handling, and health endpoint: `app/__init__.py`.
- Session loading, role checks, and CSRF: `app/auth.py`, `app/security.py`.
- SQLite schema, migrations, WAL, and busy timeout: `app/db.py`.
- User, proxy, admin, wallet, and payout routes: `app/routes/*.py`.
- API-key generation, digest authentication, revocation, rotation, and
  consume-once reveals: `app/services/api_keys.py`.
- Internal raw proxy feed: `app/routes/internal_api.py`.
- Proxy parsing, encryption, duplicate/egress reconciliation: `app/proxy_parser.py`,
  `app/crypto.py`, `app/services/proxies.py`.
- Health and EarnApp state machines: `app/checker.py`, `app/check_service.py`,
  `app/services/checks.py`, `app/earnapp_probe.py`.
- Earnings, payout reservations, and BSC verification: `app/services/earnings.py`,
  `app/services/payouts.py`, `app/services/payout_verification.py`.
- Durable verifier process: `app/payout_verifier_service.py`.
- Container/native isolation and TLS edge configuration: `Dockerfile`,
  `docker-compose.yml`, `deploy/*.service`, `deploy/Caddyfile`.

Compose and native units run web, health, EarnApp, maintenance, payout
verification, and Caddy as independently restartable services. Native units
run as `earnproxy` with `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`,
`ProtectHome`, and a restricted writable data directory. Caddy terminates TLS;
the app trusts one forwarded client-address and protocol hop only under that
deployment topology.

## Trust boundaries and input surfaces

1. **Internet -> Caddy -> Flask/Gunicorn.** Public HTTP requests enter auth,
   contributor, admin, wallet, payout, and health routes. State-changing
   methods pass the global CSRF hook.
2. **Browser/API input -> persistence.** Registration/login attempts, raw proxy
   text, wallet addresses, payout amounts and hashes, checker settings, user
   actions, and API-key names are validated before SQLite writes. Templates use
   escaping and the UI writes dynamic values as text.
3. **Bearer API key -> credential export.** An active database key authorizes
   only the internal proxy feed. Responses are marked `no-store`; the feed
   requires a fresh successful health observation, trusted egress attestation,
   an active owner, and canonical duplicate status.
4. **Worker -> user-supplied proxy.** Proxy hosts are validated and resolved to
   public addresses; probes are bounded and state updates use generation and
   claim tokens.
5. **Verifier -> BSC RPC.** RPC URLs must be HTTPS, resolve to public addresses,
   preserve the TLS hostname while pinning the resolved address, disallow
   redirects/retries, bound response size, and parse chain/receipt/log evidence.
   The verifier never signs or sends funds.
6. **Environment/bootstrap -> application.** Production rejects placeholder
   session, Fernet, API, and admin secrets. The configured legacy API token is
   imported as a digest-only, revocable database key.

## Authentication, authorization, and state controls

Sessions reload the user from SQLite and reject missing, inactive, blocked, or
stale session versions. Admin routes require the exact `admin` role; contributor
mutations include an owner predicate in the database operation. CSRF tokens are
random session values compared in constant time.

Managed API keys use high-entropy `ep_live_` tokens. SQLite stores only a
SHA-256 digest, prefix, random public identifier, timestamps, and revocation
state. Browser reveals use an encrypted, short-lived server-side vault and a
consume-once nonce. Changing or removing the configured legacy key revokes the
previous active legacy records without touching managed keys.

Payouts move through `requested -> approved -> verifying -> confirmed|failed`.
Balance reservations include all nonterminal and confirmed/legacy-sent states;
transaction hashes are normalized and unique. Verifier claims are durable and
token-bound so a stale worker cannot apply a result after a replacement or
retry. Migration invalidates any egress identity that lacks a trusted
attestation source and clears legacy plaintext proxy credential columns after
successful encryption.

## Run-2 review targets and residual notes

The review concentrated on sad paths, replay/order/race conditions, parser
boundaries, migration idempotency, cross-user object access, bearer-key
lifecycle, payout numeric/state manipulation, and worker failure recovery.
The audit found no exploitable vulnerability to report. Operational hardening
notes remain: keep Gunicorn inaccessible except through Caddy when using
`ProxyFix`, consider per-key rate limiting/pagination for the intentionally
internal feed, and load-test the unpaginated feed at the planned 30k-proxy
scale.
