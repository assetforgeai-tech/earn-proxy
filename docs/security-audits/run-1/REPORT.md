# Earn Proxy Security Audit - Run 1

## Executive summary

This source-first audit covered authentication, authorization, CSRF, proxy input and checker boundaries, API-key lifecycle, payout accounting and BSC verification, SQLite worker claims, templates, and deployment isolation. Three exploitable abuse paths were confirmed in the pre-release worktree: public registration resource exhaustion, registration email enumeration, and an unbounded per-user checker backlog. All three were fixed before release and protected by regression tests. No unresolved exploitable vulnerability rated LOW or higher was confirmed in the final revision.

The baseline comparable is a small Flask/Gunicorn administration portal with SQLite-backed background workers behind Caddy. Earn Proxy now meets or exceeds that baseline in the highest-risk areas: production refuses placeholder secrets, state-changing routes use CSRF, roles and object ownership are enforced server-side, raw credentials are encrypted at rest, API tokens are digest-only and revocable, external network destinations are public-address validated and pinned, and payout confirmation requires independently verified BSC evidence.

## Findings

| Severity | Title | Final status |
| --- | --- | --- |
| MEDIUM | Public registration allowed CPU/storage exhaustion | Fixed before release |
| LOW | Public registration disclosed account existence | Fixed before release |
| LOW | One contributor could create an unbounded checker backlog | Fixed before release |

### Public registration allowed CPU/storage exhaustion

The original public `POST /register` path performed password hashing and inserted a durable pending-user row for every unique email without an admission limit. An anonymous client could obtain a normal CSRF token and submit registrations repeatedly, consuming Gunicorn CPU and growing SQLite/admin work. The final revision calls a shared SQLite admission limiter before validation and password hashing, with configurable per-client and global windows. See `app/routes/auth.py` and `app/registration_rate_limit.py`.

### Public registration disclosed account existence

The original route returned `409 Email is already registered` for an existing address and `201` for a new address. An anonymous client could use the difference to confirm contributor or administrator emails. The final revision returns the same accepted/pending response for both cases and never returns a user ID from public registration. See `app/routes/auth.py`.

### One contributor could create an unbounded checker backlog

An approved contributor could originally add unlimited unique credential fingerprints, immediately scheduling every row for strong proxy qualification. This could starve the shared checker queue and consume database, CPU, socket, and bandwidth capacity. The final revision enforces a configurable active-proxy quota before proxy parsing/encryption. See `app/routes/proxies.py` and `app/__init__.py`.

## Hardening notes

- Keep an upstream Cloudflare/Caddy registration rate rule as an additional shared edge layer; the application limiter is authoritative on the single SQLite node.
- Monitor registration-attempt table size, checker due count, checker lag, and per-user active proxy counts in operational alerts.
- Pin runtime dependencies in a reproducible lock or image digest and audit the built production environment, not the broad Codex host Python environment.
- A first audit cannot guarantee complete coverage. Repeat an independent audit after material auth, checker, payout, or deployment changes.

## Positive patterns

- Session versioning revokes captured cookies after logout/block; admin routes check the exact role and contributor object mutations enforce ownership.
- CSRF covers every non-safe HTTP method; Jinja autoescaping and `textContent` avoid confirmed XSS paths.
- Proxy and RPC destinations reject non-public addresses and pin DNS results; curl uses argument arrays and bounded output.
- API keys use high-entropy tokens, SHA-256 digest storage, random public IDs, immediate revocation/rotation, no-store responses, and consume-once encrypted reveals.
- Payouts reserve balances atomically, reject duplicate transaction hashes, use durable claim tokens, verify chain/contract/recipient/amount/status/confirmations, and never hold a signing key.
- Services run as an unprivileged account with restart policies and restrictive systemd sandboxing.
