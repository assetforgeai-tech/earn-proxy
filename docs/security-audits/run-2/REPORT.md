# Earn Proxy Security Audit - Run 2

## Executive summary

Run 2 reviewed the current release worktree after the database-backed API-key
workspace, read-only BSC payout verifier, registration/login admission limits,
proxy quota, egress attestation hardening, and related regression tests were
added. The review covered authentication and authorization, CSRF, API-key
creation/reveal/revocation/rotation, proxy ownership and distribution, payout
reservations and verifier claims, SQLite migrations, worker boundaries, DNS/RPC
safety, templates, and deployment isolation. No confirmed exploitable
vulnerability rated LOW or higher remains in this revision.

## Baseline

The comparable baseline is a small Flask/Gunicorn administration portal behind
Caddy with SQLite-backed workers. Earn Proxy is stronger than that baseline in
the reviewed high-risk paths: production secret gates are enforced, state
changes require CSRF, role and object ownership checks are server-side, proxy
credentials are encrypted at rest, API tokens are digest-only and immediately
revocable, external destinations are public-address validated and pinned, and
payout confirmation requires independent on-chain evidence.

## Findings

| Severity | Title | Status |
| --- | --- | --- |
| - | No confirmed exploitable vulnerabilities | No finding to report |

The machine-readable result is intentionally an empty array. Previously
identified issues from Run 1 were rechecked as regression targets and remain
fixed:

- Registration admission occurs before password hashing and durable insertion,
  with shared client/global SQLite buckets.
- New and duplicate public registrations use the same pending response, so the
  route does not disclose account existence.
- Active contributors are bounded before proxy parsing/encryption and again
  under the serialized insert path.
- Legacy API-key configuration changes revoke prior active legacy keys, while
  managed keys remain available for migration.
- Rows with missing/untrusted egress attestation are reset to a strong
  qualification state before they can be distributed.

## Hardening notes

- Keep Gunicorn bound behind Caddy; `ProxyFix(x_for=1)` assumes that topology
  and should not be exposed directly to untrusted clients.
- Add edge/application rate limiting and pagination if the internal feed is
  exposed beyond the trusted integration network or approaches 30k rows.
- Keep the absolute `amount_micro_usd` bound aligned with payout policy and add
  operational alerts for checker lag, verifier backlog, and registration-attempt
  table growth.
- Pin production dependency versions/image digests and test the built Ubuntu
  deployment separately from the broad development environment.
- Repeat an independent audit after material changes to auth, checker,
  distribution, payout, or deployment code.

These are defense-in-depth or capacity recommendations, not confirmed
vulnerabilities in the reviewed configuration.

## Positive patterns

- Session-version checks revoke captured cookies after logout/block, and admin
  routes enforce exact roles and contributor ownership.
- CSRF covers every non-safe method; Jinja escaping and text-only DOM updates
  avoid confirmed stored/reflected XSS paths.
- Proxy and RPC destinations reject local/non-public addresses; network calls
  use bounded responses and pinned destinations.
- API keys use high-entropy material, digest-only storage, random public IDs,
  immediate revocation/rotation, no-store responses, and consume-once reveals.
- Payouts reserve balances atomically, reject duplicate transaction hashes, use
  durable claim tokens, and require chain/contract/recipient/amount/status/
  confirmation evidence without holding a signing key.
- Services run unprivileged with restart policies and restrictive systemd
  sandboxing.

## Coverage and limitations

This is a source-first audit plus the repository's automated regression suite.
Browser smoke execution could not be completed locally because the available
Python environment lacks Playwright and Docker is unavailable; no production
state was changed during that attempt. A deployed, authenticated browser run
and a load test of the internal feed remain recommended validation work.
