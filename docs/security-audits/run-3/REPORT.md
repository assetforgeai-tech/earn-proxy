# Security Audit Report: Run 3

## Executive summary

No confirmed exploitable vulnerability was identified in the reviewed Earn
Proxy and Transfer Proxy paths. The split raw/transfer API feeds require an
active API key and return only eligible, fresh, canonical rows. The whitelist
hostname exposes only the intended static relay IP. Authentication,
authorization, CSRF, SSO, relay feed protection, and Caddy routing were traced
through their source and checked against the deployed topology.

## Scope and evidence

Reviewed the Flask application, API-key lifecycle, contributor dashboard,
internal API feeds, Caddy routing, relay SSO/feed boundary, worker-facing
proxy paths, and native service configuration. The focused auth/API, business
logic, and relay reviews independently returned no confirmed finding. Local
verification also completed with `327 passed` in the full pytest suite; Caddy
configuration validation and compile checks passed during the release review.

## Findings

| Severity | Result |
|---|---|
| Critical/High/Medium/Low | None confirmed |

There are no entries in `findings.json`.

## Positive security controls

- State-changing browser requests are protected by global CSRF validation.
- Sessions enforce active status and a server-side session version, so logout or
  blocking revokes captured sessions.
- Raw, transfer, and legacy API routes require a revocable digest-backed API key.
- Feed rows are restricted to active users, online/fresh, attested, canonical
  proxies; responses are marked `Cache-Control: no-store`.
- Transfer feed configuration is loopback-only and size-bounded; public relay
  feed paths are blocked at Caddy.
- Relay state-changing actions require authenticated sessions and CSRF; the
  internal feed additionally requires a secret key.
- Production services bind application listeners to loopback and use restricted
  service users/paths where configured.
- Proxy credentials are encrypted at rest and never rendered in the user UI.

## Hardening notes (not vulnerabilities)

- Relay SSO nonces are signed and short-lived but not consumed; a separately
  captured token could be replayed during its validity window.
- The relay deployment should be migrated from root to a dedicated unprivileged
  account with only the capabilities it needs.
- Sanitize/limit trusted forwarded-address headers to the known reverse proxy.
- Add explicit `no-store` to authenticated relay HTML/export responses and use
  edge rate limiting/pagination as inventory size grows.

These notes were not promoted to findings because the audit did not establish a
complete attack chain with meaningful impact under the deployed topology.
