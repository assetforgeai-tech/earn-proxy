# Earn Proxy Security Audit - Run 2: Detailed Data Flows

No confirmed MEDIUM-or-higher (or LOW) vulnerability remains in the reviewed
revision, so there are no finding traces requiring a remediation record.

## Regression validations

- **Legacy API-key rotation:** startup/configuration calls
  `ensure_legacy_api_key` in `app/services/api_keys.py`; changing the digest
  revokes older active legacy rows before inserting or reusing the new record.
  Managed rows are not selected by the revocation predicate. The regression
  tests verify that the old token fails immediately and the new token works.
- **Egress attestation migration:** `migrate_db` in `app/db.py` clears exit
  identity, duplicate state, and distribution eligibility for rows without a
  trusted `https_quorum` or `earnapp_tls` source, and schedules a strong pass.
  The regression tests cover both a legacy schema and an intermediate schema
  where the attestation column already existed but was untrusted.
- **Authorization and worker claims:** dynamic ownership tests verify that one
  user cannot replace or delete another user's proxy; payout and checker tests
  verify claim-token and state-transition predicates reject stale workers.

The remaining observations (Caddy-only `ProxyFix` deployment assumption,
internal-feed capacity, and unavailable local browser dependencies) are
hardening or validation gaps rather than exploitable findings.
