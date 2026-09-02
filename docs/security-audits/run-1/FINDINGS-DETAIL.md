# Earn Proxy Security Audit - Detailed Data Flows

No unresolved MEDIUM-or-higher vulnerability remains in the final revision.

## Fixed: public registration resource exhaustion

Original flow: anonymous `POST /register` -> `register` -> `create_user` -> CPU-hard password hash -> durable SQLite user insert. CSRF did not stop an automated visitor from first obtaining a valid token. The final flow first calls `admit_registration_attempt`, which serializes a shared per-client/global reservation in SQLite; an exhausted bucket returns HTTP 429 before password hashing or user creation.

Regression coverage: `tests/test_security.py::test_registration_rate_limit_rejects_before_password_work` and `tests/test_security.py::test_registration_limit_is_shared_across_web_processes`.

## Fixed: public registration email enumeration

Original flow: anonymous `POST /register` -> unique constraint result -> distinct `201` or `409` response. The final route maps both a successful insert and a duplicate constraint to the same `201 {"status":"pending"}` contract and the same browser message.

Regression coverage: `tests/test_security.py::test_public_registration_uses_a_generic_duplicate_response`.

## Fixed: contributor checker backlog exhaustion

Original flow: active contributor `POST /proxies` -> parse/encrypt unique credential -> insert due proxy -> shared strong-check queue. The final route counts the caller's non-archived rows and returns HTTP 429 before parsing/encryption when the configured quota is exhausted.

Regression coverage: `tests/test_security.py::test_active_user_proxy_quota_is_enforced_before_proxy_parsing`.
