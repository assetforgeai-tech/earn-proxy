# Run 5 Finding Details

## LOW — Oversized registration email causes storage/admin-rendering DoS

### Data flow

1. Anonymous `POST /register` supplies the `email` form field.
2. The auth route normalizes the field and now rejects values longer than
   `MAX_EMAIL_LENGTH` before account creation.
3. The shared user service repeats the length check before the parameterized
   SQLite insert, protecting non-HTTP callers.
4. Before the patch, the same value reached the `users.email` TEXT column and
   was selected/rendered for every admin user page.

### Reproduction used before remediation

```text
POST /register
email = "a" * 900000 + "@x.com"
password = "member-password"
```

Observed on a disposable database: HTTP 201 and `length(users.email)=900006`.
No production database, provider credential, or deployment was used.

### Remediation verification

The current routes reject a 257-character normalized email with HTTP 400; the
service rejects the same value if called directly. Regression tests cover both
public registration and admin-created users.
