# Earn Proxy

Earn Proxy is a compact, self-hosted Flask service for manually approved contributors to submit proxies and track earnings. Administrators control users, checker load, payouts, and which eligible proxy classes the internal raw API distributes.

## Core behavior

- Stores proxy credentials encrypted with Fernet and never shows credentials in the user UI.
- Rejects duplicate credentials globally and reconciles duplicate exit IPs across all accounts.
- Checks online/offline health on a rolling 60-minute target with concurrency capped at 5.
- Classifies EarnApp-compatible proxies as `Allow`; other usable proxies are `Risk`.
- Exposes both `Allow` and `Risk` through the internal API by default; each class has an admin toggle.
- Keeps `Pause earn` independent from distribution, while blocked users are excluded from both.
- Accrues fixed hourly earnings into a seven-day probation cycle before funds become available.
- Supports one USDT BEP20 wallet per active account and manual payout approval.

## Local development

Python 3.11+ and `curl` are required. The checker invokes `curl` for HTTP and SOCKS5 probes.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

Generate secrets before starting:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Load `.env` into the environment, then run the web process and checker separately:

```powershell
flask --app app:create_app run --host 127.0.0.1 --port 8000
python -m app.check_service
```

## Internal API

Authenticate with `X-API-Key`:

```text
GET /internal/api/v1/proxies
GET /internal/api/v1/proxies?format=json
```

The text response is newline-delimited raw proxy data. JSON adds the public classification (`Allow` or `Risk`), detected protocol, and endpoint. Only online, canonical proxies belonging to active users are returned.

## Checker policy

The default health interval is 60 minutes and the hard concurrency cap is 5. Work is claimed durably from SQLite and spread across the interval, avoiding a single large sweep against the full inventory. EarnApp qualification runs on a slower independent schedule.

## Production deployment

The included Compose file runs the web service, checker, and Caddy. For a native Ubuntu deployment, copy the systemd units from `deploy/`, set secrets in `/etc/earn-proxy.env`, and keep the SQLite database under `/var/lib/earn-proxy`.

Do not use the development placeholder secrets. Back up the SQLite database and Fernet key together; losing the key makes stored proxy credentials unrecoverable.

## Verification

```powershell
python -m pytest -q
python -m ruff check app tests
python -m ruff format --check app tests
python -m compileall -q app tests
```

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE.md`.
