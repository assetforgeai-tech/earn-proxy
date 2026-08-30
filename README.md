# Earn Proxy

Earn Proxy is a compact, self-hosted Flask service for manually approved contributors to submit proxies and track earnings. Administrators control users, checker load, payouts, and which eligible proxy classes the internal raw API distributes.

## Core behavior

- Stores proxy credentials encrypted with Fernet and never shows credentials in the user UI.
- Rejects duplicate credentials globally and reconciles duplicate exit IPs across all accounts.
- Checks online/offline health on a rolling 60-minute target with a default concurrency of 5 (hard cap 20).
- Classifies EarnApp-compatible proxies as `Allow`; other usable proxies are `Risk`.
- Exposes both `Allow` and `Risk` through the internal API by default; each class has an admin toggle.
- Keeps `Pause earn` independent from distribution, while blocked users are excluded from both.
- Accrues fixed hourly earnings into a seven-day probation cycle before funds become available.
- Supports one USDT BEP20 wallet per active account and manual payout approval.

## Worker architecture

The service is split into three independently restartable workers so an EarnApp outage or a large health backlog cannot block web requests or earnings maintenance:

1. `health` checks proxy reachability and egress.
2. `earnapp` performs the slower EarnApp qualification refresh.
3. `maintenance` accrues earnings, archives proxies that have been continuously dead for 24 hours, and checkpoints SQLite WAL.

Each worker uses durable SQLite claims. A claim has a short lease and is released when a job is cancelled, so a restart does not permanently strand a proxy.

## Health-check policy

New, changed, or suspect rows use a strong qualification pass. A stable row uses one fast request through the previously detected protocol and rotates among the configured public IP endpoints. A fast failure or egress change triggers strong confirmation; a third-party endpoint failure is recorded as `inconclusive` and is retried instead of immediately marking the proxy dead.

Confirmed failures use short retries: the first failure waits 5 minutes, the second waits 15 minutes and marks the row `suspect`, and the third independent confirmed failure marks it `offline`. A successful result resets the streak. Online rows older than the stale-success limit (default 120 minutes) are withheld from the internal API until a fresh success is recorded.

Checks are scheduled on a rolling cadence rather than launched as one full-inventory burst. If work becomes overdue, the worker drains the backlog continuously instead of adding artificial scheduler delays. SQL interleaves provider hosts for fairness, while a runtime semaphore defaults to two simultaneous checks per hostname (maximum three).

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

## Production deployment

The included Compose file runs web, health, EarnApp, maintenance, and Caddy as separate restartable services:

```powershell
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 health-checker earnapp-checker maintenance
```

For a native Ubuntu deployment, copy the systemd units from `deploy/`, set secrets in `/etc/earn-proxy.env`, and keep the SQLite database under `/var/lib/earn-proxy`:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now earn-proxy-web earn-proxy-checker earn-proxy-earnapp earn-proxy-maintenance
sudo systemctl status earn-proxy-web earn-proxy-checker earn-proxy-earnapp earn-proxy-maintenance
```

The units use `Restart=always`, a five-second restart delay, a dedicated unprivileged account, and a restricted writable data path. Back up the SQLite database and Fernet key together before upgrades. To roll back, stop the services, restore the previous application directory and database/key pair, then start the same units again.

Do not use the development placeholder secrets. Back up the SQLite database and Fernet key together; losing the key makes stored proxy credentials unrecoverable.

## Verification

```powershell
python -m pytest -q
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m compileall -q app tests scripts
python -m pip check
```

## Capacity model

The 60-minute value is a configurable freshness target, not a guaranteed capacity figure. With five concurrent jobs, 30,000 checks per hour requires an average end-to-end check time below 0.6 seconds; slower proxies, timeouts, strong qualification, and a concentration on one provider hostname extend the sweep. For example, a two-slot hostname limit requires an average below 0.24 seconds if all 30,000 credentials share one host. Fast checks normally issue one request, and new, changed, or failed rows use the more expensive strong path. Use the admin throughput, due-count, and lag metrics to size concurrency from measured VPS and provider behavior before relying on a 60-minute cadence.

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE.md`.
