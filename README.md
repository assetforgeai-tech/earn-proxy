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
- Classifies verified egress countries in the slower EarnApp worker, with a seven-day per-IP cache and provider cooldown, so health checks stay fast and US rates are applied correctly.
- Supports one USDT BEP20 wallet per active account, manual payout approval, and read-only on-chain verification of submitted USDT transfers.

## Worker architecture

The service is split into four independently restartable workers so an EarnApp outage, RPC outage, or a large health backlog cannot block web requests or earnings maintenance:

1. `health` checks proxy reachability and egress.
2. `earnapp` performs the slower EarnApp qualification refresh.
3. `maintenance` accrues earnings, archives proxies that have been continuously dead for 24 hours, and checkpoints SQLite WAL.
4. `payout-verifier` validates submitted BSC transaction receipts without holding a wallet private key or sending funds.

Each worker uses durable SQLite claims. A claim has a short lease and is released when a job is cancelled, so a restart does not permanently strand a proxy.

## Health-check policy

New, changed, or suspect rows use a strong qualification pass. A stable row uses one fast request through the previously detected protocol and rotates among the configured public IP endpoints. The checker reads the documented JSON `ip` field from `api.prox.io.vn/v1/check/whoami`; curl socket metadata such as `%{remote_ip}` is never treated as proxy identity. Strong checks require at least two matching independent HTTPS observations and a strict majority of all valid IP observations, so a 2-2 split remains inconclusive. A fast failure or egress change triggers strong confirmation; a third-party endpoint failure is recorded as `inconclusive` and is retried instead of immediately marking the proxy dead.

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

Public registration is admitted before password hashing through shared per-client and global rate buckets. The production defaults allow 5 attempts per client and 100 attempts globally in 15 minutes; tune `EARN_PROXY_REGISTRATION_MAX_ATTEMPTS`, `EARN_PROXY_REGISTRATION_RATE_WINDOW_SECONDS`, and `EARN_PROXY_REGISTRATION_GLOBAL_MAX_ATTEMPTS` for the expected signup volume and any upstream CDN controls.

Sign-in attempts are admitted through shared client-IP and global buckets before password verification. The defaults allow 30 attempts per client and 1000 globally in 15 minutes; an account-wide lockout is deliberately not used because it would let an unauthenticated caller deny service to a known account. Tune `EARN_PROXY_LOGIN_IP_MAX_ATTEMPTS`, `EARN_PROXY_LOGIN_GLOBAL_MAX_ATTEMPTS`, and `EARN_PROXY_LOGIN_RATE_WINDOW_SECONDS` alongside any upstream login protection.

Approved contributors may keep up to 100 active proxy rows by default. Set `EARN_PROXY_MAX_ACTIVE_PROXIES_PER_USER` to match the expected per-account inventory; archived rows and historical earnings do not consume the quota.

## Contributor proxy import

The contributor proxy workspace accepts one proxy or a batch. Users can paste one proxy per line, upload a UTF-8 `.txt` or `.csv` file, or combine pasted and uploaded input in the same request. Supported raw formats are:

```text
host:port
host:port:username:password
username:password@host:port
http://username:password@host:port
https://username:password@host:port
socks5://username:password@host:port
```

CSV uploads may contain one raw proxy per row, a header named `raw_proxy` (aliases: `proxy`, `url`, or `endpoint`), or structured headers `host,port,username,password,protocol`. Structured header aliases include `ip`/`server`, `user`/`login`, `pass`/`secret`, and `scheme`/`type`. Headerless multi-column CSV is rejected so columns cannot be interpreted incorrectly.

Imports are limited to 512 KB and 5,000 lines by default. Configure `EARN_PROXY_MAX_IMPORT_BYTES` and `EARN_PROXY_MAX_IMPORT_LINES` to change those bounds. Blank lines are ignored. Valid entries are encrypted and queued with `pending` status. Credential duplicates are skipped globally, including duplicates owned by another account and duplicates repeated within the same batch; import feedback only exposes safe `host:port` labels.

The existing single-entry `POST /proxies` route remains available. Bulk clients can use `POST /proxies/import` with JSON:

```json
{
  "raw_proxies": [
    "proxy-one.example:9000:user:password",
    "socks5://user:password@proxy-two.example:1080"
  ]
}
```

Browser clients submit `multipart/form-data` with `raw_proxies`, optional `proxy_file`, and the normal CSRF token. The response reports `added`, `duplicates`, `invalid`, `quota_skipped`, `ignored_blank`, and credential-safe per-line issues.

Each contributor may have up to 10 nonterminal payout requests (`requested`, `approved`, or `verifying`) queued at once. Terminal history (`confirmed`, `failed`, and legacy `sent`) remains durable without consuming this queue limit. Set `EARN_PROXY_MAX_OUTSTANDING_PAYOUTS_PER_USER` to tune the bound; values are clamped to 1-1000.

## Internal API

Authenticate with `X-API-Key`. The canonical endpoints for new integrations are:

```text
GET https://proxy.acacondos.com/api/v1/proxy-raw
GET https://proxy.acacondos.com/api/v1/proxy-transfer
```

`proxy-raw` returns contributor upstream credentials for systems that connect directly to the provider. `proxy-transfer` returns fixed VPS listener credentials for clients that must connect through the relay. Both support newline-delimited text and `?format=json`; all responses are authenticated and marked `Cache-Control: no-store`. Only online, canonical proxies belonging to active users are returned. Existing clients may continue using `/api/v1/proxies` or `/internal/api/v1/proxies`, which remain raw-feed compatibility aliases.

Administrators manage multiple revocable API keys at `/admin/integrations/api-keys`. A newly created or rotated token is revealed once; only its digest, prefix, and operational metadata are retained in SQLite.

Example (keep the key in an environment variable):

```bash
curl -fsS -H "X-API-Key: ${EARN_PROXY_API_KEY}" "https://proxy.acacondos.com/api/v1/proxy-raw"
curl -fsS -H "X-API-Key: ${EARN_PROXY_API_KEY}" "https://proxy.acacondos.com/api/v1/proxy-transfer?format=json"
```

## Production deployment

The included Compose file runs web, health, EarnApp, maintenance, payout verification, and Caddy as separate restartable services:

```powershell
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 health-checker earnapp-checker maintenance payout-verifier
```

For a native Ubuntu deployment, keep secrets in `/etc/earn-proxy.env` and the SQLite database under `/var/lib/earn-proxy`. Deploy a committed revision from a clean checkout with the versioned release script:

```bash
sudo bash deploy/release.sh "$(git rev-parse --verify HEAD)"
sudo systemctl enable earn-proxy-web earn-proxy-checker earn-proxy-earnapp earn-proxy-maintenance earn-proxy-payout-verifier
sudo systemctl status earn-proxy-web earn-proxy-checker earn-proxy-earnapp earn-proxy-maintenance earn-proxy-payout-verifier
```

The release script creates the virtualenv only after the release has reached its final absolute path, validates imports, configuration, dependency consistency, database access, and systemd units, then atomically switches `/opt/earn-proxy`. If the restarted application fails its local health check, it restores the previous symlink and restarts the services. Never copy or move a virtualenv between release directories: Python console scripts and package metadata may retain absolute paths.

The units use `Restart=always`, a five-second restart delay, a dedicated unprivileged account, and a restricted writable data path. Back up the SQLite database and Fernet key together before upgrades. The previous versioned directory remains available as the first rollback target.

Do not use the development placeholder secrets. Back up the SQLite database and Fernet key together; losing the key makes stored proxy credentials unrecoverable.

### Payout verification configuration

Set an HTTPS BSC JSON-RPC endpoint and keep the token settings explicit:

```text
EARN_PROXY_BSC_RPC_URL=https://bsc-dataseed.binance.org/
EARN_PROXY_BSC_USDT_CONTRACT=0x55d398326f99059ff775485246999027b3197955
EARN_PROXY_BSC_USDT_DECIMALS=18
EARN_PROXY_BSC_MIN_CONFIRMATIONS=12
```

The verifier is read-only. It never signs or sends a transaction and must not receive a wallet private key. If the RPC is unavailable or returns an inconclusive response, the payout remains `verifying` and is retried; only a finalized receipt that matches all payout fields becomes `confirmed`.

A failed payout releases its reservation so the contributor may request again. If an administrator retries it later, the transition rechecks the user's available balance under the same SQLite write lock, preventing the failed payout and a newer request from reserving the same earnings twice.

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
