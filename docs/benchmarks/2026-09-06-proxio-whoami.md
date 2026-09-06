# Prox.io `/v1/check/whoami` observed load test

Date: 2026-09-06 (Asia/Saigon)

Source: production VPS `42.96.12.142`

Endpoint: `GET https://api.prox.io.vn/v1/check/whoami`

## Direct request ramp

The capped test sent 300 read-only requests with gradual stages of 1, 2, 5, and 10 requests per second. It did not submit browser fingerprints or create reports.

| Target | Requests | Achieved | HTTP 200 | Valid JSON `ip` | Errors | p50 | p95 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 RPS | 30 | 1.030 RPS | 30 | 30 | 0 | 132.39 ms | 184.18 ms | 216.31 ms |
| 2 RPS | 60 | 2.025 RPS | 60 | 60 | 0 | 130.22 ms | 141.01 ms | 144.94 ms |
| 5 RPS | 90 | 5.020 RPS | 90 | 90 | 0 | 125.15 ms | 141.16 ms | 147.50 ms |
| 10 RPS | 120 | 9.978 RPS | 120 | 120 | 0 | 124.72 ms | 139.04 ms | 141.14 ms |
| Overall | 300 | - | 300 | 300 | 0 | 127.70 ms | 141.95 ms | 172.06 ms |

No `429`, `5xx`, timeout, or rate-limit response headers were observed. Every response was dynamic and served through Cloudflare.

## Through-proxy sample

Twelve live SOCKS5 proxies from the Transfer Proxy inventory were queried through their raw upstream credentials. The deployed candidate checker completed all 12 as `live`, and every JSON `ip` exactly matched the existing exit IP independently observed for that row. A direct curl sample had a median latency of approximately 584 ms; the slowest sample completed in approximately 4.32 seconds.

The curl `%{remote_ip}` value was the same Cloudflare edge address for every sample and differed from the JSON `ip`. It is therefore transport metadata and must never be stored as proxy egress identity.

## Deployment limit

The integration limits Prox.io to five requests per second in each of the two checker processes. This keeps their combined sustained ceiling within the tested 10 RPS. Prox.io remains one member of a multi-host HTTPS quorum; a result needs at least two agreeing sources and a strict majority of valid IP observations, so a 2-2 split is inconclusive. It is not a single source of truth, and its rate limits or failures do not independently mark a proxy dead.

These results establish observed behavior for this run only. They are not a provider SLA or a guarantee of future capacity.
