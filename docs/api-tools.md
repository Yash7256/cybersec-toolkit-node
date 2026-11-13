# Tool API

All tool endpoints require authentication (`Authorization: Bearer <Clerk JWT>`)
and run through the shared route pipeline described in
`docs/tool-route-contract.md`.

Sync response envelope:

```json
{ "runId": "uuid", "tool": "dns", "target": "example.com", "status": "COMPLETED",
  "cached": false, "data": { }, "quota": { "used": 1, "limit": 5 } }
```

Async response (`202`) adds `Location: /api/runs/<id>` and:

```json
{ "runId": "uuid", "tool": "ping", "target": "example.com", "status": "QUEUED",
  "pollUrl": "/api/runs/<id>", "pollAfterMs": 1500, "quota": { } }
```

Async submissions require `Idempotency-Key: ^[A-Za-z0-9_-]{8,64}$`. Replays
return the current run with `Idempotent-Replayed: true` and consume no quota.

## Error vocabulary

| Status | Code | Meaning |
|---:|---|---|
| 400 | `VALIDATION_ERROR` | Body/query failed the zod schema |
| 401 | `UNAUTHORIZED` | Missing or invalid session |
| 403 | `FORBIDDEN` | Not allowed to access the resource |
| 404 | `NOT_FOUND` | Run or resource not found (also used for IDOR) |
| 409 | `IDEMPOTENCY_IN_PROGRESS` | Same key is still being submitted |
| 409 | `RUN_NOT_CANCELLABLE` | Run already reached a terminal state |
| 422 | `TARGET_BLOCKED` | Target is private, reserved, or otherwise denied |
| 429 | `QUOTA_EXCEEDED` | Daily free quota exhausted |
| 429 | `TOO_MANY_ACTIVE_RUNS` | Per-user active-run cap reached (refunded) |
| 429 | `RATE_LIMITED` | A submit/global rate limiter rejected the request |
| 502 | `UPSTREAM_ERROR` | Upstream lookup failed (refunded) |
| 503 | `SERVER_BUSY` | In-process concurrency cap reached (refunded) |
| 503 | `QUEUE_FULL` | Queue backpressure (refunded, `Retry-After: 30`) |
| 504 | `TOOL_TIMEOUT` | Hard timeout (refunded) |

Target-level failures that are not the caller's fault (for example the host has
no TLS service) complete with `200` and `data.error` set.

## Tools

### `POST /api/tools/dns`

Request: `{ "target": string, "record_type"?: "ALL"|"A"|"AAAA"|"MX"|"NS"|"TXT"|"CNAME"|"SOA"|"CAA"|"PTR" }`.
IP inputs are converted to a PTR lookup. Dedupe 60 s. Public DoH resolvers only.

Data keys: `target, record_type, records, query_time_ms, error, dnssec_validated, resolver`.

### `POST /api/tools/ssl`

Request: `{ "host": string, "port"?: 1..65535 (default 443) }`. Dedupe 300 s.
Probes the default protocol plus TLS 1.2-only and TLS 1.3-only handshakes.

Data keys: `host, port, tls_version, cipher_suite, certificate, valid, is_expired,
is_self_signed, days_remaining, supports_tls12, supports_tls13, chain_trusted,
authorization_error, hostname_matches, fingerprint_sha256, key_type, key_bits, error`.

### `POST /api/tools/http_headers`

Request: `{ "target": string, "path"?: string }`. `path` must start with `/`, not
`//`, contain no control characters, and be at most 2048 bytes. Bare hosts try
HTTPS then HTTP. Dedupe 120 s.

Data keys: `url, status_code, headers, redirects, security_score, risk_level,
technologies, error, tls_verification_skipped`.

### `POST /api/tools/whois`

Request: `{ "target": string }` (domain or public IP). RDAP first, port-43
fallback. Subdomains are reduced to the registrable domain. Private IPs are
rejected with `422`. Dedupe 3600 s.

Data keys: `target, domain, available, registrar, creation_date, expiration_date,
updated_date, name_servers, status, dnssec, privacy_protected, days_until_expiry,
expiry_status, summary, error, rdap_available, normalized, rdap, cached`.

### `GET /api/tools/geoip`

Query: `?target=<hostname-or-public-ip>`. Providers are tried in
`GEOIP_PROVIDER_ORDER`; results are cached for 3600 s and enriched with reverse
DNS, CDN detection, and RDAP abuse contacts when available. The first
`GEOIP_MAX_IPS` resolved addresses (default 4, max 10, IPv4 first) are looked
up, and `ip_results` holds one entry per lookup. Set `GEOIP_CONSENSUS=true` to
query a second provider and report `confidence: "high" | "low"`.

Data keys: `target, ip, addresses, resolved_ips, country, country_code,
continent, continent_code, region, city, postal, latitude, longitude, timezone,
utc_offset, flag_emoji, calling_code, asn, org, isp, asn_domain, provider,
is_cdn, cdn_provider, is_proxy, is_hosting, is_vpn, is_tor, confidence,
location_accuracy, map_url, reverse_dns, abuse_contact, fallback_note,
scan_duration_seconds, ip_results, ip_type, ip_type_basis, privacy,
privacy_sources, asn_detail, network, reputation, consensus, accuracy_radius_km,
accuracy_basis, freshness, warnings, anycast, reverse_ip, cached, error`.

`ip_results[]` keys: `ip, family, country, country_code, flag_emoji, region,
city, latitude, longitude, asn, org, isp, cdn_provider, is_cdn, reverse_dns,
provider, error`. A failed address has its own `error` while the rest of the
lookup still succeeds.

Enrichment sources are best-effort. Unavailable data is `null`, never a
fabricated `false`; each failed source adds `{ source, message }` to `warnings`.
`ip_type_basis` names the evidence behind `ip_type` (`tor-exit-list`,
`asn-list`, `provider-privacy`, or `abuseipdb-usage-type`). `GEOIP_REVERSE_IP`
enables PTR enrichment only when a licensed provider is configured.

### `GET /api/tools/geoip/me`

Looks up the caller's public IP from `req.ip` only; `X-Forwarded-For` is never
parsed manually. Private or reserved callers receive `422 TARGET_BLOCKED`.

### `POST /api/tools/asn` / `GET /api/tools/asn?asn=AS15169`

Request: `{ "asn": "AS15169" }`. Merges Team Cymru ASN metadata with RIPEstat
announced prefixes. Dedupe 86400 s. Data keys: `target, asn, name, country, rir,
allocated, prefixes, prefix_count, truncated, warnings, error, cached`.

### `POST /api/tools/geoip_cidr` / `GET /api/tools/geoip/cidr?target=8.8.8.0/24`

Request: `{ "target": "8.8.8.0/24" }`. IPv4 is limited to `/24`–`/32`; IPv6 to
`/120`–`/128`; at most 256 addresses. Private/reserved addresses are skipped and
listed in `skipped`. Blocks over 16 addresses are queued. Data keys: `target,
mode, total, completed, failed, skipped, summary, ip_results, results, warnings,
error`. `summary` contains `countries`, `asns`, `ip_types`, `cdn`, `hosting`, and
`tor` counts.

### `POST /api/tools/geoip_bulk`

Request: `{ "targets": string[] }`, 1–100 unique entries. Invalid entries are
returned in `rejected`; the remainder are processed. The per-plan cap is
`GEOIP_BULK_MAX_FREE` (default 10) or `GEOIP_BULK_MAX_PAID` (default 100).
Queued and charged one quota unit per valid target. Data keys: `target, mode,
total, completed, failed, rejected, summary, ip_results, results, warnings,
error`.

### `POST /api/tools/ping`

Request: `{ "target": string, "count"?: 1..100 (default 4) }`. Uses ICMP when the
process can (`cap_net_raw`/root), otherwise TCP connect to 443 then 80. `count >
20` is queued (`mode: 'auto'`) and returns `202`; smaller counts run inline.
Never deduped. `method` is `"icmp"` or `"tcp"`.

Data keys: `target, method, count, sent, received, loss_pct, min_ms, avg_ms,
max_ms, jitter_ms, quality, port, ttl, likely_os_family, history_delta_ms, geo,
error`.

## History and catalogue

- `GET /api/runs?tool=&status=&limit=&cursor=` — keyset pagination, max 50.
- `GET /api/runs/:id` — adds `progressPct`, `pollAfterMs` while active,
  `queuePosition` while `QUEUED`, and `data` only when `COMPLETED`.
- `POST /api/runs/:id/cancel` — `QUEUED` → `200 CANCELLED` (refunded);
  `RUNNING` → `202` with `cancelRequested: true`; terminal → `409`.
- `DELETE /api/runs/:id` — `204`.
- `GET /api/tools/geoip/history?tool=&limit=` — recent GeoIP, bulk, CIDR, and
  ASN runs; `limit` is 1–50.
- `DELETE /api/tools/geoip/history` — delete all terminal GeoIP workflow runs
  for the caller; returns `{ "deleted": n }`. Active runs are left untouched.
- `GET /api/runs/compare?ids=a,b` — 2–5 owned runs for side-by-side comparison.
- `GET /api/runs/:id/report?format=md|json` — downloadable report for a
  completed run.
- `POST /api/runs/:id/share` — create a share link. Body:
  `{ "ttlDays"?: 1..30, "redactAbuseContact"?: boolean }`. Returns `token` and
  `path`; the raw token is shown once.
- `GET /api/runs/:id/shares` — list active and expired links for the run.
- `DELETE /api/runs/:id/share/:shareId` — revoke a link.
- `GET /api/share/:token` — public, rate-limited, `no-store`, `noindex`. Returns
  only run metadata and results; never user data.
- `GET /api/tools` — catalogue with `name, label, description, touchesTarget,
  input, dailyLimit`.

Other users' runs always return `404`.
