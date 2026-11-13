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

### `POST /api/tools/geoip`

Request: `{ "target": string }` (hostname or public IP). Providers are tried in
`GEOIP_PROVIDER_ORDER`; results are cached for 3600 s and enriched with reverse
DNS, CDN detection, and RDAP abuse contacts when available.

Data keys: `target, ip, addresses, country, region, city, latitude, longitude,
asn, org, provider, is_cdn, map_url, reverse_dns, abuse_contact, fallback_note,
cached, error`.

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
- `GET /api/tools` — catalogue with `name, label, description, touchesTarget,
  input, dailyLimit`.

Other users' runs always return `404`.
