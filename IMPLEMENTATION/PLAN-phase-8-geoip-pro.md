# PHASE 8 — GeoIP Professional Workflow

> Prerequisites: Phase 7 complete, GeoIP backend/UI contract fix committed (`876e8fb`, `ba0cb07`, `b1688f5`).
> Companions: `docs/api-tools.md`, `docs/openapi/geoip.yaml`, `DATABASE-DESIGN.md`.
> Server: Express ESM JavaScript. Client: React + Vite. Reuse runs/queue/quota/limiter/cache/breaker infrastructure — no parallel systems.

## 0. Working rules

1. One checklist item at a time; tick `[x]` only after its tests pass.
2. All outbound HTTP goes through `safeHttp` with an explicit `allowHosts` list.
3. DNS lookups use a resolver with a timeout; no unbounded `dns.lookup`.
4. Never fabricate data. Missing data is `null` and the UI shows "Not available".
5. Heuristics carry a `basis` string; GeoIP stays passive (`touchesTarget: false`).
6. Private/reserved IPs are rejected by existing policy on every new input path.
7. A failed source degrades to `null` plus `warnings: [{source, message}]`.
8. Every source has its own timeout, circuit breaker, cache TTL and warning label.
9. No new npm dependency unless listed here (none planned).
10. Small commits per item; `npm test -w server` and `npm run lint -w client` per phase.

### 0.1 New network hosts (allow-list)

| Host | Purpose | Notes |
|---|---|---|
| `origin.asn.cymru.com`, `origin6.asn.cymru.com`, `asn.cymru.com` | ASN/prefix/name via DNS TXT | DNS only, 2 s timeout |
| `check.torproject.org` | Tor bulk exit list (`/torbulkexitlist`) | HTTPS, 1 h refresh, fail-closed after 24 h |
| `api.abuseipdb.com` | Reputation | only when `ABUSEIPDB_API_KEY` is set |
| `stat.ripe.net` | Announced prefixes for ASN tool | HTTPS, cap 100, 24 h cache |
| DNSBL zones from `GEOIP_DNSBL_ZONES` | DNSBL reputation | IPv4 only, 2 s per zone, cap 8 |

RDAP reuses the existing `rdapClient` bootstrap/host discovery.

### 0.2 New environment variables

`ABUSEIPDB_API_KEY`, `GEOIP_REPUTATION_ENABLED`, `GEOIP_DNSBL_ZONES`, `GEOIP_CONSENSUS`,
`GEOIP_BULK_MAX_FREE`, `GEOIP_BULK_MAX_PAID`, `GEOIP_REVERSE_IP`, `SHARE_DEFAULT_TTL_DAYS`.

---

## 1. Phase 1 — Enrichment

- [x] 1.1 Tor exit list: `server/src/tools/geoip/sources/tor.js`, Redis set + timestamp, 1 h TTL, `null` when stale > 24 h.
- [x] 1.2 Hosting ASN list: `server/src/tools/geoip/data/hosting-asns.json`, `basis: 'asn-list'`.
- [x] 1.3 Team Cymru DNS helper: origin TXT (v4 + nibble-reversed v6) and `AS<n>.asn.cymru.com`, 2 s timeout, 24 h cache.
- [x] 1.4 RDAP network details sharing **one** request with `rdapAbuse`, 24 h cache.
- [x] 1.5 Reputation: AbuseIPDB (key-gated, 6 h cache) and configurable DNSBL (IPv4 only, Spamhaus refusal codes = `unknown`).
- [x] 1.6 Result additions: `ip_type`, `ip_type_basis`, `privacy`, `privacy_sources`, `asn_detail`, `network`, `reputation`, `consensus`, `accuracy_radius_km`, `accuracy_basis`, `freshness`, `warnings`, `anycast`.
- [x] 1.7 Consensus: up to 2 providers when `GEOIP_CONSENSUS=true`, high/medium/low + `max_distance_km`, per-provider `latency_ms`.
- [x] 1.8 Unit fixtures/tests: Cymru TXT, RDAP, Tor list, DNSBL codes/timeouts, null-not-false, consensus thresholds, warnings.
- [x] 1.9 `docs/api-tools.md` + `.env.example` updated; server tests green.

## 2. Phase 2 — New inputs

- [x] 2.1 ASN tool: `server/src/tools/asn/index.js`, `GET|POST /api/tools/asn`, Tool enum `ASN` + migration, RIPEstat prefixes (cap 100).
- [x] 2.2 CIDR input: `GEOIP_CIDR` tool enum + route, IPv4 /24–32 and IPv6 /120–128, max 256 addresses, private/reserved skipped, async > 16.
- [x] 2.3 Bulk input: `GEOIP_BULK` tool enum + route, tier limits (FREE 10 / PAID 100), dedupe, `rejected[]`, always async, progress + per-row status, atomic multi-unit quota with refund.
- [x] 2.4 My IP: `GET /api/tools/geoip/me` using `req.ip` only (never parse X-Forwarded-For), friendly 422 for private callers.
- [x] 2.5 Tool registry, routes, Prisma migration, tests.

## 3. Phase 3 — Workflow

- [x] 3.1 History: `GET /api/tools/geoip/history`, delete one, clear all; retention documented and already enforced by `maintenance/retention.js`. UI history, delete, and clear-all shipped.
- [x] 3.2 Compare 2–4 completed results client-side with diff highlighting. Backend `/api/runs/compare` and history compare UI shipped.
- [x] 3.3 Share links: `ShareLink` model, 256-bit token, default 7 days / max 30, revoke; public `GET /api/share/:token` redacted, `no-store`, rate-limited.
- [x] 3.4 Reports: JSON, CSV (all fields incl. `ip_results`, formula-injection safe), Markdown, print stylesheet.
- [x] 3.5 OpenAPI `docs/openapi/geoip.yaml` for all new routes + contract drift test in `server/tests/unit/geoip-openapi.test.js`.
- [x] 3.6 `docs/api-tools.md` updated.

## 4. Phase 4 — Optional flags

- [x] 4.1 Reverse IP behind `GEOIP_REVERSE_IP` — no licensed provider selected; returns `null` + warning, documented as source-limited.
- [x] 4.2 Anycast hint `{likely, basis}` from a curated prefix/ASN list, default `null`.
- [x] 4.3 UI freshness + per-provider latency in the Provider section.
- [x] 4.4 Client lint/build; final docs.

## 5. Out of scope / source-limited

- Server-side PDF generation: print stylesheet only, no new dependency.
- Reverse IP provider: requires a licensed API; flag exists, value stays `null` with a warning until a provider is configured.
- Provider `db_date`: only populated when a provider actually reports it (currently none do).
