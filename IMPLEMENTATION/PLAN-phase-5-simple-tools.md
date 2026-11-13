# PHASE 5 — The Simple Tools: DNS, SSL, HTTP Headers, WHOIS/RDAP, GeoIP, Ping

> **For OpenCode.** Prerequisites: Phases 1–4 finished (all boxes ticked; unit, DB and API test suites green; Postgres + Redis running).
> Companions: `DATABASE-DESIGN.md`, **`docs/tool-route-contract.md`** (the mandatory pipeline from Phase 4 — re-read it first).
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`. Never write Python.**
> Old Python reference (read-only): `/tmp/old-cst` = `git clone --depth 1 https://github.com/Yash7256/cybersec-toolkit /tmp/old-cst`.
> Old files you will port: `cybersec/core/tools/{dns,ssl,http_headers,whois,geoip,ping}.py` and `cybersec/apps/api/routes/tools.py`, `cybersec/apps/api/schemas/tool.py`.

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]` here, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. **Never read a whole old Python file.** Use `grep -n` to find the function, then `sed -n 'A,Bp'` for that function only. The big ones (`geoip.py` 1068 lines, `http_headers.py` 705, `whois.py` 641) are ported **function by function** across several tasks.
3. Pipe long output through `tail -n 20`; run tests with `--reporter=dot`.
4. One commit per task, message given in the task. If verification fails twice → stop and report the exact error.
5. **No live internet in automated tests.** Unit/API tests use stubs and local servers. Live checks live only in `tests/live/` and run only when `LIVE_TESTS=1`.
6. Port **behavior**, not syntax. Where the old code had a weakness listed in §1, the new code must NOT copy it.
7. Never print secrets (`IPINFO_API_TOKEN`).

### 0.1 Reference registry

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina   # skills/node/rules/{async-patterns,performance,error-handling,testing}.md
```

| Short name | URL |
|---|---|
| UNDICI | https://undici.nodejs.org (Agent, `connect` options, `request`, timeouts, `maxRedirections`) |
| NODE-TLS | https://nodejs.org/docs/latest/api/tls.html (`tls.connect`, `getPeerCertificate`, `authorized`, `minVersion/maxVersion`) |
| NODE-X509 | https://nodejs.org/docs/latest/api/crypto.html#class-x509certificate |
| NODE-CHILD | https://nodejs.org/docs/latest/api/child_process.html (`execFile`, `signal`, `timeout`) |
| RDAP-RFC | https://www.rfc-editor.org/rfc/rfc9083 (JSON responses) and https://www.rfc-editor.org/rfc/rfc9224 (bootstrap) |
| RDAP-BOOT | https://data.iana.org/rdap/dns.json , https://data.iana.org/rdap/ipv4.json , https://data.iana.org/rdap/ipv6.json |
| DOH-CF | https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/ |
| DOH-GOOGLE | https://developers.google.com/speed/public-dns/docs/doh/json |
| OWASP-HEADERS | https://owasp.org/www-project-secure-headers/ |
| MDN-HEADERS | https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers |
| TLDTS | https://github.com/remusao/tldts |
| SELFSIGNED | https://github.com/jfromaniello/selfsigned |

---

## 1. Old weaknesses NOT to copy

| Old code | Problem | New rule |
|---|---|---|
| `ssl.py` resolved the host, then `create_connection((host, port))` re-resolved it | DNS rebinding | Connect to the **validated IP literal**; hostname only as SNI |
| `dns.py` used `Resolver()` with system config | Leaks/queries internal DNS | DNS tool uses **public resolvers only** (DoH to Cloudflare/Google) |
| `routes/tools.py` logged the full SSL result (`logger.info(result_dict)`) | Noisy, may log sensitive data | Log `{tool, runId, outcome, durationMs}` only |
| `_save_tool_result` swallowed DB errors and still answered | Silent data loss | Persisting the run is **part of the contract**; failure → 500 + refund |
| Free-form `str(e)` as error text | Leaks internals (IPs, paths) | Map errors to a fixed vocabulary (§2) |
| `http_headers` followed redirects with the library default | SSRF via redirect | **Manual** redirects, re-validated each hop |
| GeoIP last fallback `http://ip-api.com` (plain HTTP) | MITM / privacy | HTTPS-only; plain-HTTP provider off unless `GEOIP_ALLOW_INSECURE_PROVIDER=true` |
| Ping shelled out with the raw target | Argument/command injection | `execFile` (no shell), validated **IP literal**, `--` separator |
| WHOIS cache per process (OrderedDict) | Not shared | Redis cache, shared across instances |

---

## 2. Fixed design decisions

**API shape** (kept compatible with the old client): `POST /api/tools/<name>` → `200 { runId, tool, target, status, cached, data, quota }`. Inside `data`, **field names stay snake_case exactly as the Python dataclasses** (`query_time_ms`, `days_remaining`, …) so the React client ports with minimal change. Request field names also stay: dns/whois/geoip/ping/http_headers use `target`; ssl uses `host`.

**Tool definition** (each tool exports one object consumed by the shared route factory):
`{ name, toolEnum, schema (zod), touchesTarget: boolean, normalize(input), execute(ctx), summarize(data), dedupeTtlSec, timeoutMs }`.
- `touchesTarget=true` (ssl, http_headers, ping): full `validateTarget` → `targetLimiter` → quota. The tool connects only to `ctx.addresses`.
- `touchesTarget=false` (dns, whois, geoip): only `normalizeHost` / `classifyIp` (they query third-party services, never the target) → **no** per-target limiter, still quota.

**Run lifecycle** (table `tool_runs`, Phase 2): `RUNNING` → `COMPLETED` | `FAILED` | `TIMED_OUT`; `finished_at` always set on terminal states (DB CHECK enforces it); `summary` ≤ 1 KB; full result in `run_results.data` (cap 512 KB; oversize string fields such as `raw_text` are truncated and `truncated:true` is added).

**Error kinds → outcome → quota:**
| Kind | Example | Run status | HTTP | Quota |
|---|---|---|---|---|
| `target` | NXDOMAIN, connection refused, target timed out, no TLS | `COMPLETED`, `data.error` = friendly text | 200 | consumed |
| `upstream` | DoH/RDAP/GeoIP providers all down, breaker open | `FAILED` | 502 `UPSTREAM_ERROR` | **refunded** |
| `internal` | bug, DB write failed | `FAILED` | 500 | **refunded** |
| hard timeout (`TOOL_HARD_TIMEOUT_MS`) | tool exceeded budget | `TIMED_OUT` | 504 `TOOL_TIMEOUT` | **refunded** |

**Friendly error vocabulary** (only these strings reach clients): `Domain not found`, `No records of this type`, `Query timed out`, `Connection refused`, `Connection timed out`, `Connection reset`, `TLS handshake failed`, `Host not reachable`, `No TLS service on this port`, `Target returned an invalid response`, `Too many redirects`, `Redirect target not allowed`, `Response too large`, `Lookup service unavailable`, `Not registered`. Anything else → `Request failed` (details only in logs).

**Dedupe (user-level cache):** before quota, look for this user's `COMPLETED` run with the same `tool`, `target_key` and equal `options` (jsonb equality) newer than `dedupeTtlSec` → return it with `cached:true`, **no quota used, no network**. TTLs: dns 60, ssl 300, http_headers 120, whois 3600, geoip 3600, ping **0** (never).

**Global caches (Redis, shared across users):** WHOIS/RDAP 3600 s, GeoIP 3600 s, RDAP bootstrap 86 400 s. Redis down → cache miss, tool still works.

**Outbound network rule:** *all* outbound HTTP goes through `net/safeHttp.js`; all raw sockets through the validated-IP helpers; direct `fetch(`, `http.request`, `net.connect`, `tls.connect`, `dns.lookup` outside `security/`, `net/` and an explicit allow-list are forbidden and enforced by a test (T5.10).

---

## 3. Target structure (end of Phase 5)

```
server/src/
  config/env.js                    # + tool env vars
  net/
    safeHttp.js  circuitBreaker.js  dohClient.js  rdapClient.js
  tools/
    _shared/
      runTool.js  toolRoute.js  errors.js  limits.js  truncate.js
    dns/        index.js  schema.js  doh.js  contract.js
    ssl/        index.js  schema.js  probe.js  certInfo.js  contract.js
    httpHeaders/ index.js schema.js request.js contract.js
                 rules/ securityHeaders.js  techPatterns.js
                 analysis/ headers.js cookies.js misc.js scoring.js
    whois/      index.js schema.js rdapNormalize.js port43.js privacy.js contract.js
    geoip/      index.js schema.js providers/{ipinfo,ipwhois,ipapi}.js enrich.js contract.js
    ping/       index.js schema.js icmp.js tcp.js analytics.js contract.js
    index.js                         # registry of all tool definitions
  db/repos/runRepo.js
  routes/runs.js  routes/tools.js
docs/api-tools.md
tests/
  unit/ api/ db/ fixtures/ (rdap, doh, whois43, ping, ipinfo ...)  live/
```

---

## 4. Tasks

### Block A — Shared foundation

- [x] **T5.1 Orientation (read-only)**
  - Read `docs/tool-route-contract.md` and `server/src/middleware/{quota,limiters}.js` headers. Clone the old repo to `/tmp/old-cst`.
  - From the old repo print ONLY the dataclass blocks (use `grep -n "^@dataclass" -A 40` limited to the class bodies) of: `DNSResult`, `SSLResult`/`CertInfo`, `HTTPHeadersResult`, `WHOISResult`, `GeoIPResult` (+`RDAPData`), `PingResult`. Write each field list into `server/src/tools/<name>/contract.js` as `export const RESULT_KEYS = [...]` **as you go in later tasks** (not now) — now only confirm the field lists are readable.
  - Report: Node version, `uname -s`, whether `ping` exists (`command -v ping`), whether you have outbound internet (`curl -sI https://example.com | head -n 1`).
  - No commit.

- [x] **T5.2 Install packages**
  - `npm i undici tldts --workspace server` ; `npm i -D selfsigned --workspace server`.
  - Commit: `chore(server): add undici, tldts, selfsigned`

- [x] **T5.3 Env vars (`env.js`, `.env.example`, `vitest.config.js`, `env.test.js`)**
  - `HTTP_USER_AGENT` (default `CyberSecToolkit/1.0`), `TOOL_HARD_TIMEOUT_MS` (30000), `MAX_CONCURRENT_TOOL_RUNS` (50), `SSL_AUDIT_TIMEOUT_MS` (20000), `WHOIS_TIMEOUT_MS` (8000), `WHOIS_CACHE_TTL_SEC` (3600), `WHOIS_PRIVACY_PATTERNS` (comma list: `privacy,redacted,whoisguard,domains by proxy,contact privacy,data protected,private registration,withheld`), `WHOIS_SUSPICIOUS_STATUS_TOKENS` (`hold,pendingdelete,redemptionperiod,serverdeleteprohibited,clienthold`), `GEOIP_PROVIDER_ORDER` (default `ipinfo,ipwhois`), `IPINFO_API_TOKEN` (optional), `GEOIP_TIMEOUT_MS` (5000), `GEOIP_CACHE_TTL_SEC` (3600), `GEOIP_RATE_PER_MIN` (55), `GEOIP_MAX_CONCURRENT` (5), `GEOIP_ALLOW_INSECURE_PROVIDER` (bool via enum, default false), `PING_METHOD` (`auto|icmp|tcp`, default auto), `PING_HISTORY_TTL_SEC` (3600).
  - Booleans: explicit enum parse (never `z.coerce.boolean`). Commit: `feat(server): tool env vars`

- [x] **T5.4 `net/safeHttp.js` — the only outbound HTTP client**
  - **Read first:** UNDICI docs ("Agent", "Client options → connect", "request", "timeouts"), Phase 4 `security/resolve.js` + `targetPolicy.js`.
  - `createSafeHttp({ policy = strictPolicy, resolver })` → `{ request(url, opts) }`:
    - Modes: `mode:'user'` (host goes through `validateTarget`) and `mode:'trusted'` (host must be in `opts.allowHosts`; https only; **still** resolved once and every address checked with `classifyIp`).
    - Resolve once → `Agent({ connect: { lookup: pinnedLookup(addresses), rejectUnauthorized: opts.verifyTls ?? true, servername } })`. If your undici version ignores `connect.lookup`, connect to the validated IP via a custom `connect` function with the original `servername` — verify with a test that DNS is called exactly once.
    - **Manual redirects**: `maxRedirections: 0`; loop ≤ `opts.maxRedirects ?? 5`; each hop → `validateRedirect`; cross-scheme downgrade https→http allowed only if `opts.allowDowngrade`.
    - Limits: connect timeout 5 s, headers timeout 8 s, body timeout 8 s, total deadline `opts.deadlineMs`; `maxHeaderSize` 32 KB; body cap `opts.maxBytes` (default 1 MB; `headersOnly:true` destroys the body immediately); no cookie jar; no auto-decompress; fixed `User-Agent`.
    - URL building: **string-concatenate** `origin + path` and assert `new URL(result).host === expectedHost` (never `new URL(path, base)`, because `//evil.com` would swap the host).
    - Returns `{ status, headers (lower-case keys; set-cookie as array), finalUrl, redirects: [{from,to,status}], addresses, elapsedMs, bytes }`; throws `ToolError` with kinds/vocabulary from §2.
  - Commit: `feat(net): safe http client with pinning and manual redirects`

- [x] **T5.5 `tests/unit/safe-http.test.js` (local server + injected policy)**
  - Tests inject a permissive policy/resolver mapping `app.test → 127.0.0.1` (**test-only injection, never in `src/`**). Separate tests use the strict default and prove a loopback server is **blocked**.
  - Cases: 200 headers-only; body cap exceeded → `Response too large`; slow-loris (server never ends headers) → timeout; redirect chain of 5 ok, 6 → `Too many redirects`; **redirect to `http://169.254.169.254/`** → `Redirect target not allowed`; redirect to a hostname the stub resolves to `127.0.0.1` → blocked; relative redirects resolved correctly; `//evil.com` path keeps the host; resolver called **exactly once** per request; trusted mode rejects a host not in `allowHosts`.
  - Commit: `test(net): safe http client`

- [x] **T5.6 `net/circuitBreaker.js`**
  - `createBreaker({ name, failureThreshold = 5, windowMs = 60000, openMs = 60000 })` → `{ exec(fn) }`; states closed/open/half-open (one probe); open → throws `ToolError('upstream','Lookup service unavailable')` immediately; metric `cst_breaker_open_total{name}` (names enumerated: `doh`, `rdap`, `geoip`, `whois43`).
  - Tests with fake timers: opens after N failures inside the window; half-open success closes; half-open failure re-opens; successes in-window don't accumulate failures forever.
  - Commit: `feat(net): circuit breaker`

- [x] **T5.7 `tools/_shared/*` + `db/repos/runRepo.js`**
  - `errors.js`: `ToolError(kind, message)` with `kind ∈ target|upstream|internal` (+ mapper from Node errno/TLS codes to the §2 vocabulary).
  - `runRepo`: `start({userId, tool, target, targetKey, options})` → RUNNING row; `complete(id, {data, summary})` (single transaction: insert `run_results`, update status/progress/finished_at/summary); `fail(id, {status, errorCode, message})`; `findRecentCompleted({userId, tool, targetKey, options, withinSec})` using `options IS NOT DISTINCT FROM $n::jsonb`; `findByIdForUser(id, userId)`; `listForUser({userId, tool?, cursor?, limit})` **keyset** per `DATABASE-DESIGN.md` §3; `deleteForUser(id, userId)`. **Every read/delete takes `userId` in the WHERE** (IDOR-proof).
  - `truncate.js`: `capResult(data, maxBytes = 512*1024)` — shrinks the longest string fields first, sets `truncated:true`.
  - `runTool.js`: semaphore (`MAX_CONCURRENT_TOOL_RUNS`; overflow → `503 SERVER_BUSY`), hard timeout via `AbortController` (`TOOL_HARD_TIMEOUT_MS`), the lifecycle/refund table from §2, metrics `cst_tool_runs_total{tool,outcome}` and `cst_tool_run_duration_seconds{tool}` (add to the Phase 4 registry; enumerated labels).
  - `toolRoute.js`: builds the Express handler from a tool definition: `requireAuth → attachUser → submit limiters → zod → [assertNotCoolingDown → validateTarget → targetLimiter] (if touchesTarget) | normalize-only → dedupe lookup → enforceQuota → runTool → envelope`. Response header `X-Run-Id`. Log `{tool, runId, outcome, durationMs}` only.
  - Commit: `feat(tools): shared run lifecycle, repo and route factory`

- [x] **T5.8 `tests/db/run-repo.test.js` + `tests/api/tool-route.test.js` (with a fake tool)**
  - Repo: keyset pagination returns each row exactly once even when 30 rows share one `created_at`; page size capped at 50; other user's id → `null`/0 rows (IDOR); `complete` writes both tables atomically (force a failure mid-way → nothing persisted); terminal status without `finished_at` rejected by the DB.
  - Route with a fake tool: order of pipeline steps (spy), invalid input never consumes quota, `upstream` error → 502 + quota refunded, hard timeout → `TIMED_OUT` + refund, `target` error → 200 + consumed, dedupe hit → `cached:true` + quota unchanged + zero execute calls, semaphore overflow → 503, oversized result truncated.
  - Commit: `test(tools): run lifecycle, repo, route factory`

- [x] **T5.9 Runs API + tool catalogue**
  - `GET /api/runs?tool=&limit=&cursor=` (cursor = opaque base64url of `{createdAt,id}`, validated; malformed → 400), `GET /api/runs/:id` (joins `run_results`), `DELETE /api/runs/:id` — all behind `requireAuth + attachUser`; another user's run → **404** (never 403). `GET /api/tools` → `[ { name, label, description, touchesTarget, input: {...field descriptions}, dailyLimit } ]` built from the registry.
  - Tests: pagination across pages, filter by tool, IDOR 404, `Cache-Control: no-store`.
  - Commit: `feat(server): runs history and tool catalogue endpoints`

- [x] **T5.10 Raw-network guard test**
  - `tests/unit/no-raw-network.test.js` scans `src/**/*.js` (excluding `src/security/`, `src/net/`, `src/redis/`, `src/db/`, and an explicit allow-list file `tests/unit/network-allowlist.json` with a reason per entry) for `fetch(`, `http.request`, `https.request`, `net.connect`, `tls.connect`, `dns.lookup`, `dns.promises`, `execFile`, `spawn(`, `exec(`. Any other hit fails the test.
  - Allow-list entries expected later: `tools/ssl/probe.js` (tls.connect to a validated IP), `tools/ping/icmp.js` (execFile `ping`), `tools/ping/tcp.js` (net.connect to a validated IP).
  - Commit: `test(security): forbid raw network calls outside approved modules`

### Block B — DNS

- [x] **T5.11 `tools/dns/*`**
  - **Read first:** DOH-CF and DOH-GOOGLE (JSON format), old `dns.py` `dns_lookup()` only.
  - `net/dohClient.js`: `query(name, type)` via `safeHttp` trusted mode (`cloudflare-dns.com`, `dns.google`; header `accept: application/dns-json`), breaker `doh`, Cloudflare first then Google. Type numbers: A 1, NS 2, CNAME 5, SOA 6, PTR 12, MX 15, TXT 16, AAAA 28, CAA 257. `Status 3` = NXDOMAIN; `Status 0` with no `Answer` = no data. Parse `AD` → `dnssec_validated`.
  - Request: `{ target, record_type: 'ALL'|'A'|'AAAA'|'MX'|'NS'|'TXT'|'CNAME'|'SOA'|'CAA' }` (default `ALL` = the old seven + `CAA`). IP input → **PTR** lookup (build `in-addr.arpa` / `ip6.arpa` name; only for public IPs via `classifyIp`).
  - Record mapping exactly like the old code: `{type, ttl, value}`; MX adds `priority`; SOA adds `mname,rname,serial` (`value = mname`); TXT: unquote and **join the chunks**; strip trailing dots consistently with the old `to_text()` behavior (keep trailing dot on names as old code did — verify on one MX/NS example from the Python source).
  - All types queried **in parallel**, each 5 s, overall 8 s. Result `{ target, record_type, records, query_time_ms, error }` + additive `dnssec_validated`, `resolver`. `error`: first-wins like the old logic (`Domain not found` stops early).
  - Last-resort fallback if both DoH providers are down: `new dns.promises.Resolver()` with `setServers(['1.1.1.1','8.8.8.8'])` (explicit public servers, never system config; no TTLs → `ttl:null`).
  - `touchesTarget:false`; `normalizeHost` only; `dedupeTtlSec:60`; summary `{ recordCount, types, error }`.
  - Commit: `feat(tools): dns tool over public DoH`

- [x] **T5.12 `tests/unit/dns.test.js` (stub DoH with fixture JSON)**
  - NOERROR with A/AAAA/MX/NS/TXT(multi-chunk)/SOA/CAA; NXDOMAIN → `error:"Domain not found"`; NODATA → `"No records of this type"`; timeout → `"Query timed out"`; Cloudflare down → Google used; both down → resolver fallback, `ttl:null`; IP input → PTR name built correctly for IPv4 and IPv6; private IP input rejected; `localhost` rejected; **spy proves system `dns.lookup/resolve` is never called**; result keys equal `RESULT_KEYS`.
  - Commit: `test(tools): dns`

### Block C — SSL

- [x] **T5.13 `tools/ssl/*`**
  - **Read first:** NODE-TLS (`tls.connect`, `getPeerCertificate(true)`, `socket.authorized`, `authorizationError`, `getCipher`, `getProtocol`), NODE-X509; old `ssl.py` `ssl_audit()` and the response mapping in `routes/tools.py` `run_ssl`.
  - Request `{ host, port = 443 }`. `touchesTarget:true`; `dedupeTtlSec:300`.
  - `probe.js`: **connect to `ctx.addresses[0].address` (IP literal)**, `servername = host` (omit when host is an IP), `rejectUnauthorized:false` (audit broken certs), 5 s timeout, `socket.destroy()` in `finally`. Three probes concurrently: default negotiation (cipher + protocol + cert DER via `getPeerCertificate(true).raw`), TLS 1.2-only (`minVersion=maxVersion='TLSv1.2'`), TLS 1.3-only. Overall budget `SSL_AUDIT_TIMEOUT_MS`.
  - `certInfo.js` with `new X509Certificate(raw)`: `subject`/`issuer` parsed into objects using the old key names (`commonName, organizationName, countryName, stateOrProvinceName, localityName, organizationalUnitName`), `valid_from`/`valid_to` ISO UTC, `days_remaining` (floor), `is_expired`, `san` (DNS names only, as the old code), `is_self_signed` (`subject===issuer` **and** `x509.verify(x509.publicKey)`).
  - **Final response mirrors the old route's transformed output**: `{ host, port, tls_version, cipher_suite, certificate: { valid_from, valid_to, days_remaining, issuer, subject, san, is_expired }, valid, is_self_signed, supports_tls12, supports_tls13, error }`. Additive fields: `chain_trusted` (= `socket.authorized`), `authorization_error` (friendly), `hostname_matches` (`x509.checkHost(host)`), `fingerprint_sha256`, `key_type`, `key_bits`.
  - Errors mapped to the vocabulary (`ECONNREFUSED`→`Connection refused`, `ETIMEDOUT`→`Connection timed out`, `ECONNRESET`→`Connection reset`, `ERR_SSL_*`/`EPROTO`→`TLS handshake failed`, no TLS on port→`No TLS service on this port`).
  - Commit: `feat(tools): ssl audit tool with pinned ip connections`

- [x] **T5.14 `tests/unit/ssl.test.js` (local TLS servers with `selfsigned`)**
  - Tests inject a permissive policy mapping `ssl.test → 127.0.0.1` (test-only). Cases: self-signed cert → `is_self_signed:true`, `chain_trusted:false`; expired cert (`notAfterDate` in the past) → `is_expired:true`, `valid:false`, negative `days_remaining`; TLS-1.2-only server → `supports_tls12:true, supports_tls13:false`; TLS-1.3-only server → the reverse; SAN list returned; hostname mismatch → `hostname_matches:false`; closed port → `Connection refused` with status `COMPLETED`; plain-HTTP port → `No TLS service on this port`/`TLS handshake failed`; silent server → times out within budget; **the connect target is the IP literal** (spy on `tls.connect` options); keys equal `RESULT_KEYS`.
  - Commit: `test(tools): ssl`

### Block D — HTTP headers

- [x] **T5.15 `tools/httpHeaders/request.js` + schema**
  - **Read first:** old `http_headers.py` `_normalize_target` and the request section of `check_http_headers` (grep for `httpx` / `client.get`; read only those lines).
  - Request `{ target, path = '/' }` (`target` = hostname **or** `http(s)://…` URL; default scheme https, fall back to http only if https fails to connect). `path`: ≤ 2048, must start with a single `/`, no CR/LF/space/control chars, **no `//` prefix** → `VALIDATION_ERROR`.
  - Use `safeHttp` (user mode) with `headersOnly:true`, GET, `accept-encoding: gzip, br`, `verifyTls:false` (audit, like the old `tls_verification_skipped:true`), `maxRedirects:5`, collecting the redirect chain. `touchesTarget:true`; `dedupeTtlSec:120`.
  - Tests (`tests/unit/http-headers-request.test.js`): URL vs hostname input, path rules (`//evil.com`, `/a%0d%0ab`, 2049 chars), https→http fallback, redirect chain recorded, redirect to private address blocked → friendly error.
  - Commit: `feat(tools): http headers request layer`

- [x] **T5.16 Port the rule data (`rules/securityHeaders.js`, `rules/techPatterns.js`)**
  - From old `http_headers.py`: the `SECURITY_HEADERS` list (lines ≈ 69–145: header name, severity, description, recommendation) and the technology/CDN/WAF pattern dicts used by `_detect_technologies`, `_detect_from_patterns`, `_cloud_provider`. Print only those line ranges (`sed -n`). Port as plain exported data; keep every entry; no logic here.
  - Test: counts match the Python source (assert `SECURITY_HEADERS.length` equals the number you counted; list the counts in the commit body).
  - Commit: `feat(tools): security header and technology rule data`

- [x] **T5.17 `analysis/headers.js` — security headers, HSTS, CSP, clickjacking**
  - Port `_analyze_security_headers`, `_hsts_strength`, `_csp_analysis`, `_clickjacking` (read each function alone). Pure functions (`headers` object in → analysis out), no I/O.
  - Table tests: for each function ≥ 6 cases covering missing / weak / strong (HSTS `max-age` too low, no `includeSubDomains`, preload; CSP with `unsafe-inline`, `unsafe-eval`, wildcard, missing `frame-ancestors`; X-Frame-Options vs CSP `frame-ancestors`). Derive expected values by **reading the Python branches**, not by guessing.
  - Commit: `feat(tools): header, hsts, csp and clickjacking analysis`

- [x] **T5.18 `analysis/cookies.js` + `analysis/misc.js`**
  - Port `_analyze_cookies` (parse `Set-Cookie` strings: `Secure`, `HttpOnly`, `SameSite`, risk + issues; `scheme` aware), `_compression`, `_cache_analysis`, `_cors_analysis`, `_information_disclosure`, `_allowed_methods` (from the `Allow` header only — **no extra OPTIONS request**), `_api_detection`, `_cloud_provider`, `_detect_technologies` (+ CDN/WAF).
  - Table tests ≥ 5 cases per function (e.g. cookie without Secure on https, `SameSite=None` without Secure, `Access-Control-Allow-Origin: *` with credentials, `Server: nginx/1.18.0` version disclosure, `X-Powered-By`, `Allow: GET, POST, TRACE, PUT` → dangerous methods).
  - Commit: `feat(tools): cookie, cors, cache and disclosure analysis`

- [x] **T5.19 `analysis/scoring.js`, assembly and route**
  - Port `_score_result`, `_response_time_rating`, `_redirect_chain`, `_timeline`, `_summary`, recommendations, `compliance` assembly (read `_score_result` carefully — it also produces `compliance`). `ai_summary: null` (Phase 8). Keep `tls_verification_skipped:true`.
  - `index.js` assembles the final `HTTPHeadersResult` with **exactly** the dataclass keys (`RESULT_KEYS` in `contract.js`); `error` filled with the vocabulary on failure (the old `_empty_result` shape for failures).
  - Summary for history: `{ statusCode, securityScore, riskLevel, host, error }`.
  - Commit: `feat(tools): http headers scoring and assembly`

- [x] **T5.20 `tests/unit/http-headers.test.js` (local server presets)**
  - Presets: all-secure site (score high, risk low), bare site (no headers → many findings), weak CSP, insecure cookies, 3-hop redirect chain, Cloudflare-like (`cf-ray`, `server: cloudflare` → `cdn` detected), `Server: Apache/2.4.1` disclosure, `Allow` with TRACE, https-only target that refuses connection → friendly error; keys equal `RESULT_KEYS`; response never includes the body.
  - Commit: `test(tools): http headers`

### Block E — WHOIS / RDAP

- [x] **T5.21 `net/rdapClient.js`**
  - **Read first:** RDAP-RFC (sections on domain and IP network objects, `events`, `entities`, `vcardArray`, `status`, `nameservers`, `secureDNS`), RDAP-BOOT file shapes.
  - Bootstrap loader: fetch `dns.json`, `ipv4.json`, `ipv6.json` via `safeHttp` trusted mode (`data.iana.org`), cache in Redis 24 h (+ in-memory copy). `findServer(tld)` / `findServerForIp(ip)` (longest-prefix match over the CIDR list — implement with your Phase 4 IP utilities, no new dep).
  - `queryDomain(domain)` / `queryIp(ip)`: server URL from bootstrap, **https only, host must resolve to public addresses** (policy still applies), breaker `rdap`, timeout `WHOIS_TIMEOUT_MS`, follow `Link rel=related` once at most. `404` → `{ found:false }`. Respect `429` with `Retry-After` (surface as `upstream`).
  - Commit: `feat(net): rdap client with iana bootstrap`

- [x] **T5.22 `tools/whois/rdapNormalize.js` + `privacy.js`**
  - **Read first:** old `whois.py` `_parse_date`, `_expiry_status`, `_privacy_detected`, `_risk_indicators`, `_status_explanations` and the `STATUS_EXPLANATIONS` table (print only these).
  - Map RDAP JSON → the old `WHOISResult` fields: registrar (+ IANA id, url, abuse email/phone from the `abuse` entity vCard), `creation_date/expiration_date/updated_date` from `events` (`registration`, `expiration`, `last changed`), `name_servers` (lower-case, de-duplicated), `status` + `status_explanations`, `dnssec` (`secureDNS.delegationSigned`), registrant org/country/admin/tech/abuse contacts (usually redacted → `privacy_protected:true`), derived `domain_age_days`, `days_until_expiry`, `expiry_status` (reuse the exact thresholds from `_expiry_status`), `risk_indicators`, `summary`, `normalized`, `rdap`, `rdap_available:true`, `registry`, `tld`. `historical_whois` and `related_domains` stay as `{}` with a `{ available:false }` marker (explicitly out of scope).
  - Tests with JSON fixtures in `tests/fixtures/rdap/` (hand-built to RFC 9083 shape, plus — if you have internet — one real `.com` and one IPv4 response saved via curl): normal domain, privacy-redacted domain, expired domain, `clientHold` domain, brand-new domain (< 30 days → risk indicator), IP network object.
  - Commit: `feat(tools): rdap to whois result normalization`

- [x] **T5.23 `tools/whois/port43.js` — fallback for TLDs without RDAP**
  - Evaluate the `whoiser` npm package (read its README only). **Use it only if** it supports a connect timeout and lets you control the socket/lookup; otherwise implement a ~80-line client: `net.connect` to `whois.iana.org:43` → follow `refer:`/`whois:` once → query the registry server; connections go to **validated public IPs** via the Phase 4 helpers; 10 KB response cap; 8 s timeout; breaker `whois43`. Add it to the network allow-list file with a reason.
  - Parser: case-insensitive `key: value` lines → registrar, dates (many formats via a tolerant parser), name servers, status, emails; unknown fields stay in `raw_text` (truncated). Mark `rdap_available:false`.
  - Tests with canned text fixtures (two registries with different date formats and a "No match / not found" body → `available:true`).
  - Commit: `feat(tools): legacy whois fallback`

- [x] **T5.24 `tools/whois/index.js`, route, cache**
  - Request `{ target }`: domain, URL, or IP. Normalize: strip scheme/path/`www.`; reduce to the **registrable domain** with `tldts.getDomain()` (reject when null); IPs via `classifyIp` (public only) → RDAP IP path. `touchesTarget:false`.
  - Flow: Redis cache `cst:whois:<targetKey>` (TTL `WHOIS_CACHE_TTL_SEC`) → RDAP → (no RDAP for TLD) port-43 → result. RDAP `404`/"not found" → `available:true`, `error:"Not registered"`-style friendly result (still `COMPLETED`). Result `cached:true` when served from Redis.
  - Summary: `{ registrar, expiryStatus, daysUntilExpiry, privacyProtected, available }`; keys equal `RESULT_KEYS`.
  - Tests: subdomain input → registrable domain; URL input; IP input; cache hit makes zero upstream calls; RDAP down + breaker open → `upstream` kind (502, refunded); Redis down still works.
  - Commit: `feat(tools): whois tool with rdap primary and shared cache`

### Block F — GeoIP

- [x] **T5.25 Providers (`tools/geoip/providers/*.js`)**
  - **Read first:** old `geoip.py` lines for the three providers only (`IPWhoIsProvider`, `IPApiProvider`, `IPInfoProvider` ≈ 198–475) and the `GeoIPResult` dataclass (116–185).
  - Common interface `{ name, lookup(ip, { signal }) → partial GeoIPResult }` using `safeHttp` trusted mode with `allowHosts` = `ipwho.is`, `ipinfo.io`, (`ip-api.com` only when `GEOIP_ALLOW_INSECURE_PROVIDER`; it is plain HTTP — the trusted-mode HTTPS rule must be explicitly relaxed for this one provider and documented). Field mapping exactly like the old code (e.g. ipinfo `loc` "lat,lon" split; ASN parsing from `org`).
  - Tests with provider fixture JSON: each mapping; provider returning `success:false` → throws `upstream`; malformed JSON; missing coordinates.
  - Commit: `feat(tools): geoip providers`

- [x] **T5.26 `tools/geoip/index.js` + `enrich.js`, route**
  - Request `{ target }` (host or IP). `touchesTarget:false`, but the host is resolved through the **policy** (public addresses only; no private-lookup flag exists anymore).
  - Primary IP = first IPv4 else first address; other addresses listed in the result (as the old `_resolve_target` did — read it).
  - Fallback chain per `GEOIP_PROVIDER_ORDER`; each provider: Redis-cached 3600 s (key `cst:geoip:<ip>`), outbound limiter `geoip` at `GEOIP_RATE_PER_MIN` (Phase 4), semaphore `GEOIP_MAX_CONCURRENT`, one transient retry after 300 ms, `fallback_note` when a later provider answered, breaker `geoip`.
  - Enrichment: reverse DNS via `new dns.promises.Resolver()` with public servers, CDN detection (port `_detect_cdn` patterns), RDAP abuse contact via the shared `rdapClient.queryIp` (port `_extract_rdap_abuse`), `map_url`.
  - Keys equal `RESULT_KEYS`; summary `{ country, city, asn, provider, isCdn }`.
  - Tests: provider order and fallback; all providers fail → `upstream` (502, refunded); cache hit → zero provider calls; rate limiter waits instead of rejecting (use fake timers) and `UPSTREAM_BUSY` beyond max wait; private target blocked; concurrency never exceeds 5 (counter in stub).
  - Commit: `feat(tools): geoip tool`

### Block G — Ping

- [x] **T5.27 `tools/ping/analytics.js` (pure)**
  - Port the pure helpers from old `ping.py` lines ≈ 56–200 (`_quality`, `_loss_severity`, `_jitter_label`, `_ttl_guess`, `_distribution`, `_trend`, `_stability_score`, `_suitable_for`, `_network_type`, `_route_insight`, `_recommendations`, `_summary`) plus the statistics (min/avg/max, jitter, std-dev, variance) — read them in 3 chunks. No I/O.
  - Table tests: ≥ 5 cases per helper including empty/1-sample/100%-loss edge cases; thresholds copied from the Python source.
  - Commit: `feat(tools): ping analytics`

- [x] **T5.28 `tools/ping/icmp.js` (system `ping`, Linux iputils)**
  - **Read first:** NODE-CHILD (`execFile`, `timeout`, `killSignal`, `maxBuffer`); old `ping.py` `_parse_reply_line` and the subprocess section.
  - Args array (never a shell): `['-n','-c',String(count),'-i','0.5','-W','2', (v6?'-6':'-4'), '--', ip]`; `ip` is the validated literal from `ctx.addresses`; `env:{ LC_ALL:'C', PATH:'/usr/bin:/bin' }`; hard timeout `count*0.5 + 5 s`; `maxBuffer` 64 KB.
  - Parser for per-reply lines (`icmp_seq`, `ttl`, `time=`) and the summary (`transmitted/received/loss`, `rtt min/avg/max/mdev`), IPv4 and IPv6, **100 % loss** and partial loss.
  - Add to the network allow-list file. Tests: parser fixtures (Linux iputils v4/v6/loss/partial); **argument-injection tests** (a malicious `target` can never reach `execFile` because only the validated IP does; assert args never start with `-` before `--`); `count` outside 1–20 rejected by the schema.
  - Commit: `feat(tools): icmp ping runner and parser`

- [x] **T5.29 `tools/ping/tcp.js`, selection, history, route**
  - TCP fallback: `count` timed `net.connect` attempts to the validated IP on port 443 then 80 (first that answers), 2 s each, sequential 200 ms apart; result `method:'tcp'`, `ttl:null`, `likely_os_family:null`.
  - `PING_METHOD=auto`: use ICMP when `process.platform==='linux'` and `ping` is executable (checked once at boot, cached), else TCP; `icmp` forces ICMP (error if missing); `tcp` forces TCP. Result has additive `method`.
  - Request `{ target, count = 4 }` with **`count` 1–20** (deviation from the old 1–100: ICMP runs synchronously for now; Phase 6 will raise it through the queue — note this in `docs/api-tools.md`).
  - History: Redis `cst:ping:last:<userId>:<targetKey>` (TTL `PING_HISTORY_TTL_SEC`) → `history_delta_ms`. Geo block: call the GeoIP service **function** internally (cache + breaker, **no extra quota**); if it fails, `geo:{}`.
  - `touchesTarget:true`, `dedupeTtlSec:0`; summary `{ avgMs, lossPct, quality, method }`; keys equal `RESULT_KEYS`.
  - Tests: TCP method against a local server (latency stats, 100 % loss when closed); selection logic with injected platform/binary availability; ICMP integration test **skipped** automatically when `ping` or its capability is unavailable (`it.skipIf`); history delta across two runs; geo failure doesn't fail the run.
  - Commit: `feat(tools): ping tool with icmp and tcp methods`

### Block H — Wiring, hardening, close-out

- [x] **T5.30 Registry, mount and the table-driven contract test**
  - `tools/index.js` exports all six definitions; `routes/tools.js` mounts `POST /api/tools/dns|whois|ping|ssl|http_headers|geoip` **plus the legacy GET aliases the old API had** (`GET /api/tools/whois?target=`, `GET /api/tools/geoip?target=`, `GET /api/tools/geo?target=`) via the same pipeline (GET → same quota/limits, query validated by the same zod schema).
  - `tests/api/tools-contract.test.js` loops over **every tool** (stubbed network): unauthenticated → 401; invalid body → 400 and `used` unchanged; blocked target → 422 and `used` unchanged (touchesTarget tools); 6th call by a FREE user → 429 `QUOTA_EXCEEDED`; upstream failure → 502 and quota refunded; success persists a `tool_runs` row (`COMPLETED`) + `run_results`, appears in `GET /api/runs`, and `GET /api/runs/:id` returns the identical `data`; envelope has `runId, tool, target, status, cached, data, quota`; `data` keys ⊇ `RESULT_KEYS`; no response body contains an IPv4/IPv6 literal that was not part of the *result data* (error paths never leak resolved IPs); a repeated identical call is `cached:true` with quota unchanged (except ping).
  - Commit: `feat(tools): mount tool routes and contract test suite`

- [x] **T5.31 Resilience and load tests**
  - 50 concurrent mixed tool calls with stubbed network: all complete, event-loop p99 stays under 100 ms (read `cst_eventloop_lag_p99_seconds`), DB pool never exhausted (`waiting` gauge ≤ pool size).
  - `MAX_CONCURRENT_TOOL_RUNS=2` with 5 simultaneous slow runs → exactly 3 get `503 SERVER_BUSY`, quota refunded for them.
  - Hard timeout path (tool sleeps forever) → run `TIMED_OUT`, quota refunded, no leaked sockets/timers (`process._getActiveHandles()` count returns to baseline in the test).
  - Redis down: every tool still works (cache misses) and rate limiters fail open.
  - Commit: `test(tools): concurrency, timeout and degradation`

- [x] **T5.32 Security review + docs**
  - Run the raw-network guard; list every allow-list entry with its justification. Grep that no tool imports `child_process` except `ping/icmp.js`, and that no `req.*` value reaches `execFile` (only validated IPs/ints).
  - Confirm each error path returns only vocabulary strings (add a test that scans all `ToolError` messages used in `src/tools`).
  - Confirm logs never contain full results or the ipinfo token (`grep -rn "IPINFO" src | grep -v env.js`).
  - Update `docs/tool-route-contract.md` with the **"Adding a tool" recipe** (≤ 25 lines: schema → definition → summarize → fixtures → registry → contract test row) and write `docs/api-tools.md` (≤ 120 lines): per tool, request fields, limits, `data` keys, error vocabulary, dedupe TTL, the ping `count` deviation, the `method` field.
  - Commit: `docs: tools api reference and review fixes`

- [x] **T5.33 Live smoke test (USER-ASSISTED; needs real internet; optional in CI)**
  - `tests/live/smoke.test.js` (runs only with `LIVE_TESTS=1`): `example.com` through all six tools via the real route stack; assert status 200, plausible fields (`dns` has an A record, `ssl` has `supports_tls12`, `http_headers.status_code` is 200/3xx, `whois.registrar` not null or `available` false, `geoip.country` not null), and print timings.
  - Ask the user to run it and paste the timing table. If any tool exceeds 15 s, report which stage was slow (use the metrics histogram).
  - Final: `git log --oneline | head -n 40`, test counts per suite, `tree server/src/tools -L 2`.

---

## 5. Definition of Done (Phase 5)

- [x] 33 tasks ticked, one commit each; no secrets committed or logged.
- [x] Six tools live behind the exact Phase 4 pipeline; invalid / blocked / rate-limited requests never consume quota; upstream/internal failures and hard timeouts are refunded.
- [x] Every outbound connection is pinned to validated IPs; the raw-network guard test passes; redirects are re-validated each hop.
- [x] DNS uses public resolvers only; no system-resolver call exists in the DNS path (spy test).
- [x] Response `data` keeps the old snake_case field names (`RESULT_KEYS` per tool) so the React client ports directly.
- [x] History (`/api/runs`), single run, delete and tool catalogue work; other users' runs return 404.
- [x] No live internet in automated tests; live smoke test documented and passing on a networked machine.
- [x] Zero Python; `client/` untouched.

**When finished, report:** test counts per suite, the live-smoke timing table, the list of network allow-list entries, whether ICMP ping ran on your platform (or fell back to TCP), and any field you could not reproduce from the old results. Then wait for the Phase 6 file (BullMQ queue and workers, job store, crash recovery, retention jobs — and raising ping `count`).
