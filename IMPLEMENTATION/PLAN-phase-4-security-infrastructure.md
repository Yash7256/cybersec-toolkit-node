# PHASE 4 — Security & Infrastructure (Target Policy, Redis, Rate Limiting, Metrics)

> **For OpenCode.** Prerequisites: Phases 1–3 finished (all boxes ticked; unit, DB and API tests green).
> Companions: `DATABASE-DESIGN.md` (no schema change in this phase), `docs/tool-route-contract.md`.
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`. Never write Python.**
> This phase protects **third parties and your own network** from your own scanner. Treat every task as security-critical: tests are the specification.

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]` here, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. Do NOT read the whole repo. Read only files a task names (`sed -n`, `head -n 60`).
3. Pipe long output through `tail -n 20`. Run tests with `--reporter=dot`.
4. Fetch a doc/skill ONLY when a task says so; read only the named file/section.
5. One commit per task, message given in the task.
6. If verification fails twice → stop, report the exact error, do not redesign.
7. Never print or commit secrets (`METRICS_TOKEN`, `REDIS_URL` with password).
8. **Test-first for security code:** in Block B, write the table tests (T4.7, T4.9) BEFORE trusting the implementation. A bypass found later = a failing test added first.

### 0.1 Skill / reference registry

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina
#  skills/node/rules/{performance,async-patterns,error-handling,testing,logging,graceful-shutdown}.md
```

| Short name | URL |
|---|---|
| OWASP-SSRF | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html |
| IANA-IPV4 | https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml |
| IANA-IPV6 | https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml |
| NODE-DNS | https://nodejs.org/docs/latest/api/dns.html (`dns.promises.lookup`, `all`, `verbatim`) |
| NODE-NET | https://nodejs.org/docs/latest/api/net.html (`net.connect` `lookup` option, `net.isIP`) |
| NODE-URL | https://nodejs.org/docs/latest/api/url.html (`domainToASCII`) |
| IPADDR | https://github.com/whitequark/ipaddr.js |
| RLF | https://github.com/animir/node-rate-limiter-flexible/wiki (RateLimiterRedis, insuranceLimiter, blockDuration) |
| IOREDIS | https://github.com/redis/ioredis |
| PROM-CLIENT | https://github.com/siimon/prom-client |
| PROM-NAMING | https://prometheus.io/docs/practices/naming/ |

---

## 1. What the old Python code got wrong (fixed here by design)

| Old behavior (`policy.py`, `throttle.py`) | Risk | New behavior |
|---|---|---|
| Resolved DNS, validated, returned only the **first** IP; the scanner re-resolved later | **DNS rebinding / TOCTOU**: attacker's DNS answers public first, `127.0.0.1` second | Resolve **once**, validate **all** addresses, **pin** them; tools connect only via `pinnedLookup` |
| `::ffff:127.0.0.1` (IPv4-mapped IPv6) not in the deny list | Loopback/internal bypass | Normalize/unwrap mapped, NAT64, 6to4 addresses and re-check the embedded IPv4 |
| Error text included the resolved IP and CIDR | Lets attackers map internal DNS | Generic message + stable code; detail only in audit log/metrics |
| Missing ranges (0.0.0.0/8, 198.18.0.0/15, 240.0.0.0/4, NAT64, 6to4, Teredo, doc ranges) | Gaps | Full IANA special-purpose list |
| `ALLOW_PRIVATE_TARGET_SCANS` flag usable "for authenticated callers" | Production SSRF switch | One flag, **refuses to boot in production** |
| Per-IP throttle in process memory (10 submissions / 60 s) | Not shared across workers/instances | Redis-backed, shared, per-user **and** per-IP, fail-open with in-memory insurance |
| No protection for the *victim* | Your scanner can be used to hammer one site | Per-target hourly limit across all users; cooldown after repeated blocked attempts |

---

## 2. Fixed design decisions

| Topic | Decision |
|---|---|
| Error status/codes | Bad shape → `400 VALIDATION_ERROR` (zod). Policy → **`422`**: `TARGET_INVALID`, `TARGET_BLOCKED`, `TARGET_UNRESOLVABLE`, `TARGET_AMBIGUOUS`. Rate → `429`: `RATE_LIMITED`, `TARGET_RATE_LIMITED`, `TARGET_ABUSE_COOLDOWN`. |
| A target is allowed only if | **every** resolved address is public. One bad address = whole target denied (never "pick the good one"). |
| Hard caps (constants in `config/limits.js`, not env) | 256 targets/request · 1000 entries in a port list · port range span ≤ 5000 · ≤ 10 000 unique ports/scan · host ≤ 253 chars, label ≤ 63. |
| Private-target flag | `ALLOW_PRIVATE_TARGETS=true` allowed **only** when `NODE_ENV !== 'production'`. |
| Env booleans | Parse with an explicit `'true'|'false'` enum → boolean. **Never `z.coerce.boolean()`** (it turns `"false"` into `true`). |
| Redis failure | Rate limiters **fail open** (availability) with in-memory insurance + metric + log. Quota stays authoritative in Postgres. `/api/ready` reports Redis as `degraded`, not 503 (becomes hard-required in Phase 6 when the queue arrives). |
| Redis keys | No ioredis `keyPrefix`. All keys built by `redis/keys.js` as `cst:<area>:<name>:<id>`. |
| Metrics labels | Low-cardinality only. **Never** user ids, targets, IPs or raw URLs as labels. |
| `/metrics` | Bearer `METRICS_TOKEN`, constant-time compare; token unset → 404. Not under `/api`. |

Order inside every tool route (formalized in T4.23):
**auth → attachUser → zod → target policy → abuse cooldown → per-target limiter → submit limiter → quota → execute (pinned addresses only)**.

---

## 3. Target structure (end of Phase 4)

```
docker-compose.yml                  # + redis service
server/src/
  config/
    env.js                          # + Redis, private-flag, limiter, metrics vars
    limits.js                       # + hard caps constants
  redis/
    client.js  keys.js
  security/
    ipPolicy.js                     # classifyIp()
    hostPolicy.js                   # normalizeHost()
    resolve.js                      # resolveTarget(), pinnedLookup()
    targetPolicy.js                 # validateTarget(), validateTargets(), schemas
    ports.js                        # parsePorts()
    abuseGuard.js                   # blocked-attempt cooldown
    tokenBucket.js                  # outbound pacing (scan speed)
  middleware/
    rateLimit.js                    # createLimiter() factory (Redis + insurance)
    limiters.js                     # the concrete limiters wired into the app
  observability/
    metrics.js  eventLoop.js
  routes/
    metrics.js                      # GET /metrics
docs/
  tool-route-contract.md            # replaces quota-contract.md
tests/
  unit/   ip-policy  host-policy  resolve  target-policy  ports  token-bucket  metrics-labels
  api/    rate-limit  metrics  pipeline-order
```

---

## 4. Tasks

### Block A — Orientation, Redis, metrics registry

- [x] **T4.1 Orientation (read-only)**
  - Read `cybersec-toolkit/cybersec/core/security/policy.py` and `throttle.py` from the **old repo** if it is still cloned next to this project (`git clone --depth 1 https://github.com/Yash7256/cybersec-toolkit /tmp/old-cst` otherwise). Read §1 of THIS file.
  - Read OWASP-SSRF "Case 2 — application can send requests to any external IP address or domain name" and the "DNS pinning" paragraph.
  - Read `server/src/app.js` and `server/src/middleware/*` (names only + `head -n 40` of rateLimit usage).
  - Report: Node version (must support `net.BlockList`, `dns.promises`), and the Phase 1 limiter call site you will replace in T4.14.
  - No commit.

- [x] **T4.2 Redis service and env vars**
  - Add service `redis` (image `redis:7-alpine`, port `6379:6379`, command `redis-server --save "" --appendonly no`, healthcheck `redis-cli ping`) to `docker-compose.yml`. `docker compose up -d redis`.
  - Extend `env.js` (zod) — all new, with defaults:
    `REDIS_URL` (required; `redis://` or `rediss://`), `ALLOW_PRIVATE_TARGETS` (default false; **superRefine: if true and NODE_ENV==='production' → fail**), `METRICS_TOKEN` (optional, ≥ 24 chars), `DNS_TIMEOUT_MS` (3000), `USER_RATE_LIMIT_MAX` (300 / min), `SUBMIT_RATE_LIMIT_USER` (10 / min), `SUBMIT_RATE_LIMIT_IP` (30 / min), `AUTH_FAIL_MAX` (20), `AUTH_FAIL_WINDOW_SEC` (600), `AUTH_FAIL_BLOCK_SEC` (900), `TARGET_HOURLY_LIMIT_GLOBAL` (20), `TARGET_HOURLY_LIMIT_USER` (5), `BLOCKED_ATTEMPTS_MAX` (5), `BLOCKED_ATTEMPTS_WINDOW_SEC` (600), `BLOCKED_COOLDOWN_SEC` (900).
  - Update `.env.example`, `vitest.config.js` `test.env` (use `TEST_REDIS_URL=redis://localhost:6379/1`, a **separate DB index**), and `tests/env.test.js` (prod + `ALLOW_PRIVATE_TARGETS=true` throws; `"false"` string → boolean false).
  - Commit: `feat(infra): redis service and security env vars`

- [x] **T4.3 Install packages**
  - `npm i ioredis rate-limiter-flexible ipaddr.js prom-client --workspace server`. Verify with `npm ls --workspace server --depth=0 | tail -n 20`.
  - Commit: `chore(server): add redis, rate limiter, ip and metrics libs`

- [x] **T4.4 Redis client (`src/redis/client.js`, `keys.js`)**
  - **Read first:** IOREDIS README ("Auto-reconnect", "Offline queue", "Error handling").
  - Singleton ioredis: auto-connect, `enableOfflineQueue: false` (commands fail fast when down), `maxRetriesPerRequest: 1`, `connectTimeout: 3000`, `retryStrategy: n => Math.min(n * 200, 5000)`. **No `keyPrefix`.**
  - `waitForReady(timeoutMs = 5000)`: resolves `true`/`false` (never throws). Boot continues **degraded** if false.
  - `pingRedis({ timeoutMs = 1500 })`, `disconnectRedis()`. Log lifecycle events (`ready`, `error`, `reconnecting`) via pino — **never log the URL**.
  - `keys.js`: `key('rl', name, id)` → `cst:rl:<name>:<id>`; reject empty/oversized (> 200 chars) parts; sanitize `:` in ids.
  - Tests `tests/unit/redis.test.js`: against `TEST_REDIS_URL` → ping ok; against a closed port → commands reject **within 500 ms** (no hanging queue); `key()` format and sanitizing.
  - Test helper `flushTestRedis()` uses `FLUSHDB` but **aborts unless the URL ends with `/1`**.
  - Commit: `feat(infra): fail-fast redis client and key builder`

- [x] **T4.5 Metrics registry skeleton (`observability/metrics.js`)**
  - **Read first:** PROM-NAMING; PROM-CLIENT README "Default metrics", "Custom metrics".
  - Dedicated `Registry`; `collectDefaultMetrics({ register, prefix: 'cst_' })`.
  - Define (all prefixed `cst_`): counters `policy_blocked_total{reason}`, `rate_limit_rejected_total{limiter}`, `rate_limit_store_errors_total{limiter}`, `quota_rejected_total{tool}`, `webhook_events_total{outcome}`; histogram `http_request_duration_seconds{method,route,status_class}` (buckets 0.005…10 s). Export helper functions (`recordBlocked(reason)` …) so call sites never touch labels directly.
  - Allowed label values are enumerated in code; unknown values collapse to `"other"` (cardinality guard).
  - Commit: `feat(obs): metrics registry and counters`

### Block B — Target policy (security core)

- [x] **T4.6 `security/ipPolicy.js` — `classifyIp(input)`**
  - **Read first:** IANA-IPV4 and IANA-IPV6 special-purpose tables; IPADDR README ("range()", "process()", "isIPv4MappedAddress", "parse").
  - Returns `{ allowed: boolean, reason: string|null, normalized: string|null, family: 4|6|null }`. **Pure, sync, no I/O.**
  - Steps: reject non-strings / > 45 chars / any whitespace or `%` zone id (`fe80::1%eth0`) → `reason:'malformed'`. Parse with ipaddr.js. **Unwrap and re-check the embedded IPv4** for: IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`. Then deny by range.
  - Deny list — IPv4: `0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4` (covers 255.255.255.255).
    IPv6: `::/128, ::1/128, 64:ff9b:1::/48, 100::/64, 2001::/32 (Teredo), 2001:db8::/32, 2001:10::/28, 3fff::/20, fc00::/7 (covers fd00:ec2::), fe80::/10, fec0::/10, ff00::/8`.
  - Cross-check the list against both IANA tables; add anything *not globally reachable* that is missing; put the source URL + date in a header comment.
  - `reason` values (enum, used as metric label): `loopback private link_local cgnat metadata multicast reserved documentation unspecified translation malformed`.
  - Commit: `feat(security): classifyIp with unwrapping and IANA deny list`

- [x] **T4.7 `tests/unit/ip-policy.test.js` (table-driven, ≥ 80 cases)**
  - **Allowed:** `8.8.8.8, 1.1.1.1, 9.9.9.9, 172.15.255.255, 172.32.0.0, 100.63.255.255, 100.128.0.0, 193.0.0.1, 2606:4700:4700::1111, 2001:4860:4860::8888`.
  - **Blocked boundaries:** `10.0.0.0, 10.255.255.255, 172.16.0.0, 172.31.255.255, 100.64.0.0, 100.127.255.255, 192.168.0.1, 169.254.169.254, 0.0.0.0, 0.1.2.3, 127.0.0.1, 127.255.255.255, 224.0.0.1, 239.255.255.255, 240.0.0.1, 255.255.255.255, 198.18.0.1, 198.19.255.255, 192.0.2.1`.
  - **IPv6 blocked:** `::, ::1, fe80::1, fc00::1, fd00:ec2::254, ff02::1, 2001:db8::1, 2001::1 (Teredo)`.
  - **Bypass attempts (must all be blocked):** `::ffff:127.0.0.1`, `::ffff:7f00:1`, `::ffff:169.254.169.254`, `::ffff:10.0.0.1`, `::127.0.0.1`, `64:ff9b::7f00:1`, `64:ff9b::a00:1`, `2002:7f00:1::`, `2002:a9fe:a9fe::`, `0:0:0:0:0:ffff:7f00:1`.
  - **Malformed → `malformed`:** `''`, `' 8.8.8.8'`, `'8.8.8.8\n'`, `'fe80::1%eth0'`, `'1.2.3'`, `'256.1.1.1'`, `'1.2.3.4.5'`, a 300-char string, `null`, `123`.
  - Verify: `npm test --workspace server -- ip-policy --reporter=dot 2>&1 | tail -n 15` green. If any case fails, fix `ipPolicy.js`, never the test.
  - Commit: `test(security): ip policy table`

- [x] **T4.8 `security/hostPolicy.js` — `normalizeHost(input)`**
  - **Read first:** NODE-URL `domainToASCII`; OWASP-SSRF "URL parsing" notes.
  - Returns `{ kind: 'ip' | 'host', value }` or throws `AppError(422, code, msg)`. Pipeline, **in this order**:
    1. type/length (`≤ 253` after normalization) → `TARGET_INVALID`.
    2. trim; **reject** if it contains whitespace, control chars, `\0`, `@`, `/`, `\`, `?`, `#`, `://`, or a `:port` suffix (ports are a separate field) → `TARGET_INVALID`.
    3. Bracketed `[v6]` → strip brackets → IP path.
    4. Remove **one** trailing dot; lowercase; `url.domainToASCII()` (Unicode/fullwidth → ASCII; empty result → `TARGET_INVALID`).
    5. **After** normalization: if it is a canonical IP (`net.isIP`) → `{kind:'ip'}`.
    6. If it *looks numeric* but is not canonical (`2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`, `1.2.3`, hex/octal/decimal forms) → `TARGET_AMBIGUOUS`. Never hand these to the resolver (getaddrinfo would accept them).
    7. Hostname rules: labels 1–63 chars, `[a-z0-9-]`, no leading/trailing `-` (allow `_` only if you document why; default **no**); must contain ≥ 1 dot (reject single-label such as `intranet`); reject names `localhost` and suffixes `.localhost .local .internal .localdomain .lan .home.arpa .corp .intranet` → `TARGET_BLOCKED`.
  - Commit: `feat(security): host normalization and canonicalization`

- [x] **T4.9 `tests/unit/host-policy.test.js`**
  - Accept: `Example.COM` → `example.com`; `example.com.` → `example.com`; `xn--bcher-kva.example` ok; `8.8.8.8` → ip; `[2606:4700:4700::1111]` → ip; `münchen.de` → punycode.
  - Reject `TARGET_AMBIGUOUS`: `2130706433`, `0x7f000001`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`, `1.2.3`, `017700000001`.
  - Reject `TARGET_INVALID`: `user@evil.com`, `http://example.com`, `example.com/path`, `example.com:80`, `exa mple.com`, `example.com\n`, `exa\0mple.com`, `a..b.com`, `-bad.com`, `bad-.com`, a 64-char label, a 254-char host, `''`, `null`.
  - Reject `TARGET_BLOCKED`: `localhost`, `LOCALHOST.`, `foo.localhost`, `printer.local`, `db.internal`, `intranet` (single label), `x.home.arpa`.
  - **Unicode attack:** fullwidth `１２７.０.０.１` and `ⓛocalhost` must end up **blocked/ambiguous**, never allowed.
  - Commit: `test(security): host normalization table`

- [x] **T4.10 `security/resolve.js` — `resolveTarget` and `pinnedLookup`**
  - **Read first:** NODE-DNS (`lookup` with `all:true`, `verbatim:true`), NODE-NET (`lookup` option signature, including the `all` variant), OWASP-SSRF "DNS pinning".
  - `resolveTarget(value, { kind, timeoutMs, lookup = dns.promises.lookup })`:
    - `kind==='ip'` → `classifyIp`; blocked → `TARGET_BLOCKED`.
    - hostname → `lookup(host, { all:true, verbatim:true })` wrapped in a timeout (`Promise.race`, timer cleared). Errors `ENOTFOUND/EAI_AGAIN/ENODATA` → `TARGET_UNRESOLVABLE`; timeout → `TARGET_UNRESOLVABLE`.
    - Dedupe, **cap at 16 addresses**, run `classifyIp` on **all**; any blocked → `TARGET_BLOCKED` (reason recorded for metrics/audit, **not** in the message).
    - Returns `{ host, addresses: [{ address, family }] }` — already validated.
  - `pinnedLookup(addresses)` → a function with the **net.connect `lookup` signature** that **only ever answers from the validated list** (supports `options.all` and `options.family`), and never calls DNS. This is what Phase 5/7 tools pass to `net.connect`, `tls.connect` and the HTTP client.
  - Tests `tests/unit/resolve.test.js` (inject `lookup` stubs; no real DNS): public ok; **mixed public+private → blocked**; all private; CNAME-to-internal (stub returns `10.0.0.5`) → blocked; ENOTFOUND; timeout (fake timers, timer cleaned up); 40 addresses → capped at 16; **rebinding**: stub returns `1.2.3.4` the first call and `127.0.0.1` the second → `pinnedLookup` must still return only `1.2.3.4` and the stub must be called exactly once; error messages contain no IP.
  - Commit: `feat(security): single-shot resolution with validated pinning`

- [x] **T4.11 `security/targetPolicy.js` — the facade routes use**
  - `validateTarget(input, { env, resolver? })` → `{ target, targetKey, kind, addresses }`:
    `normalizeHost` → `resolveTarget` → `targetKey` = canonical lower-case host (or normalized IP) — this is what goes in `tool_runs.target_key`. `target` is the original string truncated to 255.
  - `allowPrivate`: honored only if `env.ALLOW_PRIVATE_TARGETS` (never from request input). When honored, still reject `0.0.0.0/8`, multicast, `240/4` and unspecified.
  - `validateTargets(list, { env, concurrency: 8 })`: `list.length ≤ 256`, dedupe by `targetKey`; IPv4 CIDR accepted **only** for prefixes `/24`–`/32` (≤ 256 addresses; every address classified); IPv6 CIDR → `TARGET_INVALID`; resolve with a small concurrency limiter (write a 15-line helper, no new dependency); the first failure aborts and reports **which index** failed (index only, no detail).
  - Zod: export `targetSchema` (string, trim, 1–260), `targetsSchema` (array 1–256), and `urlTargetSchema` for HTTP tools (scheme `http|https` only, no credentials in the URL, host goes through `normalizeHost`; returns `{ url, host, port }`). Export `validateRedirect(location, baseUrl)` that re-runs the full policy for each hop (Phase 5 limits redirects to 5, manual redirect mode).
  - Messages for every policy failure: **generic** (`"This target is not allowed."`, `"Target could not be resolved."`) + a stable `code`; the specific `reason` is returned separately to the caller as `err.reason` (internal, **not serialized** to the client).
  - Commit: `feat(security): target policy facade`

- [x] **T4.12 `tests/unit/target-policy.test.js`**
  - Public host (stub resolver) → ok, `targetKey` lower-cased; private flag **off** → `127.0.0.1` blocked; flag **on** (dev) → allowed but `0.0.0.0` still blocked; list of 257 → `TARGET_INVALID`; `/24` expands to 256 and a `/23` is rejected; IPv6 CIDR rejected; duplicates deduped; failure reports an index.
  - **No-leak test:** for 10 blocked inputs, `JSON.stringify(err)` and `err.message` contain neither a resolved IP nor a CIDR nor the word "private"/"internal".
  - URL schema: `ftp://x.com`, `http://user:pw@x.com`, `http://x.com@evil.com`, `http://[::1]/` → rejected; `https://example.com:8443/a?b=c` → ok.
  - Redirect: `Location: http://169.254.169.254/latest/meta-data/` from a public base → blocked.
  - Commit: `test(security): target policy facade`

- [x] **T4.13 `security/ports.js` — `parsePorts(input)` + `portsSchema`**
  - Accepts `"22,80,443,8000-8100"` or an array mixing numbers and `"a-b"` strings. Returns a **sorted unique** `number[]`.
  - Constants from `config/limits.js`: `MAX_PORT_LIST_ENTRIES=1000`, `MAX_PORT_RANGE_SPAN=5000` (`end - start + 1`), `MAX_PORTS_PER_SCAN=10000`.
  - **Check sizes before expanding:** compute each range's span and a running unique-count upper bound first; reject `1-65535` immediately without allocating.
  - Reject: `0`, `65536`, negatives, floats, `1e3`, hex, leading `+`, `08`-style leading zeros, empty segments (`22,,80`), reversed ranges (`100-50`), > limits; whitespace around items is tolerated.
  - Tests `tests/unit/ports.test.js`: valid forms; each rejection above; duplicates/overlaps collapse; `"1-5000"` ok, `"1-5001"` rejected; `"1-5000,5001-10000"` ok (exactly 10 000), `"1-5000,5001-10001"` rejected; 1000-entry list ok, 1001 rejected; a huge hostile input (`"1-65535"`) rejected in **< 5 ms**.
  - Commit: `feat(security): safe port spec parser`

### Block C — Rate limiting

- [x] **T4.14 `middleware/rateLimit.js` — `createLimiter()` and replace the Phase 1 limiter**
  - **Read first:** RLF wiki: "RateLimiterRedis", "insuranceLimiter", "blockDuration", "Express middleware".
  - `createLimiter({ name, points, durationSec, blockSec = 0, keyFn, skip })` → Express middleware:
    - Store: `RateLimiterRedis` using the Phase 4 client (explicit `keyPrefix: 'cst:rl:<name>'`), `insuranceLimiter: new RateLimiterMemory(same points/duration)`, `rejectIfRedisNotReady: true`.
    - On limit: set `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `Retry-After`; `next(new AppError(429, 'RATE_LIMITED', 'Too many requests', { retryAfterSec }))`; metric `rate_limit_rejected_total{limiter:name}`.
    - On **store error** (RLF rejects with an `Error`, not a `RateLimiterRes`): **fail open** — log once per 30 s, metric `rate_limit_store_errors_total`, call `next()`.
    - `keyFn(req)` returning falsy → skip (no key = no limit, e.g. unauthenticated route).
  - Remove `express-rate-limit` from `app.js`/`package.json` and migrate Phase 1's `tests/security.test.js` rate-limit test to the new middleware (same expectation: 4th request → 429 `RATE_LIMITED`).
  - Commit: `feat(security): redis-backed limiter factory replacing in-memory limiter`

- [x] **T4.15 `middleware/limiters.js` — the concrete limiters**
  | Name | Key | Limit | Where |
  |---|---|---|---|
  | `global_ip` | `req.ip` | `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` (Phase 1 env) | all `/api` |
  | `user_general` | `req.user.id` | `USER_RATE_LIMIT_MAX` / 60 s | after `attachUser` |
  | `submit_user` | `req.user.id` | `SUBMIT_RATE_LIMIT_USER` / 60 s | tool-submission routes |
  | `submit_ip` | `req.ip` | `SUBMIT_RATE_LIMIT_IP` / 60 s | tool-submission routes (multi-account abuse) |
  | `auth_fail` | `req.ip` | `AUTH_FAIL_MAX` per `AUTH_FAIL_WINDOW_SEC`, block `AUTH_FAIL_BLOCK_SEC` | **consumed only when `requireAuth` fails** (brute-force/credential-stuffing guard); checked *before* Clerk verification so blocked IPs cost nothing |
  | `webhooks_ip` | `req.ip` | 300 / 60 s | `/api/webhooks` (replaces Phase 3's temporary limiter) |
  - Export ready-to-mount middlewares (`submitLimiters = [submit_ip, submit_user]`). Update the Phase 3 mount order in `app.js` accordingly.
  - Commit: `feat(security): wire per-ip, per-user, submit, auth-failure and webhook limiters`

- [x] **T4.16 `security/abuseGuard.js` — victim protection**
  - `targetLimiter`: keys `tgt:global:<targetKey>` (`TARGET_HOURLY_LIMIT_GLOBAL`/h, shared by **all** users) and `tgt:user:<userId>:<targetKey>` (`TARGET_HOURLY_LIMIT_USER`/h). Exceeding either → `429 TARGET_RATE_LIMITED` (message: "This target has been scanned too often recently."). Runs **after** policy validation (it needs `targetKey`) and **before** quota, so being rate-limited never burns quota.
  - Blocked-attempt cooldown: `recordBlocked(userId)` increments a Redis counter (`BLOCKED_ATTEMPTS_WINDOW_SEC` TTL); at `BLOCKED_ATTEMPTS_MAX` it sets a cooldown key for `BLOCKED_COOLDOWN_SEC`. `assertNotCoolingDown(userId)` → `429 TARGET_ABUSE_COOLDOWN` with `Retry-After`. Runs at the **start** of the policy step.
  - On every policy rejection: `recordBlocked(...)`, metric `policy_blocked_total{reason}`, and `auditRepo.log({ action:'scan.blocked_target', actorId, ip, metadata:{ reason, tool, target:<first 255 chars> } })` (audit never throws).
  - Redis down → both fail **open** (log + metric).
  - Commit: `feat(security): per-target limiter and blocked-attempt cooldown`

- [x] **T4.17 Outbound limiter + token bucket**
  - `middleware`-independent utilities for **later phases** (NVD, GeoIP provider at ~55/min, scan pacing):
    - `security/outboundLimiter.js`: `createOutboundLimiter({ name, points, durationSec, maxWaitMs })` → `{ acquire(cost = 1) }` that **sleeps** until a Redis slot is free (shared across processes), throws `AppError(503, 'UPSTREAM_BUSY')` if the wait would exceed `maxWaitMs`; memory insurance on Redis failure.
    - `security/tokenBucket.js`: in-process `TokenBucket({ ratePerSec, burst })` with `async take(n = 1)` — a port of the old Python bucket's behavior (continuous refill, burst cap), used later to pace connect attempts. Use an injectable clock/`setTimeout` for tests; **no busy-wait**.
  - Tests `tests/unit/token-bucket.test.js` (fake timers): burst allowed then paced to the exact rate; never exceeds burst; `take(n > burst)` rejects with a clear error; concurrent `take` calls are served FIFO.
  - Commit: `feat(security): outbound limiter and token bucket`

- [x] **T4.18 `tests/api/rate-limit.test.js` (real Redis, db index 1)**
  - Limit enforced; `Retry-After` and `RateLimit-*` headers; two users don't share counters; **two limiter instances with the same name share one counter** (simulates two server processes).
  - `auth_fail`: 20 failed requests → next one blocked for the block duration **even with a valid token**; successful auth does not consume.
  - **Fail-open:** point the client at a dead Redis → request still succeeds, `rate_limit_store_errors_total` increments, and the in-memory insurance still caps abusive bursts.
  - Target limiter: 6th scan of the same target by one user → 429 `TARGET_RATE_LIMITED`; 21st by different users → 429; a rejected request leaves `usage_counters.used` unchanged.
  - Cooldown: 5 blocked targets within the window → 6th request (even to a valid target) → 429 `TARGET_ABUSE_COOLDOWN`; clears after TTL (use short test TTLs through env).
  - Commit: `test(security): rate limiting, abuse guard, fail-open`

### Block D — Metrics & event-loop health

- [x] **T4.19 HTTP metrics + `GET /metrics`**
  - Middleware (mounted first, after `requestId`): start timer; on `res.finish` observe `http_request_duration_seconds` with `route = req.route?.path ? (req.baseUrl + req.route.path) : 'unmatched'`, `status_class` = `2xx|3xx|4xx|5xx`. **Never use `req.path`/URL.** Skip `/metrics`.
  - `routes/metrics.js` mounted at `/metrics` (**not** under `/api`): requires `Authorization: Bearer <METRICS_TOKEN>`, compare with `crypto.timingSafeEqual` on equal-length SHA-256 digests; `METRICS_TOKEN` unset → `404`; wrong/missing → `401`. Response `Content-Type` = registry content type, `Cache-Control: no-store`. Own small limiter (30/min per IP).
  - DB pool gauges via `collect()` callbacks: `cst_db_pool_total`, `cst_db_pool_idle`, `cst_db_pool_waiting` (read from the `pg.Pool` used in Phase 2; expose it from `db/client.js` if needed).
  - Commit: `feat(obs): http metrics and protected metrics endpoint`

- [x] **T4.20 Event-loop monitor (`observability/eventLoop.js`)**
  - `perf_hooks.monitorEventLoopDelay({ resolution: 20 })`; every 5 s read `p99`, update gauge `cst_eventloop_lag_p99_seconds`, `histogram.reset()`; log `warn` when p99 > 200 ms (log at most once per minute). `unref()` the interval; `disable()` in a shutdown hook.
  - Commit: `feat(obs): event loop lag monitor`

- [x] **T4.21 `tests/api/metrics.test.js` + `tests/unit/metrics-labels.test.js`**
  - `/metrics`: 404 with no token configured; 401 wrong token; 401 missing; 200 right token containing `cst_http_request_duration_seconds` and `cst_nodejs_` default metrics; endpoint is **not** reachable via `/api/metrics`.
  - **Cardinality guard:** send 300 requests to random unknown URLs and 50 distinct user ids → the set of `route` label values grows by at most 1 (`unmatched`); no metric line contains a user id, an IP address or a target string.
  - Unknown counter label value → recorded as `other`.
  - Commit: `test(obs): metrics endpoint and label cardinality`

### Block E — Readiness, contract, pipeline, review

- [x] **T4.22 Readiness and shutdown**
  - Add a Redis check to the Phase 2 readiness registry: Redis down → **HTTP 200** with `status:'degraded'`, `checks:{ db:'ok', redis:'fail' }`; DB down → 503 as before. Add `disconnectRedis` and the event-loop monitor `disable` to `shutdownHooks`; at boot call `waitForReady(5000)` and log `redis degraded` if it returns false (do not crash).
  - Test: stop Redis container → `/api/health` 200, `/api/ready` 200 `degraded`; start it → `ok` again without restart.
  - Commit: `feat(server): redis readiness (degraded mode) and shutdown hooks`

- [x] **T4.23 `docs/tool-route-contract.md` (replaces `quota-contract.md`; ≤ 70 lines)**
  - The mandatory pipeline: **`requireAuth → attachUser → submit limiters → zod → assertNotCoolingDown → validateTarget(s) → targetLimiter → enforceQuota → execute`** (note: submit limiters run before zod to cap cheap abuse; validation never consumes quota).
  - Rules for tool authors: connect **only** via `pinnedLookup(addresses)`; never call `dns.lookup`/`fetch(url)` on user input; manual redirects with `validateRedirect` (max 5); never put resolved IPs, internal errors or stack traces in responses; use `refundQuota` only for failures before execution; metric/audit expectations; a 12-line example route.
  - `git rm docs/quota-contract.md` and fix any reference to it.
  - Commit: `docs: tool route contract`

- [x] **T4.24 `tests/api/pipeline-order.test.js` (throwaway test-only route)**
  - Register `POST /__t/scan` in the test file only, mounting the full chain from T4.23 with stubbed DNS.
  - Assertions (check `usage_counters.used` after each): zod failure → 400, **used = 0**; blocked target → 422, used = 0, audit row + metric present; target rate-limited → 429, used = 0; quota exhausted → 429 `QUOTA_EXCEEDED`; success → 200 and used = 1; handler receives only validated `addresses`; response body of every failure contains no IP/CIDR text; unauthenticated → 401 before any policy work (spy that `resolveTarget` was not called).
  - Commit: `test(security): end-to-end pipeline ordering`

- [x] **T4.25 Security review (checklist — report each finding, fix, re-test)**
  - `grep -rn "dns\.\(lookup\|resolve\)\|net\.connect\|fetch(" server/src | grep -v security/` → every hit must be a **documented** use of pinned addresses or a call to a fixed trusted host; list them.
  - Confirm `ALLOW_PRIVATE_TARGETS` is read **only** from validated `env` (never `req`), and production boot fails when it is true (run `NODE_ENV=production ALLOW_PRIVATE_TARGETS=true node src/server.js` → exit 1, readable message).
  - Confirm no `z.coerce.boolean()` anywhere (`grep -rn "coerce.boolean" server/src`).
  - Confirm pino redaction still covers `authorization`, `cookie`, `svix-signature` and that no log line prints `REDIS_URL` or `METRICS_TOKEN`.
  - Confirm every 4xx/5xx error body matches `{ error:{ code, message, requestId } }` and carries no resolved IPs.
  - Mutation spot-checks (revert after each): remove the IPv4-mapped unwrap → T4.7 must fail; make `pinnedLookup` call DNS → T4.10 must fail; drop the "all addresses" rule → T4.10 must fail. Report that each mutation was caught.
  - Commit only if fixes were needed: `fix(security): review findings`

- [x] **T4.26 Final verification**
  - `docker compose up -d db redis`; run unit, DB and API test suites (report counts); `npm run dev:server`.
  - Manual: `curl -s localhost:3001/api/health`; `curl -s localhost:3001/api/ready`; `curl -si localhost:3001/metrics` → 404 (token unset); with `METRICS_TOKEN` set in `.env` and a Bearer header → 200 text exposition.
  - Kill Redis → service keeps answering, `/api/ready` = `degraded`, limiter metric `cst_rate_limit_store_errors_total` > 0.
  - `git log --oneline | head -n 30`; `tree server/src -L 2`.

---

## 5. Definition of Done (Phase 4)

- [x] 26 tasks ticked, one commit each; no secrets committed or logged.
- [x] IP policy table (≥ 80 cases) and host policy table pass; every known SSRF bypass in §T4.7/T4.9 is blocked.
- [x] DNS is resolved **once**; tools can only connect through `pinnedLookup`; the rebinding test proves a second answer is never used.
- [x] Policy errors are generic and never reveal resolved IPs/CIDRs.
- [x] Production refuses to boot with `ALLOW_PRIVATE_TARGETS=true`.
- [x] Limiters are Redis-shared, per-user and per-IP, fail open with in-memory insurance; brute-force auth guard and per-target victim protection work.
- [x] Invalid / blocked / rate-limited requests never consume daily quota (pipeline test).
- [x] `/metrics` is token-protected, low-cardinality, and not exposed under `/api`.
- [x] Redis outage degrades gracefully (200 `degraded`), DB outage is 503.
- [x] Zero Python; `client/` untouched.

**When finished, report:** test counts, the three mutation-test results, any IANA range you added beyond the list in T4.6, and anything you deviated on. Then wait for the Phase 5 file (the simple tools: DNS, WHOIS/RDAP, SSL, HTTP headers, GeoIP, ping — each following `docs/tool-route-contract.md`).
