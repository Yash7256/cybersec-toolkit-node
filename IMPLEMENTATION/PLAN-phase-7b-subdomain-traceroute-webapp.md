# PHASE 7B — Subdomain Discovery, Traceroute, Web-App Scanner

> **For OpenCode.** Prerequisites: Phases 1–6 and **7A** finished (all boxes ticked; all prior suites green).
> Companions: `DATABASE-DESIGN.md`, `docs/tool-route-contract.md`, `docs/queue-architecture.md`, `docs/api-tools.md`, `docs/scanner-design.md` (7A).
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`.**
> **No Python in the project.** Old Python code is read-only reference at `/tmp/old-cst` (`git clone --depth 1 https://github.com/Yash7256/cybersec-toolkit /tmp/old-cst`).
> This closes out Phase 7: after this, every tool from the old project exists except raw-packet scans, OS fingerprinting and screenshots (screenshots → Phase 8).

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]`, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. Never read a whole old file. Use `grep -n` then `sed -n 'A,Bp' | cut -c1-140` for the one function the task names.
3. Pipe long output through `tail -n 20`; run tests with `--reporter=dot`.
4. One commit per task. If verification fails twice → stop and report the exact error.
5. **Legal/ethical guard is load-bearing in this file, not decoration.** The web-app scanner sends real attack payloads. Every task that touches it must keep the authorization gate exactly where specified — do not "simplify" it away.
6. Everything fetched from the network (subdomain probes, traceroute output, web pages) is hostile input: bound size, bound time, sanitize before storing or rendering.
7. Never print secrets.

### 0.1 Reference registry

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina   # node/rules/{async-patterns,performance,testing}.md
```

| Short name | URL |
|---|---|
| NODE-DNS | https://nodejs.org/docs/latest/api/dns.html |
| NODE-CHILD | https://nodejs.org/docs/latest/api/child_process.html |
| UNDICI | https://undici.nodejs.org |
| OWASP-TESTING | https://owasp.org/www-project-web-security-testing-guide/ (index only — read the SQLi/XSS/SSTI/path-traversal/CSRF chapter summaries, not the whole guide) |
| OWASP-SSRF | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html |
| DMARC-RFC | https://www.rfc-editor.org/rfc/rfc7489 |
| SPF-RFC | https://www.rfc-editor.org/rfc/rfc7208 |

---

## 1. Fixed design decisions

### 1.1 Subdomain discovery
- **Does not touch the target directly for DNS** — resolves via the Phase 5 DoH client (public resolvers), never the system resolver (keeps the Phase 4/5 "no raw DNS" rule).
- `touchesTarget:false` for the DNS phase (DoH, not the target); the **HTTP probe phase touches real hosts**, so each discovered hostname is re-validated through `validateTarget` immediately before probing — a subdomain resolving to a private/metadata IP is **never probed** (ported from the old `_is_safe_public_ip` all-IPs-must-be-public rule, done through the shared policy instead of a duplicate check).
- Wordlists ported verbatim (small/medium/large, counts preserved). Async job (Phase 6); progress = DNS phase 0–60 %, HTTP phase 60–100 %.
- Screenshots: field present, `null`, note `"Screenshots are not enabled yet"` (→ Phase 8).

### 1.2 Traceroute
- Old code shelled out to the system `traceroute`/`tracert` binary. **Kept**, because a Node ICMP implementation needs raw sockets (root) anyway — same constraint the old code had. Ported safety rules, all strengthened:
  - Resolve once, validate **all** addresses (Phase 4 policy), connect `traceroute` to the **IP literal only**, never the hostname.
  - `execFile` (never shell), fixed flag list, `--` separator, validated IP as the only variable argument (directly ports the old argument-injection defense, now via `execFile` instead of `create_subprocess_exec` with an args array — same safety property).
  - Binary availability checked once at boot (same pattern as Phase 5 ping); missing binary → tool reports `UPSTREAM_ERROR`/unavailable rather than crashing.
- `touchesTarget:true`; async (Phase 6) because a 30-hop trace with GeoIP enrichment can run 10–40 s.
- Hop GeoIP/reverse-DNS reuse the Phase 5 GeoIP service function and public DNS — no new provider code.

### 1.3 Web-app scanner (highest risk — read this twice)
- **The old code's `confirm_authorized: bool` field is the entire legal gate and it is trivially bypassable** (the API trusted a client-supplied boolean). The new design keeps the explicit confirmation **and adds a server-side ownership record**, because a checkbox a client can set to `true` by default is not a real control:
  - New request field `confirm_authorized: true` is still **required** (schema rejects `false`/missing with `AUTH_GATE_REQUIRED` and the old message text).
  - **New:** before the first active (payload-sending) scan of a `targetKey`, the user must have an **approved `TargetAuthorization`** row (new table, T7B.19) for that `targetKey`'s registrable domain — self-service for now (user attests, rate-limited, logged, revocable), not a rubber stamp removed. `confirm_authorized:true` without a matching authorization creates one (attested) and proceeds; this mirrors the old UX (one checkbox) while leaving an audit trail and a revocation point for Phase 9+ (e.g. admin review, or domain-verification such as a DNS TXT record) without reworking the API again.
  - **Passive-only mode** (`active:false`): crawl + headers + TLS + exposed files + robots + DNS/email security + directory listing — **no payload is ever sent**, so it runs **without** authorization, like the old passive checks implicitly did.
  - Every payload-sending request goes through `safeHttp` with the full Phase 4/5 pinning/redirect rules — **SSRF-in-forms is closed**: the old code's `_resolve_ip`/`allow_private` checks are replaced by the shared policy, applied to the crawl and to every form `action` URL (including one found mid-crawl that points at a different host — re-validated, not assumed safe because the base URL was).
  - Payloads are the exact old lists (SQLi/XSS/SSTI/path-traversal) — kept conservative/non-destructive like the original (no stacked queries, no OOB callbacks, no file writes); this is a safety floor, not a coverage ceiling.
  - `max_pages` 1–100 (unchanged); crawl same-origin only (ported `_base_domain`); `touchesTarget:true`; async; **own stricter rate limit**: `WEBAPP_SCAN_USER_LIMIT_PER_DAY` separate counter (default 10/day) layered **on top of** (not instead of) the normal tool quota, because payload traffic is heavier than a passive check.

### 1.4 Shared error/outcome rules
Same as Phase 5/7A: `target` kind → `COMPLETED` + friendly `error`; `upstream`/`internal`/timeout → `FAILED`/`TIMED_OUT` + refund. New vocabulary entries: `"Authorization required for active testing"` (422 `AUTH_GATE_REQUIRED`, not consumed), `"Traceroute is not available on this server"`.

---

## 2. Target structure (end of 7B)

```
server/src/
  tools/
    subdomain/  index.js schema.js wordlists/{small,medium,large}.js
                wildcard.js risk.js confidence.js resolve.js probe.js contract.js
    traceroute/ index.js schema.js runner.js parser.js enrich.js intelligence.js contract.js
    webapp/
      index.js schema.js contract.js
      crawl.js fingerprint.js
      checks/ tls.js headers.js methods.js cors.js exposedFiles.js adminPanels.js
              dirListing.js openRedirect.js sqli.js xss.js csrf.js ssti.js
              pathTraversal.js dnsEmail.js robots.js
      payloads.js
  db/repos/targetAuthRepo.js
  routes/authorizations.js
docs/webapp-scanner-safety.md
tests/
  unit/ subdomain-*  traceroute-*  webapp-*
  integration/ subdomain-e2e  traceroute-e2e  webapp-e2e  webapp-authorization  webapp-ssrf
  helpers/ webServer.js (a deliberately vulnerable local test app), dnsStub.js
```

---

## 3. Old-code map

| Port to | Old source (lines, in `cybersec/core/tools/` unless noted) |
|---|---|
| `subdomain/wordlists/*` | `data/wordlists/{small,medium,large}.txt` |
| `subdomain/wildcard.js` | `subdomain.py` `_generate_random_prefix`, `_detect_wildcard` (165–238) |
| `subdomain/risk.js` | `classify_subdomain_risk` + `RISK_KEYWORDS` (104–123, 240–280) |
| `subdomain/confidence.js` | `compute_confidence` (281–336) |
| `subdomain/resolve.js` | `resolve_subdomain_records`, `RECORD_TYPES/EXTRACTORS` (41–51, 337–412) |
| `subdomain/probe.js` | `probe_subdomain_http`, `_extract_title`, `_detect_technologies`, `TECH_*_PATTERNS` (76–103, 413–452) |
| `subdomain/index.js` | `find_subdomains` (520–651), `_is_safe_public_ip` (21–39) |
| `traceroute/parser.js` | `traceroute()` parsing passes (`traceroute.py` ≈ 413–465) |
| `traceroute/enrich.js` | `_quality_for_latency`, `_private_ip`, `_reverse_dns`, `_geoip_for_hop`, `_detect_provider`, `_empty_hop`, `_enrich_hop`, `_apply_geoip_to_hops` (73–277) |
| `traceroute/intelligence.js` | `_build_route_intelligence` (278–394) |
| `traceroute/runner.js` | subprocess section (395–412, 465–498) |
| `webapp/crawl.js` | `crawl`, `_resolve_ip`, `_safe_get`, `_abs`, `_base_domain` (97–211) |
| `webapp/fingerprint.js` | `fingerprint`, `_FINGERPRINTS` (130–150, 551–600) |
| `webapp/checks/tls.js` | `check_tls` (212–281) |
| `webapp/checks/headers.js` | `check_headers`, `SECURITY_HEADERS` (151–156, 282–368) |
| `webapp/checks/methods.js` | `check_http_methods` (369–405) |
| `webapp/checks/cors.js` | `check_cors` (406–449) |
| `webapp/checks/exposedFiles.js` | `check_exposed_files`, `SENSITIVE_FILES` (84–100, 450–476) |
| `webapp/checks/adminPanels.js` | `check_admin_panels`, `ADMIN_PATHS` (101–111, 477–510) |
| `webapp/checks/dirListing.js` | `check_directory_listing` (511–529) |
| `webapp/checks/openRedirect.js` | `check_open_redirect` (530–550) |
| `webapp/checks/sqli.js` | `check_sqli`, `SQLI_PAYLOADS`, `SQL_ERRORS` (112–125, 601–630) |
| `webapp/checks/xss.js` | `check_xss`, `XSS_PAYLOADS` (113–114, 631–680) |
| `webapp/checks/csrf.js` | `check_csrf` (680–695) |
| `webapp/checks/ssti.js` | `check_ssti`, `SSTI_PAYLOADS` (115, 695–718) |
| `webapp/checks/pathTraversal.js` | `check_path_traversal`, `TRAVERSAL_PAYLOADS` (116–117, 718–742) |
| `webapp/checks/dnsEmail.js` | `check_dns_email_security` (742–804) |
| `webapp/checks/robots.js` | `check_robots` (804–832) |
| `webapp/index.js` | `_build_result`, `scan` (832–935ish — read in 2 chunks) |

---

## 4. Tasks

### Block A — Subdomain discovery

- [ ] **T7B.1 Orientation**
  - Read §1.1, §3 (subdomain rows). Confirm Phase 5 `net/dohClient.js`, `tools/geoip` and the Phase 4 `validateTarget`/`classifyIp` exports exist and their signatures. No commit.

- [ ] **T7B.2 Wordlists + env vars**
  - Port the three `.txt` files verbatim to `wordlists/{small,medium,large}.js` (one entry per line, trimmed, lower-cased, de-duplicated; export as a frozen array). Verify counts: small 54, medium 227, large 930 **minus** blank/comment lines in the source — report the exact counts you get and compare to `wc -l`.
  - Env: `SUBDOMAIN_DNS_CONCURRENCY` (10), `SUBDOMAIN_DNS_TIMEOUT_MS` (5000), `SUBDOMAIN_DNS_MAX_RETRIES` (2), `SUBDOMAIN_HTTP_TIMEOUT_MS` (8000), `SUBDOMAIN_HTTP_CONCURRENCY` (20), `SUBDOMAIN_WILDCARD_CHECKS` (3), `SUBDOMAIN_MAX_WORDLIST` (large list length, computed, not hardcoded).
  - Commit: `feat(subdomain): wordlists and env vars`

- [ ] **T7B.3 `subdomain/wildcard.js` + `subdomain/risk.js`**
  - Port `_detect_wildcard` (random 8-char prefix × `SUBDOMAIN_WILDCARD_CHECKS`, via `dohClient` not a raw resolver) and `classify_subdomain_risk` + `RISK_KEYWORDS` table.
  - Tests: wildcard present/absent (stub DoH), risk classification table (≥ 12 cases from the Python branches: keyword match, 401/403/407, 5xx, title keywords, redirect, 404, tech-only, plain 2xx, no http).
  - Commit: `feat(subdomain): wildcard detection and risk classification`

- [ ] **T7B.4 `subdomain/confidence.js` + `subdomain/resolve.js`**
  - Port `compute_confidence` (exact score arithmetic and the wildcard-dampening `*0.3` rule) and `resolve_subdomain_records` (A/AAAA/CNAME/MX/TXT/NS via `dohClient`, `SUBDOMAIN_DNS_MAX_RETRIES` retries with backoff, concurrency via a semaphore of `SUBDOMAIN_DNS_CONCURRENCY`).
  - Tests: confidence score table (≥ 10 cases matching the Python arithmetic exactly, including the wildcard dampening and the `min(score,0.2)` wildcard cap); resolve: NXDOMAIN, NODATA, timeout-then-success, all-types-empty, first-A captured.
  - Commit: `feat(subdomain): confidence scoring and DNS resolution`

- [ ] **T7B.5 `subdomain/probe.js`**
  - Port `probe_subdomain_http` (https-then-http fallback, title extraction regex, `_detect_technologies` + header/cookie/body patterns) using `net/safeHttp.js` (Phase 5) **in user mode** — this is where the re-validation from §1.1 happens, since `safeHttp` already pins.
  - Tests: alive https, falls back to http, title extraction (incl. CDATA-wrapped), tech detection from headers/cookies/body, connect error → `alive:false`, private-IP resolution → probe skipped with the old `skipped_reason` string.
  - Commit: `feat(subdomain): http probe with ssrf-safe http client`

- [ ] **T7B.6 `subdomain/index.js` + schema + route**
  - Request `{ target (domain, ≤253, no whitespace, not an IP), wordlist: 'small'|'medium'|'large', strictness: 'off'|'low'|'medium'|'high' }`. `mode:'async'`, `touchesTarget:false` for the tool-route gate (DNS-only), summary `{ totalFound, wildcardDetected }`.
  - Orchestration mirrors `find_subdomains`: wildcard detection (unless `off`) → DNS phase (bounded concurrency, progress to 60%) → wildcard filtering (`medium`/`high` drop matches) → HTTP phase for resolved, re-validated-public entries only (progress 60→100) → risk + confidence → assemble `SubdomainResult` (contract.js keys) with `screenshot:null` fields.
  - Commit: `feat(tools): subdomain discovery orchestrator`

- [ ] **T7B.7 `tests/integration/subdomain-e2e.test.js`**
  - Stub DoH resolver with a fixture map (some subdomains resolve, some NXDOMAIN, one wildcard IP, one resolving to a private IP). Local web server for the HTTP phase. Assert: wildcard-matching entries excluded at `medium`/`high`, included (flagged) at `low`, untouched at `off`; private-IP entry never HTTP-probed (assert via a call-count spy) and marked with the skip reason; progress monotonic; result keys match contract; quota 1 unit; async submit/poll works (Phase 6); 6th call/day → 429.
  - Commit: `test(subdomain): end-to-end discovery`

### Block B — Traceroute

- [ ] **T7B.8 Orientation + availability check**
  - Confirm `traceroute`/`tracert` exists (`command -v traceroute`). Read §1.2, §3 (traceroute rows), and Phase 5 `tools/ping/icmp.js` (reuse its boot-time binary-check pattern).
  - Env: `TRACEROUTE_MAX_HOPS` (30, cap 64), `TRACEROUTE_TIMEOUT_SEC` (30), `TRACEROUTE_GEOIP_CONCURRENCY` (5).
  - No commit (env var task folds into T7B.9).

- [ ] **T7B.9 `traceroute/runner.js`**
  - **Read first:** NODE-CHILD (`execFile`, `timeout`, `killSignal`).
  - `run({ ip, maxHops, signal })`: platform branch (`win32` → `tracert -h N -d <ip>`; else → `traceroute -m N -n -- <ip>`), `execFile` (no shell), `env:{LC_ALL:'C',PATH:'/usr/bin:/bin'}` (POSIX) or system default on Windows, hard timeout `TRACEROUTE_TIMEOUT_SEC`, `maxBuffer` 256 KB. `ip` is the single variable argument and is always the validated literal.
  - Add to the network allow-list (reason: "execFile to system traceroute binary with a validated IP literal").
  - Tests: happy path against a fixture, timeout → kills the process and resolves with a timeout marker, binary missing → clean `upstream` error (stub `execFile` to reject `ENOENT`), argument-injection test (a crafted "IP-shaped" string can't inject flags — assert the args array, not a shell string).
  - Commit: `feat(tools): traceroute process runner`

- [ ] **T7B.10 `traceroute/parser.js`**
  - Port both parsing passes (POSIX `* * *` / IP+ms lines; Windows `tracert` lines) **exactly**, including the regexes for extracting ms samples and the private-vs-public IP note.
  - Table tests with real-shaped fixture output (one POSIX multi-hop with a `* * *` gap, one Windows fixture, one all-timeout trace, one single-hop reaching the destination, malformed junk lines ignored).
  - Commit: `feat(tools): traceroute output parser`

- [ ] **T7B.11 `traceroute/enrich.js`**
  - Port `_quality_for_latency`, `_private_ip` (reuse Phase 4 `classifyIp` instead of re-implementing), `_reverse_dns` (public DNS, bounded timeout), `_geoip_for_hop` (call the Phase 5 GeoIP service function directly — **no extra quota**, cache-first), `_detect_provider` + `_CDN_PATTERNS`, `_empty_hop`, `_enrich_hop` (packet-loss %, latency-added, insight text).
  - Tests: quality bands at each threshold, private-hop detection via the shared policy, provider detection table (Cloudflare/Akamai/Fastly/CloudFront/Google/Azure/private/ISP/unknown), empty-hop shape, enrich with 0/1/3 samples.
  - Commit: `feat(tools): traceroute hop enrichment`

- [ ] **T7B.12 `traceroute/intelligence.js`**
  - Port `_build_route_intelligence` (stability score, efficiency, health indicators, AS path, ownership chain, bottlenecks, hidden/loss hop counts, international-route flag, CDN summary, route risk + factors, routing intelligence, security insights). Read in 2 chunks (278–335, 335–394).
  - **Golden tests**: 3 fixed hop lists (clean international CDN route, route with 2 hidden hops + packet loss, route ending at a private IP mid-trace) → exact output traced from the Python branches.
  - Commit: `feat(tools): traceroute route intelligence`

- [ ] **T7B.13 `traceroute/index.js` + schema + route**
  - Request `{ target, max_hops: 1-64 default 30 }`. `touchesTarget:true`, `mode:'async'`, `dedupeTtlSec:60`, summary `{ totalHops, destinationReached, routeRisk }`.
  - Resolve+validate (Phase 4, re-validated at execution per Phase 6) → `runner.run` → `parser.parse` → `enrich` each hop (bounded concurrency `TRACEROUTE_GEOIP_CONCURRENCY`) → `intelligence.build` → assemble with exact old field names (`ai_summary:null`, note "not enabled yet").
  - `ai_summary`/`security_insights` enrichment stays (pure, ported); only the **AI-generated** summary field is deferred to Phase 8.
  - Commit: `feat(tools): traceroute orchestrator`

- [ ] **T7B.14 `tests/integration/traceroute-e2e.test.js`**
  - Stub `runner.run` with fixture process output (can't run a real traceroute to the internet in CI). Full pipeline through enrich + intelligence; async submit/poll; cancel mid-run; binary-unavailable path → clean error, quota refunded; private target blocked before any subprocess spawn (spy `execFile` call count = 0).
  - Commit: `test(tools): traceroute end-to-end`

### Block C — Web-app scanner: authorization, crawl, passive checks

- [ ] **T7B.15 Orientation (read twice)**
  - Read §1.3 fully. Read `webapp_scanner.py` lines 97–211 (`crawl`/`_safe_get`/`_resolve_ip`) and 832–935ish (`_build_result`, `scan`) in two `sed` calls. Read Phase 5 `net/safeHttp.js` exports and Phase 4 `security/targetPolicy.js` `validateRedirect`.
  - No commit.

- [ ] **T7B.16 Payload data (`webapp/payloads.js`)**
  - Port `SQLI_PAYLOADS`, `XSS_PAYLOADS`, `SSTI_PAYLOADS`, `TRAVERSAL_PAYLOADS`, `SQL_ERRORS`, `SENSITIVE_FILES`, `ADMIN_PATHS`, `SECURITY_HEADERS`, `_FINGERPRINTS` verbatim as plain data exports. No logic.
  - Test: counts match what you counted in the Python source (state counts in commit body).
  - Commit: `feat(webapp): payload and signature data`

- [ ] **T7B.17 Env vars + schema**
  - Env: `WEBAPP_SCAN_MAX_PAGES` (100, request-level cap, old default 20), `WEBAPP_SCAN_TIMEOUT_SEC` (10, per-request), `WEBAPP_SCAN_TOTAL_TIMEOUT_SEC` (180), `WEBAPP_SCAN_USER_LIMIT_PER_DAY` (10), `WEBAPP_SCAN_CRAWL_CONCURRENCY` (5), `WEBAPP_AUTH_ATTESTATION_COOLDOWN_SEC` (60, anti-spam on the authorization endpoint).
  - `tools/webapp/schema.js`: `{ target, max_pages: 1-100 default 20, active: boolean default true, confirm_authorized: boolean required when active }`. `active:false` → `confirm_authorized` not required (schema-conditional).
  - Commit: `feat(webapp): env vars and request schema`

- [ ] **T7B.18 `webapp/crawl.js`**
  - Port `crawl`, `_base_domain`, `_abs`, `_safe_get` using `net/safeHttp.js` **user mode** (so every request — including same-page follow-ups the old code made manually — gets Phase 4/5 pinning and redirect re-validation; this closes the old per-call `allow_private` parameter entirely). Same-origin queue, `max_pages` cap, form extraction (`action` resolved absolute + re-validated against the *crawled page's* origin before it's ever queued for a check — closes the old "trust the base URL's validation" gap for off-host form actions), body snippet (4 KB) for fingerprinting, link extraction.
  - Tests: same-origin crawl respects `max_pages`; off-site links not followed; a form whose `action` points at a different, private host is excluded (never reaches any check module) and this is asserted by call-count, not just by output; a form action pointing at a different **public** host is included but **separately re-validated**, asserted via the `safeHttp` resolver spy.
  - Commit: `feat(webapp): ssrf-safe crawler`

- [ ] **T7B.19 Target authorization (`db/repos/targetAuthRepo.js`, Prisma model, route)**
  - **Read first:** `DATABASE-DESIGN.md` §1 principles (deny-by-default RLS pattern) to match style.
  - New model `TargetAuthorization { id uuid pk, userId uuid, registrableDomain varchar(253), method enum ATTESTATION, status enum APPROVED|REVOKED, createdAt, revokedAt? }` with `@@unique([userId, registrableDomain])`, migration (`run migrate dev`), RLS enabled no policies (consistent with `DATABASE-DESIGN.md` §5).
  - `repo`: `getActive(userId, registrableDomain)`, `attest(userId, registrableDomain)` (upsert APPROVED, rate-limited by `WEBAPP_AUTH_ATTESTATION_COOLDOWN_SEC` via Redis key, audit `target.authorized`), `revoke(userId, registrableDomain)` (audit `target.authorization_revoked`).
  - `routes/authorizations.js`: `GET /api/authorizations` (list mine), `POST /api/authorizations` `{domain}` → attest, `DELETE /api/authorizations/:domain` → revoke. All behind `requireAuth`.
  - Tests (DB + API): attest creates/reactivates a revoked row; cooldown blocks rapid re-attestation; revoke blocks future active scans immediately; another user's authorizations are invisible.
  - Commit: `feat(db,server): target authorization records`

- [ ] **T7B.20 Passive checks part 1: `tls.js`, `headers.js`, `methods.js`, `cors.js`**
  - Port `check_tls` (reuse Phase 5 `tools/ssl` audit function, don't reimplement), `check_headers` + `SECURITY_HEADERS` table, `check_http_methods` (`OPTIONS`/`Allow` parsing — reuse the Phase 5 HTTP-headers `Allow` logic if it already exists; otherwise port fresh), `check_cors` (reflected-origin + credentials test, **using the crawler's own request**, never a second attacker-controlled probe).
  - Table tests per function from the Python branches (≥ 5 each).
  - Commit: `feat(webapp): tls, headers, methods, cors checks`

- [ ] **T7B.21 Passive checks part 2: `exposedFiles.js`, `adminPanels.js`, `dirListing.js`, `robots.js`**
  - Port `check_exposed_files` (concurrency-bounded probing of `SENSITIVE_FILES`), `check_admin_panels` (`ADMIN_PATHS`), `check_directory_listing` (pattern match on crawled pages' bodies — no extra requests), `check_robots` (fetch `/robots.txt`, flag `Disallow` entries that look sensitive, per the old logic).
  - Tests against a local fixture server exposing a subset of these paths; false positives avoided (e.g. a custom 200 "not found" page must not trigger every path as a finding — port whatever distinguishing logic the Python code used, or note if it didn't have one and add a minimal status/length heuristic, documented in the commit).
  - Commit: `feat(webapp): exposed files, admin panels, directory listing, robots checks`

- [ ] **T7B.22 `fingerprint.js` + `dnsEmail.js`**
  - Port `fingerprint` (`_FINGERPRINTS` regex table over headers/cookies/body) and `check_dns_email_security` (SPF/DMARC/DKIM presence via the Phase 5 DNS tool's TXT lookup — reuse, don't re-implement DNS). Read DMARC-RFC/SPF-RFC only enough to sanity-check the parsing (`v=spf1`, `v=DMARC1; p=`).
  - Tests: CMS/framework/library detection table; SPF missing/present/`~all`/`-all`; DMARC missing/`p=none`/`p=reject`; combined severity per the old branches.
  - Commit: `feat(webapp): fingerprinting and email security checks`

### Block D — Active checks (payload-sending; gated)

- [ ] **T7B.23 `openRedirect.js` + `csrf.js`**
  - Port `check_open_redirect` (param-based redirect probe to a **fixed external sentinel domain**, not attacker/user-controlled — verify the old code's target and keep it fixed) and `check_csrf` (form inspection for anti-CSRF tokens — **no network call**, so this one is safe even in passive mode; confirm from the Python whether it's gated and match that).
  - Tests per the Python branches.
  - Commit: `feat(webapp): open redirect and csrf checks`

- [ ] **T7B.24 `sqli.js`, `xss.js`, `ssti.js`, `pathTraversal.js`**
  - Port all four exactly: payload lists from T7B.16, error-signature matching for SQLi, reflection check for XSS (text search for the unescaped payload in the response — port the exact old matching logic, don't invent a stricter/looser one), arithmetic-evaluation check for SSTI (`49` appearing where `7*7` was injected), path-traversal content markers (`root:x:` or similar — read the old code for the exact marker).
  - Every payload request goes through `safeHttp` user mode with the **crawled, already-validated** form action; no new host is ever introduced here.
  - Tests against a **deliberately vulnerable local fixture app** (`tests/helpers/webServer.js`: one endpoint that's SQLi-vulnerable via a canned error string, one that reflects XSS, one that evaluates SSTI-like templating in a toy way, one that path-joins unsafely) — assert each check fires on its vulnerable endpoint and **does not** fire on a hardened sibling endpoint (false-positive check).
  - Commit: `feat(webapp): injection checks (sqli, xss, ssti, path traversal)`

- [ ] **T7B.25 `webapp/index.js` — orchestrator + gate enforcement**
  - Request validated → if `active:true`: look up `targetAuthRepo.getActive(userId, registrableDomain)`; if `confirm_authorized:true` and no active record, **create one via `attest`** (rate-limited; cooldown hit → `429` before any scanning, not consumed); if `confirm_authorized:false`/missing and `active:true` → `422 AUTH_GATE_REQUIRED` with the old message text, **before enqueue, no quota used**.
  - Order: crawl (passive, always) → fingerprint → `[tls, headers, methods, cors, exposedFiles, adminPanels, dirListing, robots, dnsEmail]` (always, concurrency-bounded) → if `active` → `[openRedirect, csrf always; sqli, xss, ssti, pathTraversal gated]` → `_build_result` (sort by severity, counts, `WEBAPP_SCAN_USER_LIMIT_PER_DAY` separate Redis counter checked alongside the normal quota — both must pass).
  - `touchesTarget:true`, `mode:'async'`, progress by phase, `screenshot` fields `null`.
  - Commit: `feat(tools): web-app scanner orchestrator with authorization gate`

- [ ] **T7B.26 Route, catalogue, docs**
  - `POST /api/tools/webapp_scan`; `GET /api/tools` entry shows `requiresAuthorization: true` for active mode. Update `docs/api-tools.md`. Write `docs/webapp-scanner-safety.md` (≤ 60 lines): the authorization model (attestation now, upgrade path to stronger verification later), passive-vs-active distinction, the fixed payload list as a safety floor, the extra daily limit, what to do if abused (revoke endpoint, audit trail).
  - Commit: `docs(webapp): safety model documentation`

### Block E — End-to-end, SSRF/abuse tests, review

- [ ] **T7B.27 `tests/integration/webapp-e2e.test.js`**
  - Passive scan (no authorization needed) against the fixture app → findings from headers/TLS/exposed-files/etc.; active scan without authorization → `422`, nothing executed; active scan with attestation → runs the injection checks, finds the seeded vulnerabilities, misses them on the hardened sibling; result keys match `WebAppScanResult`; async submit/poll/cancel; progress monotonic; extra daily limit enforced (11th active scan in a day → 429 even if normal quota remains).
  - Commit: `test(webapp): end-to-end passive and active scans`

- [ ] **T7B.28 `tests/integration/webapp-ssrf.test.js`**
  - A crawled page contains a form whose `action` is `http://169.254.169.254/` → never requested (spy); a redirect during crawl points at a private IP → crawl stops there, no further requests down that path; a page links to a different **public** domain → not crawled (same-origin rule) but if it appeared as a form action it is independently validated (per T7B.18); open-redirect check's sentinel is fixed, never derived from request input (assert the exact URL used).
  - Commit: `test(webapp): ssrf resistance during crawl and checks`

- [ ] **T7B.29 Security & cross-tool review, mutation checks**
  - Grep: every webapp network call goes through `safeHttp`/the DNS tool/the GeoIP service (no bare `fetch`/`http.request`); no payload check reaches a host that wasn't part of the validated crawl graph.
  - **Mutation checks (revert after each):** (a) remove the authorization lookup before active checks → T7B.27 fails; (b) let a form action skip re-validation → T7B.28 fails; (c) remove the wildcard filter in subdomain discovery → T7B.7 fails; (d) connect traceroute to the hostname instead of the IP → T7B.14 fails.
  - Run the full regression suite (Phases 5, 6, 7A unchanged) plus all of 7B. Report counts.
  - Commit only if fixes needed: `fix(webapp,subdomain,traceroute): review findings`

- [ ] **T7B.30 Final verification**
  - `npm run dev:server` + `npm run dev:worker`. Manual: subdomain scan of a domain you own (small wordlist), traceroute to a public IP, web-app passive scan of a page you own, then an active scan after calling `POST /api/authorizations`. Paste each final status/summary.
  - `git log --oneline | head -n 30`; `tree server/src/tools/{subdomain,traceroute,webapp} -L 2`.

---

## 5. Definition of Done (Phase 7B)

- [ ] 30 tasks ticked, one commit each; no secrets committed or logged.
- [ ] All three tools run as Phase 6 async jobs with the old result field names preserved (+ documented additive fields, `screenshot`/`ai_summary` as `null`).
- [ ] Subdomain discovery never HTTP-probes a hostname that resolves to a non-public address; DNS goes through public DoH only.
- [ ] Traceroute connects the subprocess only to a validated IP literal, with argument-injection closed by `execFile` + a fixed arg array.
- [ ] The web-app scanner cannot send a single injection payload without a recorded authorization; passive mode needs none; SSRF is closed on the crawler, on redirects, and on form actions independently.
- [ ] A deliberately vulnerable local fixture proves each injection check fires on the vulnerable endpoint and not on its hardened sibling.
- [ ] All four mutation checks in T7B.29 were caught by tests.
- [ ] Phases 5, 6 and 7A pass unchanged; zero Python files; `client/` untouched.

**When finished, report:** test counts per suite, the four mutation results, wordlist counts vs the old `.txt` files, whether `traceroute`/`tracert` was available on your platform, and anywhere you deviated from the Python behavior (especially the directory-listing false-positive heuristic in T7B.21). This closes Phase 7. Wait for the Phase 8 file (AI reports via Groq, PDF/CSV export, port-scan screenshots, SSE streaming endpoints).
