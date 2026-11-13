# PHASE 7A — Port Scanner, Service Detection, CVE Lookup, Risk Analysis

> **For OpenCode.** Prerequisites: Phases 1–6 finished (all boxes ticked; unit, DB, API and integration suites green; Postgres + Redis running; embedded worker works).
> Companions: `DATABASE-DESIGN.md` (tables `port_findings`, `finding_cves`, `cves`, `service_cve_lookups` already exist), `docs/tool-route-contract.md`, `docs/queue-architecture.md`, `docs/api-tools.md`.
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`.**
> **No Python in the project.** Old Python code is read-only reference at `/tmp/old-cst` (`git clone --depth 1 https://github.com/Yash7256/cybersec-toolkit /tmp/old-cst`).
> Phase 7 is split: **7A (this file)** = port scan tool. **7B** (next file) = subdomain discovery, traceroute, web-app scanner.

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]`, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. **Never read a whole old file.** The old `port_scanner.py` is 2 584 lines — use the line-range map in §3 and `sed -n 'A,Bp' | cut -c1-150`. Port **one function (or one tight group) per task**.
3. Pipe long output through `tail -n 20`; run tests with `--reporter=dot`.
4. One commit per task. If verification fails twice → stop and report the exact error.
5. **Port behavior from the Python branches, not from guesses.** Every table test's expected values come from reading the Python code path. When you change a threshold or label, say why in the commit body.
6. **Everything the scanner reads from the network is hostile.** Banners can contain terminal escapes, megabytes of data, or dribble forever. Bound size, bound time, sanitize at the source.
7. **Legal/ethical guard:** automated tests scan only local fake services. Live checks use a target the user owns or one that explicitly permits scanning (`scanme.nmap.org`, T7A.33). Never scan anything else.
8. Never print secrets (`NVD_API_KEY`, `ABUSEIPDB_API_KEY`).

### 0.1 Reference registry

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina   # node/rules/{async-patterns,performance,streams,testing,error-handling}.md
```

| Short name | URL |
|---|---|
| NODE-NET | https://nodejs.org/docs/latest/api/net.html (`net.connect`, timeouts, `socket.destroy`) |
| NODE-TLS | https://nodejs.org/docs/latest/api/tls.html |
| NVD-START | https://nvd.nist.gov/developers/start-here (API 2.0, rate limits: public 5 req / 30 s, with key 50 req / 30 s) |
| NVD-CVE | https://nvd.nist.gov/developers/vulnerabilities (`cpeName`, `resultsPerPage`, `cvssV3Severity`) |
| CVSS | https://www.first.org/cvss/specification-document (severity bands) |
| ATTACK | https://attack.mitre.org (technique ids/urls) |
| ABUSEIPDB | https://docs.abuseipdb.com/ (`/check`, header `Key`, `maxAgeInDays`) |

---

## 1. Fixed design decisions

**Scan model.** TCP **connect** scan only (no raw packets, no UDP — consistent with the agreed scope; the old code was TCP-only too). One scan targets **one host**; the engine scans the **first validated public address** (prefer IPv4) and reports it as `scanned_ip`.

**Hard safety rails (all enforced in code and tested):**
| Rail | Value |
|---|---|
| Connect only to **re-validated, pinned IP literals** (Phase 6 execution-time check) | always |
| Per-scan concurrency | default 100, hard cap `SCAN_MAX_CONCURRENCY` = 200 (old API allowed 2 000: schema still accepts ≤ 2 000 for compatibility, the effective value is clamped and reported as `max_concurrent_effective`) |
| Per-scan pacing (token bucket, Phase 4) | `SCAN_RATE_CONN_PER_SEC` = 300 |
| Per-worker-process socket ceiling across all scans | `SCAN_GLOBAL_MAX_SOCKETS` = 1 500 (check `ulimit -n` ≥ 4 096 in prod) |
| Ports per scan | ≤ 10 000; range span ≤ 5 000; list ≤ 1 000 (Phase 4 `parsePorts`) |
| Per-port connect timeout | request `timeout` 0.1–10 s (default 2) |
| Banner read | ≤ 4 096 bytes, total per-port probe deadline, socket always destroyed |
| Whole scan | `SCAN_TIMEOUT_MS` = 300 000 (tool `timeoutMs`) |
| Quota | 1 unit per scan; async (`202`) via the Phase 6 queue |
| Target limiter | Phase 4 (5 scans/hour/user/target, 20/hour/target overall) |

**Banner hygiene (stored data is later rendered in a browser and in PDFs):** decode UTF-8 with replacement, **strip C0/C1 control chars and ANSI escape sequences** (keep `\n`, `\t`), cap length, cap lines. Raw bytes are never stored.

**Probe protocol hygiene:** the HTTP probe's `Host:` value must match `^[a-z0-9.-]{1,253}$` (the validated, normalized hostname) — else the probe uses the IP literal. No user string is ever concatenated into a protocol request without that check.

**Enrichment degrades, never fails the scan.** Each enrichment step (TLS audit, CVE lookup, misconfig probes, threat intel) is wrapped: on failure the corresponding field gets an `…_error` note and the rest of the result is still returned.

**Omitted on purpose in 7A:** AI recommendations and screenshots (→ Phase 8; the request flags are accepted, the fields stay `null`, and `recommendations_error` says `"AI recommendations are not enabled yet"` when requested), raw-packet scan types, OS fingerprinting, and the old `attack_mapping.py` / `enhanced_attack.py` (verified unused by the port-scan path; only a prompt file mentions a similarly named JSON key).

**Behavior deviations from the Python code (each deliberate):** duplicate ports are de-duplicated instead of rejected; range span is inclusive (`end−start+1 ≤ 5000`); closed/filtered counts are added to the result (additive keys); errors use the Phase 5 friendly vocabulary.

---

## 2. Target structure (end of 7A)

```
server/src/
  scanner/
    data/portRegistry.js           # 48 entries + derived views
    portMeta.js                    # classifyPortRisk, getPortDescription
    serviceVersion.js  techDetect.js  fingerprint.js  banners.js  sanitize.js
    connect.js  engine.js  sockets.js              # sockets.js = global socket semaphore
    analysis/
      exploits.js  exposure.js  mitre.js  attackSurface.js  attackPaths.js
      simulations.js  securityScore.js
    probes/
      misconfig.js  ftpAnon.js  openProxy.js  httpMisconfig.js  tlsMisconfig.js
    cve/
      cpe.js  nvdClient.js(net/)  detect.js
    intel/
      threatIntel.js
  net/nvdClient.js
  db/repos/cveRepo.js  findingsRepo.js
  tools/portScan/  index.js  schema.js  contract.js
  routes/findings.js
docs/scanner-design.md
tests/
  unit/  scanner-*.test.js  analysis-*.test.js  cve-*.test.js
  integration/ portscan-e2e  scanner-safety  scanner-perf
  helpers/serviceFarm.js           # fake SSH/HTTP/HTTPS/FTP/SMTP/tarpit/silent servers on loopback
```

---

## 3. Old-code map (use these ranges; `P` = `cybersec/core/tools/port_scanner.py`)

| Port to | Old source (lines) |
|---|---|
| `serviceVersion.js` | `service_version.py` (all 68) |
| `banners.js` helpers | `banner_grab.py` (all 92) |
| `techDetect.js` | `tech_detect.py` (all 99) |
| `data/portRegistry.js`, `portMeta.js` | `port_registry.py` (data 42–688, derived views 689–721), `port_risk.py` (45), `port_descriptions.py` (96) |
| `fingerprint.js` | `P` 312–395 |
| `analysis/exploits.js` | `P` 259–306 (rules) + 687–748 |
| `probes/*` | `P` 748–984 (+ `_detect_tls_misconfiguration` 895–962) |
| `analysis/exposure.js` | `P` 1041–1208 |
| `intel/threatIntel.js` | `P` 1239–1422 |
| `analysis/attackPaths.js` | `P` 1422–1691 |
| `analysis/simulations.js` | `P` 1691–1832 |
| `analysis/attackSurface.js` | `P` 1832–1916 |
| `analysis/mitre.js` | `P` 148–258 (mappings) + 1916–1950 |
| `analysis/securityScore.js` | `P` 661–690 + 1950–2029 |
| `engine.js`, tool orchestration | `P` 2029–2360 (`check_port`, `scan_ports`) |
| `cve/*`, `nvdClient.js` | `core/tools/cve_detect.py` (297), `core/security/nvd_client.py` (477) |
| Result keys | `OpenPortDetail` and `PortScanResult` dataclasses, `P` 50–106 |

---

## 4. Tasks

### Block A — Orientation, config, static data

- [ ] **T7A.1 Orientation + one question**
  - Read §3 above; read `docs/tool-route-contract.md`, `docs/queue-architecture.md` headers; read Phase 6 `jobs/executeRun.js` signature and Phase 5 `tools/ssl/probe.js` exports.
  - Print `ulimit -n`, Node version. Verify the old repo is cloned at `/tmp/old-cst`.
  - **Ask the user once:** *"The port registry is ~650 lines of Python dict data. May I use a throwaway `python3` one-liner in `/tmp` (never committed, never in the repo) to dump it to JSON, or should I port it by hand in chunks?"* Record the answer; follow it.
  - No commit.

- [ ] **T7A.2 Env vars**
  - Add: `SCAN_MAX_CONCURRENCY` (200), `SCAN_DEFAULT_CONCURRENCY` (100), `SCAN_RATE_CONN_PER_SEC` (300), `SCAN_GLOBAL_MAX_SOCKETS` (1500), `SCAN_TIMEOUT_MS` (300000), `NVD_API_KEY` (optional), `NVD_CACHE_TTL_HOURS` (24), `NVD_MAX_RESULTS_PER_SERVICE` (10), `NVD_MIN_CVSS_SCORE` (5.0), `ABUSEIPDB_API_KEY` (optional), `THREAT_INTEL_SPAMHAUS` (`'true'|'false'`, default false — Spamhaus refuses most public/cloud resolvers), `THREAT_INTEL_CACHE_TTL_SEC` (3600). Update `.env.example`, test env, `env.test.js`.
  - Commit: `feat(scanner): scanner and cve env vars`

- [ ] **T7A.3 Port registry data (`scanner/data/portRegistry.js`)**
  - Follow the user's answer from T7A.1. Port **all 48 `PortInfo` entries** (`port, service, risk_level, risk_reason, purpose, security_concern, …` — print the dataclass at `port_registry.py` 24–41 first) plus `MITRE_PORT_MAPPINGS`, `POTENTIAL_THREATS`, `EXPOSED_SERVICE_PORTS` (lines 689–721 and the matching constants in `P` 131–147).
  - Test `tests/unit/scanner-registry.test.js`: entry count equals 48; every entry has all fields; ports unique; risk levels ∈ low/medium/high; spot-check 8 well-known ports (22, 23, 80, 443, 3306, 3389, 6379, 27017) against the Python values you read.
  - Commit: `feat(scanner): port registry data`

- [ ] **T7A.4 `scanner/portMeta.js`**
  - Port `classify_port_risk` (with the keyword fallbacks and the 1–1023 / high-port defaults) and `get_port_description` (read `port_descriptions.py` fully), `getServiceForPort`, derived views `COMMON_PORTS`.
  - Table tests: registry hit; keyword fallback (`telnet-alt`); well-known unlisted port (e.g. 1000) → medium + wording from Python; ephemeral port 50000 → medium; unknown service.
  - Commit: `feat(scanner): port risk and description helpers`

- [ ] **T7A.5 Sanitizing, banners, service versions**
  - `scanner/sanitize.js`: `sanitizeBanner(buf, { maxBytes = 4096, maxLines = 100 })` — UTF-8 decode with replacement, remove ANSI/CSI/OSC sequences and C0/C1 controls (keep `\n`, `\t`), collapse `\r\n`, truncate with the same `… [truncated]` marker as the Python code.
  - `serviceVersion.js`: `parseSshBanner`, `parseHttpResponse`, `_extractHttpVersions` (same regexes, same output strings: `"Apache 2.4.49"`, `"nginx 1.18.0"`, `"IIS 10.0"`, `"PHP 7.4.3"`, `"Node.js 14.0.0"`/`"Express"`).
  - `banners.js` pure helpers: `fromBytes`, `fromHttpResponse` (welcome = first non-empty line; `server_response` = header block).
  - Table tests (≥ 25 cases): each regex (positive, negative, case-insensitive), OpenSSH with `p1` and Ubuntu suffix, multiple headers combined with `", "`, no headers → `null`; sanitizer: ANSI colour codes, cursor-movement escapes, OSC title injection, NUL bytes, invalid UTF-8, 10 MB input (completes < 50 ms), exactly-at-limit and over-limit.
  - Commit: `feat(scanner): banner sanitizer and service version parsing`

- [ ] **T7A.6 `scanner/techDetect.js`**
  - Port `_TECH_PATTERNS` (read `tech_detect.py` in two chunks), `detect_technologies(bytes|string)`, `merge_technologies(...lists)` preserving the Python ordering rules. Cap the scanned input at 8 KB and compile regexes once.
  - Tests: each technology has one positive fixture; order stable; merge de-duplicates; **catastrophic-regex guard** — a 1 MB adversarial string finishes < 100 ms (if any pattern is slow, rewrite it).
  - Commit: `feat(scanner): technology detection`

- [ ] **T7A.7 `scanner/fingerprint.js`**
  - Port `_fingerprint_method`, `_calculate_fingerprint_confidence`, `add_service_fingerprints` (`P` 336–395). Output goes to `OpenPortDetail.fingerprint`.
  - Table tests from the Python branches (banner+version → high; port-only → low; HTTP header evidence, etc.).
  - Commit: `feat(scanner): service fingerprint confidence`

### Block B — Scan engine

- [ ] **T7A.8 `scanner/sockets.js` + `scanner/connect.js`**
  - **Read first:** NODE-NET (`net.connect` options, `timeout`, `destroy`), NODE-TLS (`tls.connect`), Phase 4 `tokenBucket.js`.
  - `sockets.js`: process-wide counting semaphore (`SCAN_GLOBAL_MAX_SOCKETS`), `acquire(signal)`/`release()`; abort-aware; metric gauge `cst_scan_sockets_in_use`.
  - `connect.js` — `tryConnect({ address, family, port, tls, servername, timeoutMs, signal })` → `{ state:'open'|'closed'|'filtered', socket?, latencyMs }`: `ECONNREFUSED` → closed; timeout/unreachable/other → filtered; **open** returns the live socket (TLS ports: `tls.connect` with `rejectUnauthorized:false`, `servername` only when it's a valid hostname). Every error path destroys the socket; a hard timer guarantees the promise settles; no listener leaks (`socket.removeAllListeners` on settle).
  - Injectable `connectImpl` for tests. Add to the network allow-list (`tests/unit/network-allowlist.json`) with the reason "scanner connects to validated pinned IPs only".
  - Tests: open (local server), closed (unused port), filtered (stub that never completes), abort mid-connect destroys the socket, 1 000 sequential opens/closes leave `process._getActiveHandles()` at baseline.
  - Commit: `feat(scanner): connect primitive and global socket semaphore`

- [ ] **T7A.9 `scanner/probes` for banners (`scanner/bannerProbe.js`)**
  - Port `check_port`'s probe selection (`P` 2029–2096 + `_probe_timeout` 312–319): HTTP ports → send `GET / HTTP/1.1` with `Host`, UA `CyberSec-PortScanner/1.0`, `Connection: close`; WELCOME ports → passive read; others → passive read capped at 1.5 s. HTTPS ports use TLS (already established by `tryConnect`).
  - **Tarpit defense:** per-probe deadline (`probeTimeout`), total byte cap, stop on first complete chunk for passive reads after the deadline; the socket is always destroyed in `finally`. `Host` header validated per §1 (else IP literal).
  - Returns `{ raw_banner, welcome_message, server_response, version, technologies }` using T7A.5/T7A.6 helpers; version from `_version_from_banner` (read `P` 326–336).
  - Commit: `feat(scanner): per-port banner probes with tarpit defense`

- [ ] **T7A.10 `scanner/engine.js`**
  - `scanPorts({ address, family, hostname, ports, timeoutMs, concurrency, ratePerSec, signal, onProgress, deps })` → `{ open:[OpenPortDetail…], total_scanned, open_ports_count, closed_count, filtered_count, packets_sent, avg_latency_ms, scan_duration_seconds, aborted }`.
  - **Bounded worker pool** (N async workers pulling from an index counter — never `Promise.all` over thousands of ports); each attempt: `tokenBucket.take()` → `sockets.acquire()` → `tryConnect` → (if open) banner probe → release in `finally`. Results sorted by port. `onProgress(done/total)` throttled to ≤ 10 calls/s. On abort: stop pulling, destroy in-flight sockets, return partial results with `aborted:true`.
  - Builds `OpenPortDetail` exactly like old `check_port` (risk/description from `portMeta`, `status:"open"`).
  - Unit tests (stub `connectImpl`, fake timers): concurrency never exceeds N (counter); pacing never exceeds `ratePerSec` over any 1 s window; global socket ceiling respected with 3 concurrent scans; abort mid-scan returns partial + destroys all sockets; a rejecting stub for one port doesn't fail the scan; 5 000 ports with concurrency 200 finish in the expected virtual time.
  - Commit: `feat(scanner): bounded paced scan engine`

- [ ] **T7A.11 `tests/helpers/serviceFarm.js` + `tests/integration/scanner-engine.test.js`**
  - Farm of real loopback servers on ephemeral ports: SSH-like (sends `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.13`), HTTP (`Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4.3`), HTTPS (self-signed via `selfsigned`), FTP-like (`220 ProFTPD 1.3.5 Server`), SMTP-like, **silent** (accepts, never speaks), **tarpit** (sends 1 byte/second forever), **banner bomb** (sends 5 MB of escapes), **closed** ports.
  - Tests inject a permissive policy (test-only). Assert full `OpenPortDetail` for each; tarpit/silent probes finish within `timeout + slack`; banner bomb stored ≤ 4 096 chars with no control characters; closed ports counted; the engine never holds handles after the scan.
  - Because the registry maps well-known ports to services, the engine accepts a **port→service override** for tests (never from the API).
  - Commit: `test(scanner): engine against a fake service farm`

### Block C — CVE detection (NVD)

- [ ] **T7A.12 `net/nvdClient.js`**
  - **Read first:** NVD-START, NVD-CVE; old `nvd_client.py` lines 39–300 (`NVDClient`: request, headers, parsing). Use `safeHttp` **trusted mode** (`services.nvd.nist.gov`), header `apiKey` when configured, query `cpeName=<cpe>` + `resultsPerPage`.
  - Rate: Phase 4 outbound limiter `nvd` — **5 requests / 30 s without a key, 50 / 30 s with a key** (docs above), shared across processes. Retry only on `403/429/503` with exponential backoff + jitter, max 3 tries; breaker `nvd`; hard timeout 15 s.
  - Parse CVSS preferring v3.1 → v3.0 → v2 (score, vector, severity), description (English), `published`, url `https://nvd.nist.gov/vuln/detail/<id>`; skip `Rejected` vulnerabilities.
  - Tests with fixture JSON (`tests/fixtures/nvd/`): normal response, only-v2 metrics, no metrics, rejected CVE, empty result, malformed JSON, 429 then success, 403 persistent → `upstream` error, limiter waits instead of rejecting.
  - Commit: `feat(net): nvd client with shared rate limiting`

- [ ] **T7A.13 `scanner/cve/cpe.js`**
  - Port `SERVICE_CPE_MAPPINGS`, `normalize_service_name`, `parse_version_string`, `cvss_score_to_severity` (`cve_detect.py` 64–147). **Read how `detect_cves_batch` (243–281) treats multi-product strings like `"Apache 2.4.49, PHP 7.4.3"`** and port that behavior (split, per-product lookups, merged result keyed by the original string).
  - Tests: `OpenSSH 9.6p1`, `Apache 2.4.49`, `nginx 1.18.0`, `PHP 7.4.3`, `Node.js 14.0.0`, `Microsoft IIS 10.0`, unknown product → no lookup, garbage → `null`, severity bands (0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0).
  - Commit: `feat(scanner): cpe mapping and version parsing`

- [ ] **T7A.14 `db/repos/cveRepo.js`**
  - `getServiceLookup(cacheKey)` (returns only non-expired), `putServiceLookup({service, version, cveIds, ttlHours})`, `upsertCves(list)` (multi-row `INSERT … ON CONFLICT (id) DO UPDATE`, ids **sorted** before insert to avoid deadlocks under concurrency), `findCvesByIds(ids)`. `cacheKey = sha256(lower(service)|version)` as in `DATABASE-DESIGN.md`. TTL from `NVD_CACHE_TTL_HOURS`.
  - DB tests: upsert idempotent; expired lookup ignored; 20 parallel upserts of overlapping id sets → no deadlock/errors; invalid CVE id rejected by the CHECK constraint; raw `data` JSONB round-trips.
  - Commit: `feat(db): cve cache repository`

- [ ] **T7A.15 `scanner/cve/detect.js` — `detectCvesBatch(versionStrings)`**
  - Dedupe inputs; **single-flight** per `(service, version)` (shared in-flight promise map); cache first (`cveRepo`), then NVD sequentially under the limiter; filter `cvss ≥ NVD_MIN_CVSS_SCORE`, keep top `NVD_MAX_RESULTS_PER_SERVICE` by score; compute `total/critical/high/medium/low` counts and the CVE list shape of old `CVEResult`/`CVE` (`cve_id, description, severity, cvss_score, cvss_vector, published_date, url`). Per-port attach helper reproduces `max_cvss_score/severity/cve` (`P` 2273–2290).
  - NVD down/limited → return `{}` plus `cve_error:"Lookup service unavailable"` (scan continues).
  - Tests: cache hit makes zero NVD calls; two ports with the same version → one lookup; counts and max-CVSS correct; NVD failure degrades; DB failure on cache write is tolerated (logged), as the old code did.
  - Commit: `feat(scanner): batched cve detection with cache and single-flight`

### Block D — Probes and analysis (pure logic first)

- [ ] **T7A.16 `scanner/probes/*` — misconfiguration probes**
  - Port `_probe_anonymous_ftp` (`P` 821–853), `_probe_open_proxy` (853–895, **canary request to the fixed constant `http://example.com/`; never user-controlled**), `_detect_http_misconfigurations` (784–821 incl. `_http_response_text`, `_parse_http_headers`), `_detect_tls_misconfiguration` (895–962; **reuse Phase 5's TLS probe** — export `auditTls({ address, host, port })` from `tools/ssl/` if it isn't already), `_misconfiguration` factory (748–764).
  - All sockets via `tryConnect` (pinned IP, semaphore, bounded reads, sanitized). Each probe ≤ 5 s.
  - Tests against the service farm: FTP that allows anonymous login → finding; FTP refusing → none; proxy answering 200 → critical `open_proxy`; proxy answering `407`/`403` → none; HTTP with `Server: Apache/2.2.15` + `X-Powered-By` + missing headers → findings as the Python branches define; TLS expired / self-signed / weak-cipher marker (`RC4`, `3DES`, …) via stubbed audit results.
  - Commit: `feat(scanner): misconfiguration probes`

- [ ] **T7A.17 `detectMisconfigurations` + summary**
  - Port `detect_misconfigurations` (1208–1239) and `_misconfiguration_summary` (962–984): ports → which probes run (`FTP_PORTS`, `PROXY_PORTS`, `HTTP_PORTS`, `HTTPS_PORTS`), concurrency 5, results attached to `OpenPortDetail.misconfigurations`, summary counts by severity.
  - Tests from the Python branches, including "no open ports" and "probe throws".
  - Commit: `feat(scanner): misconfiguration orchestration and summary`

- [ ] **T7A.18 `analysis/exploits.js`**
  - Port `CURATED_EXPLOIT_RULES` (all rules, `P` 259–306), `_version_matches`, `add_exploit_availability` (687–748).
  - Tests: one positive per rule (e.g. Apache 2.4.49 → `CVE-2021-41773`; vsftpd 2.3.4), one near-miss per rule (2.4.51), service name case-insensitivity, no version → none.
  - Commit: `feat(scanner): curated exploit availability`

- [ ] **T7A.19 `analysis/exposure.js`**
  - Port `_exposure_level`, `_promote_risk_level`, `_exposure_finding`, `_exposure_recommendation`, `calculate_exposure_severity` (1041–1208) including the constants `EXPOSED_SERVICE_PORTS`, `ADMIN_SERVICE_PORTS`, `DATABASE_PORTS`, `REMOTE_ACCESS_PORTS`, `EXPOSURE_SEVERITY_RANK`.
  - ≥ 15 table tests covering each score contribution, public vs non-public exposure, threat-intel influence, summary counts, the "no open ports" shape.
  - Commit: `feat(scanner): exposure severity`

- [ ] **T7A.20 `intel/threatIntel.js`**
  - Port `_empty_threat_intel`, `_abuseipdb_check`, `_spamhaus_check`, `check_threat_intelligence` (1239–1422). AbuseIPDB via `safeHttp` trusted mode (`api.abuseipdb.com`, header `Key`, `maxAgeInDays=90`); **only public IPs ever sent** (the scanned IP is already validated). Redis cache `cst:intel:<ip>` (`THREAT_INTEL_CACHE_TTL_SEC`), breaker `intel`, outbound limiter.
  - Spamhaus (only when `THREAT_INTEL_SPAMHAUS`): DNS query `<reversed-ip>.zen.spamhaus.org` through the system resolver — constructed **only** from a validated IP and the fixed zone (add to the network allow-list with that reason). **Return codes `127.255.255.252/.254/.255` mean "query refused/blocked", not "listed" and not "clean" → `unavailable`.**
  - No API key → result `reputation:"Not checked"` with the note, as the old `_empty_threat_intel`.
  - Tests with fixtures: clean, listed (score ≥ threshold), AbuseIPDB 429/5xx → degraded result, Spamhaus refused code → unavailable, cache hit → zero upstream calls, key never appears in logs/errors.
  - Commit: `feat(scanner): threat intelligence`

- [ ] **T7A.21 `analysis/mitre.js` + `analysis/attackSurface.js`**
  - Port `MITRE_PORT_MAPPINGS`/`MITRE_SERVICE_MAPPINGS` (`P` 148–258 + registry copy), `_mitre_url`, `add_mitre_attack_mapping` (1916–1950); `_attack_surface_level`, `calculate_attack_surface` (1422–1432, 1832–1916).
  - Tests: port→techniques mapping for 22/23/445/3389; unknown port → empty; surface levels at each threshold boundary; factors list contents.
  - Commit: `feat(scanner): mitre mapping and attack surface`

- [ ] **T7A.22 `analysis/attackPaths.js`**
  - Port helpers `_attack_path_node`, `_attack_path_edge`, `_best_web_label`, `_best_port_by_score`, `_path_summary` and `build_attack_path_visualization` (1432–1691). Read it in **three** `sed` chunks.
  - **Golden test**: a fixed 5-port input (22, 80, 443, 3306, 6379) → exact `nodes`, `edges`, `paths`, `summary`, `highest_severity` derived by tracing the Python; plus empty-input shape and single-port shape.
  - Commit: `feat(scanner): attack path graph`

- [ ] **T7A.23 `analysis/simulations.js`**
  - Port `_simulation` and `build_attack_simulation_recommendations` (1691–1832). Golden tests for 3 inputs (web only, web + database, remote access exposed) + empty.
  - Commit: `feat(scanner): attack simulation recommendations`

- [ ] **T7A.24 `analysis/securityScore.js`**
  - Port `_score_factor`, `_surface_factor`, `_unknown_bool_label` (661–690) and `calculate_security_score` (1950–2029; it uses the cached SSL audit results — take them as an argument, never re-audit).
  - Table tests: perfect score 100 with no ports; each penalty category; floor at 0; HTTPS with expired cert; weak TLS cipher marker; factors list shape.
  - Commit: `feat(scanner): security score`

### Block E — Tool assembly

- [ ] **T7A.25 `tools/portScan/schema.js` + `contract.js`**
  - Request (names exactly as the old API): `target`, `ports` (array of ints **or** Phase 4 spec string), `start_port`/`end_port` (both or neither; `end ≥ start`; span rule), `timeout` (default 2.0, 0.1–10), `max_concurrent` (default 100, 1–2000; effective value clamped to `SCAN_MAX_CONCURRENCY`), `include_ai_recommendations`, `include_threat_intel`, `include_misconfigurations`, `include_screenshots` (booleans, default true — AI/screenshots are accepted but inert in 7A). Only one of `ports` / range allowed (reject both).
  - `contract.js`: `PORT_SCAN_RESULT_KEYS` (from the `PortScanResult` dataclass) and `OPEN_PORT_KEYS` (from `OpenPortDetail`, **including** the Phase 8 fields `screenshot, screenshot_url, recommendation*` as `null`), plus additive `scanned_ip`, `closed_count`, `filtered_count`, `max_concurrent_effective`, `cve_error`, `intel_error`.
  - Tests: every old validation message path (both-or-neither, reversed range, span, > 1 000 list entries, out-of-range ports), defaults, rejects `ports`+range together.
  - Commit: `feat(tools): port scan request schema and result contract`

- [ ] **T7A.26 `tools/portScan/index.js` — the orchestrator (mirror `scan_ports`, `P` 2097–2360)**
  - Tool definition: `mode:'async'`, `touchesTarget:true`, `timeoutMs: SCAN_TIMEOUT_MS`, `dedupeTtlSec:0`, summary `{ openPorts, scanned, securityScore, highestSeverity, cveCount }`.
  - Order (same as the old function): default ports = `COMMON_PORTS` → `scanPorts` (progress 0–55 %) → `addServiceFingerprints` → **TLS audit once per open HTTPS port** (concurrency 3, results shared via `ssl_cache` with misconfig + score) (55–65 %) → in parallel **[CVE ‖ misconfig ‖ threat intel]** (65–90 %; honor `include_*`; screenshots/AI skipped) → attach CVEs → exploit availability → exposure severity → attack paths → simulations → MITRE → security score → attack surface (90–100 %).
  - Failure handling: resolution/policy failures are Phase 5/6 errors (not this file's job); an enrichment failure sets its `*_error` field only; an aborted scan returns the partial result with `error:"Scan cancelled"` only if the run ends `CANCELLED` (the worker finalizes).
  - Result assembled with exactly `PORT_SCAN_RESULT_KEYS`; `recommendations_error` per §1.
  - Commit: `feat(tools): port scan orchestrator`

- [ ] **T7A.27 Persist findings atomically**
  - Extend `runRepo.completeFenced` with an optional `extra(tx)` callback executed **inside the same transaction, only after the fenced UPDATE succeeded**. `findingsRepo.replaceForRun(tx, runId, openPorts)` does `DELETE FROM port_findings WHERE run_id=$1` then bulk-inserts (`port`, `protocol:'TCP'`, `state:'OPEN'`, `service`, `version`, `banner` ≤ 2 000 chars, `risk` mapped low/medium/high → `LOW/MEDIUM/HIGH`) and `finding_cves` (CVEs upserted first via `cveRepo` with sorted ids). Re-running an attempt is idempotent.
  - DB tests: findings + result commit together or not at all (force an error in `extra`); a fenced-out worker writes **no** findings; 300 open ports × 10 CVEs inserts in < 1 s; CHECK constraint (port 1–65535) holds; unique `(run_id,port,protocol)`.
  - Commit: `feat(db): atomic port findings persistence`

- [ ] **T7A.28 Wiring, findings endpoint, catalogue**
  - Register in `tools/index.js`; `POST /api/tools/port_scan` (+ the old alias paths if any were used by the client — check `routes/tools.py` 438–520). `GET /api/runs/:id/findings?cursor=&limit=` (keyset by `port`, ownership-checked → 404 otherwise, `Cache-Control:no-store`) reading `port_findings` + CVEs.
  - `GET /api/tools` shows `port_scan` with `async:true`. Update `docs/api-tools.md` (request, result keys, limits, error vocabulary, additive fields).
  - Commit: `feat(server): port scan route and findings endpoint`

### Block F — End-to-end, safety, performance, review

- [ ] **T7A.29 `tests/integration/portscan-e2e.test.js` (embedded worker, service farm, NVD stub server)**
  - Submit → `202` → poll to `COMPLETED`; result has `PORT_SCAN_RESULT_KEYS`; open ports match the farm; Apache-like banner gets the stubbed CVEs attached with correct counts; `port_findings` rows exist; progress is monotonic and reaches 100; `GET …/findings` paginates.
  - Cancel mid-scan → `CANCELLED` within one heartbeat (sockets closed, no handle leak, no refund); re-validation: stub resolver flips to a private address between submit and run → `COMPLETED` with `data.error`, audit row, no refund; NVD down → result still complete with `cve_error`; quota: exactly 1 unit; 6th scan by a FREE user → 429.
  - Commit: `test(scanner): end-to-end async port scan`

- [ ] **T7A.30 `tests/integration/scanner-safety.test.js`**
  - Measured connection rate (server-side timestamps) ≤ `SCAN_RATE_CONN_PER_SEC × 1.25` over every 1 s window; **three concurrent scans** never exceed `SCAN_GLOBAL_MAX_SOCKETS` (sampled gauge); tarpit/silent/banner-bomb services cannot extend the run past its timeout; stored banners contain no control or ANSI characters; request with 10 000 ports rejected before any expansion; per-target limiter blocks the 6th same-target scan; concurrency requested 2 000 → effective 200 reported.
  - Commit: `test(scanner): rate, socket and hostile-service safety`

- [ ] **T7A.31 `tests/integration/scanner-perf.test.js` (skipped unless `PERF_TESTS=1`)**
  - 1 000 closed loopback ports, concurrency 200 → < 5 s; 5 000 ports against a stub that never answers, timeout 0.5 s, concurrency 200 → within 15 % of the theoretical ~12.5 s; event-loop p99 (`cst_eventloop_lag_p99_seconds`) < 50 ms during the scan; heap growth after GC < 20 %.
  - Commit: `test(scanner): performance envelope`

- [ ] **T7A.32 Security review, mutation checks, docs**
  - Grep: every `net.connect`/`tls.connect` in `src/scanner` is inside `connect.js` (allow-list entry), every outbound HTTP uses `safeHttp`, no `Host:` built from unchecked input (assert in a test via the regex rule), no `queryRawUnsafe`.
  - **Mutation checks (revert after each; each must be caught):** (a) connect to the hostname instead of the pinned IP → engine/e2e test fails; (b) remove token-bucket `take()` → pacing test fails; (c) bypass `sanitizeBanner` → T7A.5/T7A.11 fail; (d) remove the global socket semaphore → safety test fails; (e) drop the CVSS floor → T7A.15 fails.
  - Write `docs/scanner-design.md` (≤ 80 lines): concurrency model, pacing, hard limits table, banner hygiene, enrichment order and degradation rules, what is intentionally missing (raw-packet scans, UDP, OS fingerprint, screenshots/AI → Phase 8, `attack_mapping.py`/`enhanced_attack.py`).
  - Commit: `docs(scanner): design, safety review and mutation results`

- [ ] **T7A.33 Live smoke test (USER-ASSISTED)**
  - **Only against a target the user owns or `scanme.nmap.org`** (the Nmap project explicitly permits light scanning; keep it to a handful of ports and do not loop). Run `ports: [22, 80, 443, 9929, 31337]` through the real stack (API + worker), paste the final JSON summary (open ports, versions, CVE counts, score, duration).
  - Record timings per phase (scan / TLS / CVE / probes) from logs. If any phase exceeds its budget (scan > 15 s for 5 ports, CVE > 60 s), report which step and why (NVD limiter waiting is expected without a key).
  - Final: all suites + counts, `git log --oneline | head -n 45`, `tree server/src/scanner -L 2`.

---

## 5. Definition of Done (Phase 7A)

- [ ] 33 tasks ticked, one commit each; no secrets committed or logged.
- [ ] A port scan runs as a Phase 6 async job and returns a result with exactly the old `PortScanResult`/`OpenPortDetail` keys (+ documented additive keys); AI/screenshot fields present as `null`.
- [ ] The scanner can only touch re-validated pinned IPs, at bounded concurrency, bounded rate, bounded per-process sockets — proved by tests, including three concurrent scans.
- [ ] Hostile services (tarpit, silent, banner bomb, escape sequences) cannot hang a scan or poison stored data.
- [ ] CVE lookup is cached in Postgres, rate-limited across processes, single-flight, and degrades gracefully when NVD is down.
- [ ] Findings and CVE links persist atomically with the result and are fenced against zombie workers.
- [ ] All five mutation checks in T7A.32 were caught by tests.
- [ ] Phase 5/6 tests pass unchanged; zero Python files; `client/` untouched.

**When finished, report:** test counts per suite, mutation results, live-smoke timings, the answer to the T7A.1 question, and every place where you deviated from the Python behavior. Then wait for the Phase 7B file (subdomain discovery with wordlists, traceroute, web-app scanner).
