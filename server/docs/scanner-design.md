# Port scanner design (Phase 7A)

## Scope

`port_scan` is an asynchronous TCP connect scanner. It fingerprints open
services, enriches them with CVE, misconfiguration, TLS, and threat-intel data,
then scores exposure. It never sends raw packets, never scans UDP, and never
fingerprints the OS.

Targets are re-validated before execution: the worker connects only to the
pinned IP returned by `validateTarget`, never to the user-supplied hostname.
Host headers are rebuilt from the validated hostname (or pinned IP fallback).

## Concurrency model

- One `AbortController` per run; cancellation destroys every in-flight socket.
- A per-process semaphore (`SCAN_GLOBAL_MAX_SOCKETS`) caps sockets across all
  concurrent scans. The engine releases in `finally`, including on abort.
- Per-scan `max_concurrent` is clamped to `SCAN_MAX_CONCURRENCY`; the effective
  value is reported in `max_concurrent_effective`.
- TLS audits run at concurrency 3. Misconfig probes at concurrency 5. CVE,
  misconfig, and threat-intel work runs in parallel after the scan.

## Pacing

A token bucket with `SCAN_RATE_CONN_PER_SEC` and burst 1 allows exactly one new
connection per interval per scan. Rate limiting happens before socket
acquisition, so queued work cannot create bursts. Connections use
`timeoutMs` for connect plus bounded probe timeouts.

## Hard limits

| Limit | Value |
| --- | --- |
| Ports per request | 10,000 (`MAX_PORTS_PER_SCAN`) |
| Port range span | 5,000 (`MAX_PORT_RANGE_SPAN`) |
| Port list entries | 1,000 (`MAX_PORT_LIST_ENTRIES`) |
| Per-scan concurrency | 200 (`SCAN_MAX_CONCURRENCY`) |
| Per-process sockets | 1,500 (`SCAN_GLOBAL_MAX_SOCKETS`) |
| Connection rate | 300/s default (`SCAN_RATE_CONN_PER_SEC`) |
| Run timeout | `SCAN_TIMEOUT_MS` (300 s default) |
| Banner bytes | `MAX_BANNER_BYTES` (8 KiB) |
| Finding banner column | 2,000 chars |
| NVD response | 2 MiB, 15 s deadline |
| NVD rate | 50/30 s with key, 5/30 s without |

## Banner hygiene

Banners are treated as hostile. Reads are capped by bytes, time, and line count.
`sanitizeBanner` strips OSC/CSI/ESC sequences, C0/C1 controls (except newline and
tab), normalizes CRLF, and appends a truncation marker. Only sanitized text is
stored in `port_findings.banner`; raw socket buffers never reach the database.

## Enrichment order

1. Scan and banner probe (pinned IP, bounded).
2. Service/version fingerprint and technology detection.
3. TLS audit for 443/8443 (shared cache for analysis).
4. Parallel CVE lookup, misconfiguration probes, threat intelligence.
5. Attach CVEs, then exploit availability, exposure, MITRE mapping, score,
   attack surface, attack paths, and simulations.

All enrichment is best-effort. A failed source sets a field such as
`cve_error` or `intel_error`; the scan still completes with partial data.

## Persistence

`runRepo.completeFenced` writes `run_results` and findings in one transaction.
`findingsRepo.replaceForRun` deletes old rows for the run, upserts CVEs, inserts
bounded `port_findings`, then links `finding_cves`. Zombie workers are fenced by
status, worker id, and attempt, so stale completions cannot write findings.

## Degradation rules

- No `ABUSEIPDB_API_KEY` and Spamhaus disabled: reputation `Not checked`.
- Private/loopback IPs: reputation `Private/Local`, no outbound calls.
- AbuseIPDB failure: `Unknown`, `abuseipdb.available = false`.
- Spamhaus refusal codes: unavailable, never reported as clean.
- NVD failure: `cve_error = "Lookup service unavailable"`, zero CVEs.
- Cache write failure: logged and ignored; the scan result is unchanged.

## Intentionally missing

Raw-packet SYN scans, UDP scans, OS fingerprinting, screenshots and AI
recommendations (Phase 8), and the legacy `attack_mapping.py` /
`enhanced_attack.py` heuristics. Screenshot, recommendation, and AI fields are
present in the contract as `null` so Phase 8 can fill them without a breaking
change.
