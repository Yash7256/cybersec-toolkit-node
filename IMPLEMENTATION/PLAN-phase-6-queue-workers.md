# PHASE 6 — Queue, Workers, Crash Recovery, Retention

> **For OpenCode.** Prerequisites: Phases 1–5 finished (all boxes ticked; unit, DB and API suites green; Postgres + Redis running).
> Companions: `DATABASE-DESIGN.md` (this phase adds 3 columns + 2 indexes, see T6.3), `docs/tool-route-contract.md`, `docs/api-tools.md`.
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`. Never write Python.**
> Old Python reference (read-only): `/tmp/old-cst` (`git clone --depth 1 https://github.com/Yash7256/cybersec-toolkit /tmp/old-cst`) — files `cybersec/runtime/*.py`, `cybersec/core/recovery.py`.

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]` here, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. Never read a whole large file. `grep -n` the function, then `sed -n 'A,Bp'`.
3. Pipe long output through `tail -n 20`; run tests with `--reporter=dot`.
4. One commit per task, message given. If verification fails twice → stop and report the exact error.
5. **Concurrency bugs are the whole point of this phase.** Every race listed in a task needs a test that actually runs the race (`Promise.all`, parallel processes). A test that only checks the happy path does not count.
6. Never print secrets. Never put user-controlled strings into Redis keys, job ids or SQL text (parameters only).

### 0.1 Reference registry

```bash
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina        # node/rules/{graceful-shutdown,async-patterns,testing}.md
git clone --depth 1 https://github.com/supabase/agent-skills /tmp/skills-supabase  # references/lock-*, schema-*, data-* rule files
```

| Short name | URL |
|---|---|
| BULLMQ-INDEX | https://docs.bullmq.io/llms.txt (append `.md` to any docs page to read it as markdown) |
| BULLMQ-STALLED | https://docs.bullmq.io/bull/important-notes.md (locks, `lockDuration`, `stalled` event, `maxStalledCount`) |
| BULLMQ-SCHED | https://docs.bullmq.io/guide/job-schedulers.md (`upsertJobScheduler`, `every`, `pattern`, `tz`) |
| BULLMQ-V6 | https://docs.bullmq.io/guide/migrations/migrate-from-v5-to-v6 (legacy repeatable jobs removed — use Job Schedulers only) |
| PG-LOCKS | https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS |
| PG-SKIP | https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE (`SKIP LOCKED`) |
| PG-BRIN | https://www.postgresql.org/docs/current/brin.html |

> BullMQ evolves (v5 → v6). **Read the installed major version's docs** (BULLMQ-INDEX) before writing queue code. Option names in this plan (`lockDuration`, `stalledInterval`, `maxStalledCount`, `concurrency`, `upsertJobScheduler`) were verified in the docs; if the installed version differs, the docs win on *names*, this plan wins on *behavior*.

---

## 1. What the old Python runtime did (and why it is not ported)

| Old | Problem | New |
|---|---|---|
| `scan_queue = asyncio.Queue(maxsize=1000)` in process memory | Lost on restart; invisible to other instances | **BullMQ on Redis** (transport only) |
| `job_store.jobs = {}` dict | Lost on restart, unbounded growth | **Postgres `tool_runs` is the source of truth** |
| `WorkerPool` of 10 coroutines inside the API process | Heavy scans compete with HTTP handling; a crash kills them | **Separate worker process** (embedded worker only as a dev convenience) |
| Port-scan routes ran the scan **inline in the request** (the queue was effectively dead code) | Request timeouts, no durability | Long tools are **async jobs**: `202` + polling |
| `recovery.py`: worker heartbeat table, reaper marks stalled scans `timed_out` after 120 s | No retry, no refund, no fencing | Run-level heartbeat, reaper **retries once, then fails + refunds**, fenced writes |
| Celery stub (`tasks.py`) | Unused | Dropped |

---

## 2. Fixed design decisions

**Roles.** *Postgres decides; Redis carries.* BullMQ delivers a job id to a worker; **every state transition is decided by a guarded SQL statement** on `tool_runs`. A lost or duplicated Redis message can therefore never corrupt state.

**State machine** (`tool_runs.status`, already in Phase 2):
```
QUEUED ──claim──▶ RUNNING ──complete──▶ COMPLETED
  │  ▲               │ ├─fail──▶ FAILED
  │  └──requeue──────┘ ├─timeout──▶ TIMED_OUT
  └─cancel (atomic)─▶ CANCELLED ◀──cancel (worker finalizes)──┘
```

**Guards** (each is one `UPDATE … WHERE`, returning 0 rows = "someone else won"):
- *claim*: `WHERE id=$1 AND status='QUEUED'` → `RUNNING`, `attempt = attempt+1`, `worker_id`, `heartbeat_at = now()`.
- *fencing*: every later write from a worker adds `AND status='RUNNING' AND worker_id=$me AND attempt=$n`. A "zombie" worker that was reaped can no longer heartbeat, complete or fail; 0 rows ⇒ **abort immediately, write nothing**.
- *refund*: exactly once via `quota_refunded` flag (`UPDATE … SET quota_refunded=true WHERE … AND NOT quota_refunded RETURNING …`), in the same transaction as the usage decrement.

**Retries.** The *reaper* (not BullMQ) re-queues a stale run once: `RUN_MAX_ATTEMPTS = 2`. BullMQ is configured with `attempts: 1` and `maxStalledCount: 0` (a stalled job is failed in Redis immediately; the DB reaper decides what happens next). Every attempt gets a fresh job id: `<runId>-<attempt>`.

**Tool-level errors are results, not retries** (Phase 5 table still applies): `target` errors → `COMPLETED` with `data.error`; `upstream`/`internal`/timeout/lost-worker → `FAILED`/`TIMED_OUT` + refund.

**Admission control for async runs** (order matters, checked before any side effect where possible):
`submit limiters → zod → cooldown → validateTarget → targetLimiter → queue depth < QUEUE_MAX_WAITING (else 503 QUEUE_FULL + Retry-After) → [Idempotency-Key claim] → enforceQuota → createQueuedWithCap (else refund + 429 TOO_MANY_ACTIVE_RUNS) → enqueue (else mark FAILED + refund + 503)`.

**Per-user active cap** (QUEUED+RUNNING): FREE 2, PAID 5 (env), ADMIN 5. Enforced atomically in Postgres with a per-user **transaction-level advisory lock** — no Redis counters that can leak.

**Re-validation at execution time.** A job may wait minutes in the queue; DNS can change meanwhile. For `touchesTarget` tools the worker runs `validateTarget` **again** immediately before executing and uses the *fresh* pinned addresses. If it now fails → run `COMPLETED` with `data.error:"Target is not allowed"`, **no refund**, audit `scan.blocked_target`, `recordBlocked(userId)`.

**Cancellation.** QUEUED → atomic `UPDATE … SET status='CANCELLED' WHERE status='QUEUED'` (+ remove the BullMQ job, + refund). RUNNING → durable flag `cancel_requested_at`, picked up by the heartbeat (≤ 15 s) and nudged instantly via Redis pub/sub; the worker aborts and finalizes `CANCELLED` (no refund — work was done).

**Redis becomes a hard dependency** (Phase 4 left it "degraded"): API `/api/ready` → 503 when Redis is down.

**Retention defaults:** FREE runs 90 days, PAID 365, `usage_counters` 400, `webhook_events` 30; expired CVE cache rows only if unreferenced; never touch non-terminal runs. Batches of 5 000, 100 ms pause.

---

## 3. Target structure (end of Phase 6)

```
server/src/
  config/env.js                    # + queue/worker/retention vars
  queue/
    connections.js  queues.js  events.js            # events = redis pub/sub (progress, cancel nudge)
  jobs/
    executeRun.js                  # shared executor (inline + worker)
  worker/
    processor.js  index.js  health.js
  maintenance/
    scheduler.js  reaper.js  retention.js
  db/repos/runRepo.js              # + claim, heartbeat, fenced complete/fail, cancel, requeue, refundOnce, cap
  worker.js                        # entrypoint: `node src/worker.js`
docs/queue-architecture.md  docs/ops-queue.md
tests/
  helpers/{workerProcess.js, asyncTestTool.js}
  db/ run-lifecycle  retention
  api/ async-runs  cancel  idempotency
  integration/ worker  reaper  redis-loss  shutdown  load
```

---

## 4. Tasks

### Block A — Orientation, packages, config, schema

- [x] **T6.1 Orientation (read-only)**
  - Print only function names of old `core/recovery.py` (`grep -n "^async def\|^def"`) and `runtime/scan_workers.py`. Read Phase 5 `tools/_shared/runTool.js`, `db/repos/runRepo.js` (function names), `middleware/quota.js`.
  - Read BULLMQ-INDEX, then BULLMQ-STALLED and BULLMQ-SCHED. Report: latest BullMQ major, Node version, whether `docker compose ps` shows Redis healthy.
  - No commit.

- [x] **T6.2 Install and configure**
  - `npm i bullmq --workspace server` (record the exact version in the commit body).
  - Env (zod, defaults): `QUEUE_PREFIX` (`cst`), `WORKER_CONCURRENCY` (10), `WORKER_HEARTBEAT_SEC` (15), `RUN_STALL_SEC` (120), `RUN_MAX_ATTEMPTS` (2), `QUEUE_MAX_WAITING` (1000), `QUEUE_MAX_WAIT_SEC` (900), `ORPHAN_QUEUED_SEC` (60), `MAX_ACTIVE_RUNS_FREE` (2), `MAX_ACTIVE_RUNS_PAID` (5), `WORKER_SHUTDOWN_GRACE_MS` (25000), `RUN_EMBEDDED_WORKER` (`'true'|'false'`, default true in development, **false in production**), `WORKER_HEALTH_PORT` (3002), `MAINTENANCE_ENABLED` (true), `RETENTION_DAYS_FREE` (90), `RETENTION_DAYS_PAID` (365), `RETENTION_USAGE_DAYS` (400), `RETENTION_WEBHOOK_DAYS` (30), `RETENTION_BATCH_SIZE` (5000), `RETENTION_MAX_BATCHES` (50), `RETENTION_DRY_RUN` (false). Cross-check: `RUN_STALL_SEC ≥ 4 × WORKER_HEARTBEAT_SEC` else fail validation.
  - Update `.env.example`, `vitest.config.js` test env (use a unique `QUEUE_PREFIX` per test run), `env.test.js`.
  - Commit: `feat(queue): bullmq dependency and queue env vars`

- [x] **T6.3 Database migration (Prisma) — columns and indexes**
  - Add to `model ToolRun` in `schema.prisma`: `cancelRequestedAt DateTime? @map("cancel_requested_at") @db.Timestamptz(3)`, `quotaDate DateTime? @map("quota_date") @db.Date`, `quotaRefunded Boolean @default(false) @map("quota_refunded")`, and `@@index([createdAt], type: Brin)`.
  - `prisma migrate dev --create-only --name run_queue_support`, then add raw SQL:
    ```sql
    CREATE INDEX ix_tool_runs_user_active ON tool_runs (user_id) WHERE status IN ('QUEUED','RUNNING');
    ALTER TABLE tool_runs ADD CONSTRAINT tool_runs_refund_needs_date CHECK (NOT quota_refunded OR quota_date IS NOT NULL);
    ```
  - Update `DATABASE-DESIGN.md` §3 (new access patterns: *active runs per user*, *retention by age*) and §4/§5 accordingly.
  - Verify with `EXPLAIN` on the 1M-row benchmark DB from Phase 2 (if absent, a 100k-row seed + `ANALYZE`): active-count-per-user uses `ix_tool_runs_user_active`; `WHERE created_at < $1` uses the BRIN index. Record both plans in `docs/db-benchmark.md`.
  - Commit: `feat(db): run queue support columns and indexes`

- [x] **T6.4 Queue modules (`queue/connections.js`, `queues.js`)**
  - **Read first:** BULLMQ-STALLED, BullMQ "Connections" and "Going to production" pages (via BULLMQ-INDEX).
  - Two **dedicated** ioredis connections built from `REDIS_URL` (never reuse the Phase 4 limiter client): *producer* = fail-fast (`enableOfflineQueue:false`); *worker* = `maxRetriesPerRequest:null` (required by BullMQ workers).
  - Queues `runs` and `maintenance` with prefix `env.QUEUE_PREFIX`; default job options `{ attempts:1, removeOnComplete:{age:3600,count:1000}, removeOnFail:{age:604800,count:1000} }`.
  - `enqueueRun({ runId, attempt, priority })`: jobId `${runId}-${attempt}`, **payload = `{ runId }` only**, priority PAID/ADMIN `1`, FREE `10`. `getQueueDepth()` = waiting+prioritized count, cached 1 s. `closeQueues()` for shutdown hooks.
  - Tests (`tests/integration/queue.test.js`, real Redis): same jobId twice → one job; priority 1 is processed before 10 with concurrency 1; payload contains nothing but `runId`; producer fails fast (< 500 ms) against a dead Redis.
  - Commit: `feat(queue): queues, connections and enqueue helper`

- [x] **T6.5 Readiness: Redis is now required**
  - `/api/ready` → **503** when Redis (producer connection ping) fails; keep DB check; add `queue` check (producer ping + `getQueueDepth()` under 2 s). Update Phase 4's "degraded" test accordingly. Add `closeQueues` to `shutdownHooks`.
  - Commit: `feat(server): redis required for readiness`

### Block B — Data-layer lifecycle (the correctness core)

- [x] **T6.6 `runRepo` lifecycle functions**
  - **Read first:** PG-LOCKS and PG-SKIP; `/tmp/skills-supabase/.../references/lock-*` (list, read the 1–2 that mention advisory/skip-locked). All SQL via `$queryRaw` tagged templates (bound params); enum comparisons inline as literals (`status = 'QUEUED'`), casts written explicitly (`$1::uuid`, `'QUEUED'::"RunStatus"`).
  - `createQueuedWithCap({ userId, tool, target, targetKey, options, quotaDate, cap })` — interactive transaction:
    ```sql
    SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0));            -- $1 = userId
    SELECT count(*)::int AS n FROM tool_runs WHERE user_id = $1::uuid AND status IN ('QUEUED','RUNNING');
    -- n >= cap  → return null (no insert);  else INSERT … status 'QUEUED' … RETURNING id, attempt
    ```
  - `claim({ runId, workerId })`:
    ```sql
    UPDATE tool_runs SET status='RUNNING', worker_id=$2, attempt=attempt+1,
           started_at=COALESCE(started_at, now()), heartbeat_at=now()
    WHERE id=$1::uuid AND status='QUEUED'
    RETURNING id, user_id, tool, target, target_key, options, attempt, quota_date;
    ```
  - `heartbeat({ runId, workerId, attempt, progressPct })`:
    ```sql
    UPDATE tool_runs SET heartbeat_at=now(), progress_pct=GREATEST(progress_pct,$4)
    WHERE id=$1::uuid AND status='RUNNING' AND worker_id=$2 AND attempt=$3
    RETURNING (cancel_requested_at IS NOT NULL) AS cancel_requested;       -- 0 rows ⇒ fenced out
    ```
  - `completeFenced` / `failFenced({ status ∈ COMPLETED|FAILED|TIMED_OUT|CANCELLED, … })`: **one transaction** — fenced `UPDATE` (adds `finished_at=now()`, `progress_pct`=100 for COMPLETED, `summary`, `error_code`, `error_message`); only if it returned a row, `INSERT INTO run_results … ON CONFLICT (run_id) DO UPDATE`. 0 rows → rollback, return `false`.
  - `cancelQueued(runId, userId)`: `UPDATE … SET status='CANCELLED', finished_at=now() WHERE id AND user_id AND status='QUEUED' RETURNING …`. `requestCancel(runId, userId)`: `SET cancel_requested_at=now() WHERE id AND user_id AND status='RUNNING' AND cancel_requested_at IS NULL`.
  - `reclaimStale({ stallSec, maxAttempts, limit })` (reaper) — single statement with `FOR UPDATE SKIP LOCKED`:
    ```sql
    WITH s AS (SELECT id FROM tool_runs WHERE status='RUNNING'
                 AND heartbeat_at < now() - make_interval(secs => $1)
               ORDER BY heartbeat_at LIMIT $2 FOR UPDATE SKIP LOCKED)
    UPDATE tool_runs t SET
      status      = CASE WHEN t.attempt < $3 THEN 'QUEUED'::"RunStatus" ELSE 'TIMED_OUT'::"RunStatus" END,
      worker_id   = NULL, heartbeat_at = NULL,
      queued_at   = CASE WHEN t.attempt < $3 THEN now() ELSE t.queued_at END,
      finished_at = CASE WHEN t.attempt < $3 THEN NULL  ELSE now() END,
      error_code  = CASE WHEN t.attempt < $3 THEN NULL  ELSE 'WORKER_LOST' END
    FROM s WHERE t.id = s.id
    RETURNING t.id, t.status, t.attempt, t.user_id, t.tool, t.quota_date;
    ```
  - `refundOnce(runId)` — transaction: `UPDATE tool_runs SET quota_refunded=true WHERE id=$1 AND quota_date IS NOT NULL AND NOT quota_refunded RETURNING user_id, tool, quota_date`; if a row came back, run the Phase 3 refund SQL with **that** date. Returns boolean.
  - Also: `findOrphanQueued(olderThanSec, limit)`, `failStaleQueued(olderThanSec, limit)` (→ `FAILED`, `QUEUE_TIMEOUT`), `findOverlong(maxRunSec, limit)`, `countQueuedBefore(queuedAt)`, `countActiveForUser(userId)`, `markEnqueueFailed(runId)`.
  - Commit: `feat(db): fenced run lifecycle, caps, reclaim and exactly-once refund`

- [x] **T6.7 `tests/db/run-lifecycle.test.js` — run every race for real**
  1. 20 parallel `createQueuedWithCap` for one user, cap 2 → **exactly 2** rows, 18 `null`.
  2. 10 parallel `claim` of one run → exactly **1** winner.
  3. `claim` vs `cancelQueued` in parallel (×50 iterations) → never both succeed.
  4. Fencing: claim as worker A; `reclaimStale` requeues; worker B claims (attempt 2); then A's `heartbeat`, `completeFenced`, `failFenced` all return fenced/false and **no `run_results` row is written**.
  5. `refundOnce` ×10 in parallel → exactly one `true`; `usage_counters.used` decreased by exactly 1; a run with `quota_date NULL` (ADMIN) → `false`.
  6. `reclaimStale`: fresh heartbeats untouched; attempt 1 → `QUEUED` (attempt kept, `queued_at` refreshed); attempt 2 → `TIMED_OUT` + `WORKER_LOST`; two concurrent calls never reclaim the same row twice (`SKIP LOCKED`).
  7. Every terminal transition sets `finished_at` (DB CHECK would reject otherwise); heartbeat returns `cancel_requested:true` after `requestCancel`.
  - Commit: `test(db): run lifecycle races and fencing`

- [x] **T6.8 Move Phase 5's sync path onto the same primitives**
  - `runRepo.start` now stores `quota_date` (from `req.quota.usageDate`; NULL for ADMIN/unlimited). `refundQuota(req)` becomes a thin wrapper over `refundOnce(runId)` (if no run row exists yet — failure before `start` — fall back to the old direct refund). Sync runs set `worker_id = 'inline:<pid>'`, `attempt = 1`, and use `completeFenced/failFenced` too.
  - All Phase 5 tests must still pass **unchanged** (they are the regression suite). Add one test: a sync run refunded twice (route + reaper) decrements once.
  - Commit: `refactor(tools): sync runs use fenced lifecycle and refundOnce`

### Block C — Execution engine and worker

- [x] **T6.9 `jobs/executeRun.js` — one executor for inline and worker**
  - Signature: `executeRun({ run, definition, signal, onProgress, deps })` → `{ status, data?, summary?, errorCode?, errorMessage? }`; **no DB writes** (callers persist). `ctx = { signal, reportProgress(pct, msg?), addresses, user, logger }`. `reportProgress` is synchronous and cheap (stores the latest value).
  - For `touchesTarget` tools: **re-run `validateTarget`** now (fresh pinned `addresses`); on policy failure follow §2 "Re-validation" (return `COMPLETED` + `data.error`, plus a `blocked:true` flag the caller uses for audit/cooldown/no-refund).
  - Enforces `definition.timeoutMs` (abort via `signal`), `capResult`, outcome mapping from the Phase 5 table. Phase 5 `runTool` is refactored to call this (sync path unchanged for clients).
  - Commit: `refactor(tools): shared executor with execution-time revalidation`

- [x] **T6.10 `worker/processor.js`**
  - `processor(job)`: `runId = job.data.runId` (validate UUID shape) → `claim()`; `null` ⇒ log + return (cancelled / already claimed / duplicate delivery).
  - Per-run `AbortController` registered in an in-memory map (for cancel nudges). Heartbeat timer every `WORKER_HEARTBEAT_SEC` (`unref()`): calls `heartbeat()` with the latest progress; **0 rows ⇒ abort with reason `fenced` and stop — never write again**; `cancel_requested:true` ⇒ abort with reason `cancelled`. DB errors in heartbeat are counted (`cst_heartbeat_failures_total`) and tolerated up to `RUN_STALL_SEC/2`, then abort.
  - After `executeRun`: `completeFenced`/`failFenced`; if refund applies (kind rules in §2) → `refundOnce`; on `blocked` → audit + `recordBlocked`; on `cancelled` → `failFenced(status:'CANCELLED')` without refund. `finally`: clear timer, delete from map.
  - **The processor never throws for expected outcomes** (DB is authoritative). A last-resort `catch` tries `failFenced(FAILED, INTERNAL)` + refund, logs, and returns.
  - Redis events (fire-and-forget, never awaited on the hot path): publish to `cst:run:<runId>` `{type:'progress'|'status', …}` — the Phase 8 SSE endpoint will consume these. Cancel nudges: one subscriber connection on `cst:cancel` maps `runId` → `abort('cancelled')`.
  - Metrics: `cst_run_queue_wait_seconds{tool}` (`started_at - queued_at`), `cst_worker_active_runs`, `cst_fenced_total{op}`.
  - Commit: `feat(worker): job processor with heartbeat, fencing and cancellation`

- [x] **T6.11 `worker/index.js`, `worker.js`, health server, scripts**
  - `startWorker({ concurrency })`: BullMQ `Worker('runs', processor, { connection: workerConn, concurrency, lockDuration: 60000, stalledInterval: 15000, maxStalledCount: 0 })` (verify names in the installed docs). Listen to `stalled` (log + `cst_worker_stalled_total`), `failed`, `error`. `workerId = hostname:pid:random4` (also stored in `worker_id`).
  - Also starts the `maintenance` worker (concurrency 1) when `MAINTENANCE_ENABLED` (processor added in Block E).
  - `stopWorker({ graceMs })`: stop fetching (`worker.close()` in the background), wait up to `WORKER_SHUTDOWN_GRACE_MS` for active runs; **runs still active after the grace** get `abort('shutdown')` and are **requeued immediately** (`requeueOwn(runId, workerId, attempt)` — fenced `UPDATE … SET status='QUEUED', worker_id=NULL …`, then `enqueueRun` with the next attempt id) so another worker takes over without waiting for the reaper. Exit code 0.
  - `src/worker.js`: boots env, DB, Redis, calls `startWorker`, wires SIGINT/SIGTERM and unhandled errors (same pattern as `server.js`); tiny HTTP server on `WORKER_HEALTH_PORT` bound to `127.0.0.1`: `/health` (200), `/ready` (DB+Redis), `/metrics` (same bearer-token rule as Phase 4).
  - `server.js`: if `RUN_EMBEDDED_WORKER` → `startWorker()` in-process + shutdown hook (dev convenience; refuse `true` in production at env validation).
  - Scripts: `dev:worker` (`node --watch src/worker.js`), `start:worker`; document in the commit body how root `npm run dev` behaves (embedded worker on).
  - Commit: `feat(worker): worker runtime, graceful shutdown, health server`

- [x] **T6.12 `tests/integration/worker.test.js` (real Redis + Postgres, in-process worker)**
  - Test helpers: `tests/helpers/asyncTestTool.js` registers a **test-only** async tool (`sleep` with configurable ms, progress steps, failure modes) through definition injection — never present in `src/`.
  - Cases: happy path (QUEUED→RUNNING→COMPLETED, result + summary stored, progress persisted); duplicate delivery of the same run via two different job ids → executed once; cancelled-before-start job skipped; tool throws → `FAILED` + refunded once; hard timeout → `TIMED_OUT` + refund; **target flips to private between submit and run** (stub resolver) → `COMPLETED` with `data.error`, audit row, **no refund**; fenced-out worker (requeue mid-run) stops within one heartbeat and writes nothing; queue wait metric recorded; events published on `cst:run:<id>`.
  - Commit: `test(worker): processor behavior`

### Block D — Async API

- [x] **T6.13 Async mode in `toolRoute`**
  - Tool definition gains `mode: 'sync' | 'async' | 'auto'` and optional `asyncWhen(input) → boolean` (for `auto`). Async flow = the admission order in §2. Success → **`202`** with header `Location: /api/runs/<id>` and body `{ runId, tool, target, status:'QUEUED', pollUrl, pollAfterMs: 1500, quota }`.
  - Priority: PAID/ADMIN 1, FREE 10. Cap from env by tier. `QUEUE_FULL` → 503 with `Retry-After: 30` and **no** quota used. Cap hit → refund + `429 TOO_MANY_ACTIVE_RUNS`. Enqueue failure → `markEnqueueFailed` + refund + 503.
  - **`Idempotency-Key`** (async only; `^[A-Za-z0-9_-]{8,64}$`): claim `SET cst:idem:<userId>:<sha256(tool|key)> pending NX EX 86400` **before** quota; loser of a race → `409 IDEMPOTENCY_IN_PROGRESS` (`Retry-After: 1`); after the run row exists store the runId; a replay returns the current run state with header `Idempotent-Replayed: true` and uses **no** quota; any failure path deletes the key.
  - Commit: `feat(tools): async submission with caps, backpressure and idempotency`

- [x] **T6.14 Runs API for async**
  - `GET /api/runs/:id` adds `progressPct`, `pollAfterMs` (1500 QUEUED/RUNNING, none when terminal), `queuePosition` (QUEUED only, approximate, via `countQueuedBefore`), `data` **only** when `COMPLETED`, `error {code,message}` when `FAILED/TIMED_OUT`.
  - `POST /api/runs/:id/cancel`: QUEUED → `cancelQueued` + remove BullMQ job (ignore "not found") + `refundOnce` → `200 {status:'CANCELLED'}`; RUNNING → `requestCancel` + pub/sub nudge → `202 {status:'RUNNING', cancelRequested:true}`; terminal → `409 RUN_NOT_CANCELLABLE`; others' runs → **404**.
  - `GET /api/runs?status=QUEUED|RUNNING|…` filter (active-runs panel for the dashboard).
  - Commit: `feat(server): async run polling, cancel and status filter`

- [x] **T6.15 Ping becomes async above 20 packets**
  - Schema `count` 1–100 (default 4); ping definition `mode:'auto'`, `asyncWhen = count > 20`; worker reports progress per packet (`i/count`). Update `docs/api-tools.md` (remove the Phase 5 deviation note) and Phase 5 ping tests (count 21 returns 202).
  - Commit: `feat(tools): ping up to 100 packets via the queue`

- [x] **T6.16 `tests/api/async-runs.test.js`, `cancel.test.js`, `idempotency.test.js` (embedded worker + test tool)**
  - submit → poll until `COMPLETED` → `data` present; `Location` header correct.
  - Cap: PAID-like high quota, cap 2, **3 simultaneous submissions** → 2×202 and 1×429 `TOO_MANY_ACTIVE_RUNS`; quota refunded for the loser.
  - Queue full (`QUEUE_MAX_WAITING=1`) → 503 `QUEUE_FULL`, quota unchanged.
  - Cancel QUEUED → refunded + never executed (execute counter 0); cancel RUNNING → ends `CANCELLED` within one heartbeat, **no** refund; terminal → 409; other user's run → 404 for poll and cancel.
  - Priority: concurrency 1, enqueue FREE then PAID → PAID runs first.
  - Idempotency: same key twice sequentially → same `runId`, quota used once; 10 parallel same-key requests → exactly one run, the rest 202-replay or 409; key on a failed submission is released.
  - Responses never contain `worker_id`, Redis keys or stack traces.
  - Commit: `test(tools): async submission, cancel, idempotency`

### Block E — Reaper and retention

- [x] **T6.17 `maintenance/scheduler.js`**
  - On startup (maintenance worker owner), `upsertJobScheduler` on the `maintenance` queue (BULLMQ-SCHED; v6 uses `tz:'UTC'`, no legacy repeatable APIs): `reaper` every 30 000 ms; `retention` cron `0 30 3 * * *` UTC; `cache-sweep` every 3 600 000 ms. Idempotent upsert (safe on every boot). Scheduler → exactly one execution cluster-wide; every job body is still idempotent.
  - Processor router by job name; unknown names ignored with a warning.
  - Commit: `feat(maintenance): job schedulers`

- [x] **T6.18 `maintenance/reaper.js`** — one pass, four steps, each batch ≤ 100:
  1. **Stale RUNNING**: `reclaimStale`. For rows now `QUEUED` → `enqueueRun({attempt})` (+ metric `reason:"stale_requeued"`); for `TIMED_OUT` → `refundOnce` (`reason:"worker_lost"`).
  2. **Orphan QUEUED** (`queued_at < now() - ORPHAN_QUEUED_SEC` and `queue.getJob(runId-attempt)` is null) → re-enqueue (idempotent jobId) (`reason:"orphan_requeued"`). This also repairs a Redis flush.
  3. **QUEUED too long** (`QUEUE_MAX_WAIT_SEC`) → `failStaleQueued` + `refundOnce` (`QUEUE_TIMEOUT`).
  4. **Overlong RUNNING** (`started_at < now() - 2 × tool timeout`, even if heartbeating) → fenced `TIMED_OUT` + refund; the zombie is fenced out on its next heartbeat.
  - Metric `cst_reaper_reclaimed_total{reason}`; one audit row `system.reaper` **only if** something was reclaimed (counts only, no user data).
  - Commit: `feat(maintenance): reaper`

- [x] **T6.19 `tests/integration/reaper.test.js` (accelerated: heartbeat 1 s, stall 3 s)**
  - **Kill -9 test:** `tests/helpers/workerProcess.js` forks a real worker process; start a long run; `SIGKILL` it mid-run; within ~`stall+reaper interval` the run is requeued (attempt 2), a second worker completes it **exactly once** (execute counter = 2 total starts, 1 completion), quota unchanged.
  - Attempts exhausted (kill both) → `TIMED_OUT` `WORKER_LOST` + refunded exactly once.
  - Orphan QUEUED row (inserted with no BullMQ job) → re-enqueued and processed. QUEUED too long → `FAILED` `QUEUE_TIMEOUT` + refund. Heartbeating run untouched. Overlong run → `TIMED_OUT`.
  - Two reaper passes in parallel → every run reclaimed once.
  - Commit: `test(maintenance): crash recovery with real process kill`

- [x] **T6.20 `maintenance/retention.js` + `cache-sweep`**
  - **Read first:** PG-BRIN, `DATABASE-DESIGN.md` §8.
  - Loop up to `RETENTION_MAX_BATCHES` batches of `RETENTION_BATCH_SIZE`, `100 ms` pause:
    ```sql
    DELETE FROM tool_runs WHERE id IN (
      SELECT r.id FROM tool_runs r JOIN users u ON u.id = r.user_id
      WHERE r.status IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT')
        AND ((u.tier='FREE' AND r.created_at < $1) OR (u.tier IN ('PAID') AND r.created_at < $2))
      ORDER BY r.created_at LIMIT $3);
    ```
    (children cascade). Then `usage_counters` (`usage_date < …`), `webhook_events` (`received_at < …`) in the same batched style.
  - `cache-sweep`: delete `service_cve_lookups` where `expires_at < now()`; delete `cves` where `expires_at < now()` **and** `NOT EXISTS (SELECT 1 FROM finding_cves WHERE cve_id = cves.id)` (FK is `RESTRICT`).
  - `RETENTION_DRY_RUN=true` → count only. Metric `cst_retention_deleted_total{table}`; one audit row `system.retention` with counts.
  - Commit: `feat(maintenance): batched retention and cache sweep`

- [x] **T6.21 `tests/db/retention.test.js`**
  - FREE vs PAID cutoffs honored; **active (QUEUED/RUNNING) runs never deleted** even if ancient; cascades remove results/findings/reports; recent rows untouched; referenced CVE kept, unreferenced expired CVE deleted; dry run deletes nothing but reports counts; stops at max batches and a second run continues; idempotent; plan check on ≥ 100k rows (`EXPLAIN`): no full sequential scan driven by `created_at`.
  - Commit: `test(maintenance): retention and cache sweep`

### Block F — Observability, drills, load

- [x] **T6.22 Metrics and ops runbook**
  - Gauges `cst_queue_jobs{queue,state}` (refresh 10 s from `getJobCounts`), `cst_runs_active{status}` (DB count via the partial index, refresh 15 s), counters from earlier tasks all registered with **enumerated labels**. Cardinality test extended (no runId/userId in labels).
  - Write `docs/ops-queue.md` (≤ 80 lines): what each metric means, healthy ranges, runbooks for *queue growing*, *runs stuck RUNNING*, *Redis flushed/restarted* (what the reaper does automatically), *worker crash loop*, *retention backlog*.
  - Commit: `feat(obs): queue and run metrics with runbook`

- [x] **T6.23 Drill: Redis data loss (`tests/integration/redis-loss.test.js`)**
  - With QUEUED and RUNNING runs present, `FLUSHALL` the test Redis (guard: DB index 1 / prefix check). Expected: the live worker's **DB-based** heartbeats and fenced completion still finish its RUNNING run **exactly once**; QUEUED runs are re-enqueued by the reaper within one interval and complete; nothing lost, nothing executed twice (counter), no quota drift.
  - Commit: `test(queue): redis flush recovery drill`

- [x] **T6.24 Drill: graceful deploy (`tests/integration/shutdown.test.js`, real worker process)**
  - `SIGTERM` during a short run (2 s, grace 25 s) → run completes, exit code 0. `SIGTERM` during a long run with a short grace → the run is **requeued immediately** (attempt+1), a second worker completes it; exit code 0; no leaked handles/timers; quota unchanged.
  - Commit: `test(worker): graceful shutdown and handoff`

- [x] **T6.25 Load test (`tests/integration/load.test.js`, skipped unless `LOAD_TESTS=1`)**
  - 200 async runs (stub tool 200 ms) from 20 users, 3 worker processes × concurrency 10: all reach a terminal state; sampled **active count per user never exceeds the cap**; p95 queue wait < 5 s; DB pool `waiting` stays 0 at steady state; heap after forced GC grows < 20 % between first and last quartile; print a throughput table (runs/s) in the report.
  - Commit: `test(queue): load and cap-under-load`

### Block G — Close-out

- [x] **T6.26 Security review (report each finding, fix, re-test)**
  - Job payload is `{runId}` only; processor validates UUID shape and **loads everything else from Postgres** (never trusts payload). No user-controlled string reaches a Redis key, job id or raw SQL (grep `queryRawUnsafe` → zero hits). `hashtextextended` advisory-lock key derived from the UUID only.
  - Cancel/poll/list queries all include `user_id` (IDOR tests exist). Worker health server binds `127.0.0.1`; `/metrics` requires the token. Admin/unlimited runs create **no** quota rows and are never "refunded" (`quota_date` NULL).
  - Mutation checks (revert after each; each must be caught by a test): remove the `AND worker_id/attempt` fencing → T6.7 fails; remove `NOT quota_refunded` → T6.7 fails; remove `SKIP LOCKED` → T6.7/T6.19 fail; drop re-validation in `executeRun` → T6.12 fails.
  - Commit only if fixes were needed: `fix(queue): review findings`

- [x] **T6.27 Docs and final verification**
  - `docs/queue-architecture.md` (≤ 100 lines): the state machine as a **mermaid** diagram, who decides each transition, the guard SQL (link to `runRepo`), failure matrix (worker dies / Redis flushed / API dies between insert and enqueue / duplicate delivery / zombie worker), admission order, retention table. Update `docs/tool-route-contract.md` (async mode, `202`, idempotency, re-validation rule for tool authors) and `docs/api-tools.md`.
  - Run all suites (unit, db, api, integration; load only if you can) and report counts. Manual: `npm run dev:worker` in a second terminal with `RUN_EMBEDDED_WORKER=false`; submit `POST /api/tools/ping` with `count:50`, poll to completion, cancel another one, `kill -9` the worker during a third and watch it recover (paste the three status timelines).
  - `git log --oneline | head -n 40`; `tree server/src -L 2`.

---

## 5. Definition of Done (Phase 6)

- [x] 27 tasks ticked, one commit each; no secrets in git or logs.
- [x] All races in T6.7 are **tested by running the race** and pass reliably (run that file 5× in a row, no flakes).
- [x] `kill -9` of a worker mid-run recovers automatically: one completion, correct quota, no human action.
- [x] A Redis flush loses no run and executes none twice.
- [x] Per-user active cap holds under load; queue backpressure returns 503 without consuming quota.
- [x] Refund happens **exactly once** per run across API, worker and reaper paths.
- [x] Execution-time target re-validation proven by test; zombie workers cannot write results.
- [x] Retention deletes only expired, terminal rows in batches; referenced CVEs survive.
- [x] Redis required for readiness; worker has its own health/metrics endpoint; graceful deploy drill passes.
- [x] Phase 5 tests pass unchanged; zero Python; `client/` untouched.

**When finished, report:** BullMQ version, test counts per suite, the kill -9 recovery timeline, load-test throughput + p95 queue wait, and every mutation-test result. Then wait for the Phase 7 file (heavy tools: TCP port scanner, banner grabbing and service detection, subdomain discovery, traceroute, web-app scanner, CVE lookup via NVD — all as async jobs on this runtime).
