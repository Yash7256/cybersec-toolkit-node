# Queue operations

Postgres is authoritative. Redis/BullMQ is a delivery mechanism: every state
transition is fenced in SQL by `run_id + worker_id + attempt`, so a lost or
duplicated job cannot double-complete a run.

## Metrics

| Metric | Meaning | Healthy |
|---|---|---|
| `cst_queue_jobs{queue,state}` | BullMQ counts, refreshed every 10 s | `waiting` near 0 at steady state |
| `cst_runs_active{status}` | `QUEUED`/`RUNNING` rows, refreshed every 15 s | bounded by caps |
| `cst_tool_runs_total{tool,outcome}` | Executions by outcome | mostly `success` |
| `cst_tool_run_duration_seconds` | Execution latency | stable p95 |
| `cst_db_pool_waiting` | Clients waiting for a connection | 0 |
| `cst_eventloop_lag_p99_seconds` | Event loop delay | < 0.1 s |
| `cst_worker_stalled_total` | BullMQ stalled events | 0 |
| `cst_breaker_open_total{name}` | Upstream circuit openings | occasional |

Scrape `/metrics` with `Authorization: Bearer $METRICS_TOKEN`. The worker health
server binds `127.0.0.1:$WORKER_HEALTH_PORT` and exposes `/health`, `/ready`
(DB + Redis), and `/metrics`.

## Runbooks

### Queue growing

1. Check `cst_queue_jobs{state="waiting"}` and `cst_runs_active{status="QUEUED"}`.
2. Check worker health (`/ready`) and logs for crash loops.
3. Scale worker replicas (`WORKER_CONCURRENCY`) or reduce submissions.
4. If `QUEUE_MAX_WAITING` is hit, clients receive `503 QUEUE_FULL` with
   `Retry-After: 30`; quota is refunded.

### Runs stuck RUNNING

1. Compare `heartbeat_at` with `RUN_STALL_SEC`.
2. The reaper requeues stale runs while `attempt < RUN_MAX_ATTEMPTS`; after that
   it marks them `TIMED_OUT` / `WORKER_LOST` and refunds once.
3. Runs exceeding twice `TOOL_HARD_TIMEOUT_MS` are timed out by the reaper.

### Redis flushed or restarted

1. RUNNING runs keep heartbeating and complete through the DB-fenced path.
2. The reaper re-enqueues orphaned `QUEUED` rows (`ORPHAN_QUEUED_SEC`) and
   BullMQ rebuilds its queue.
3. Verify no run executed twice via `cst_tool_runs_total` and the execute
   counter in the drill test.

### Worker crash loop

1. Inspect worker logs and exit code; confirm `/ready` reports DB and Redis.
2. Roll back the last deploy if failures repeat.
3. Stalled jobs are reclaimed automatically; no manual requeue is required.

### Retention backlog

1. Check `cst_retention_deleted_total{table}` and maintenance logs.
2. Retention runs in bounded batches (`RETENTION_BATCH_SIZE`,
   `RETENTION_MAX_BATCHES`); a second pass continues where the first stopped.
3. Use `RETENTION_DRY_RUN=true` to measure before deleting.

## Graceful deploy

`SIGTERM` stops fetching, waits `WORKER_SHUTDOWN_GRACE_MS`, then aborts and
immediately requeues still-active runs with the next attempt so another worker
takes over. Exit code is `0`.
