# Database benchmark — 1M runs / 3M findings

Proof that the indexes in `IMPLEMENTATION/DATABASE-DESIGN.md` §3 satisfy the §6
performance budget at the target scale. Reproduce with:

```bash
# One-time: create + migrate a disposable bench database
docker compose exec db psql -U cybersec -d cybersec -c 'CREATE DATABASE cybersec_bench'
DATABASE_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec_bench \
DIRECT_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec_bench \
  npm run db:deploy --workspace server

# Seed (in-Postgres generate_series) and run the EXPLAIN suite
DATABASE_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec_bench \
  node server/scripts/bench-seed.js --all
```

The script refuses any database whose name does not end in `_bench` or `_test`.

## Environment

| Item | Value |
|---|---|
| PostgreSQL | 17 (`postgres:17` container) |
| Prisma | 7.10.1 |
| Host | local Docker, default settings (not tuned for the benchmark) |

## Seeded data

| Table | Rows | Notes |
|---|---|---|
| `users` | 1,000 | |
| `tool_runs` | 1,000,100 | 1,000,000 `COMPLETED` + 100 `RUNNING` for Q6 |
| `port_findings` | 3,000,000 | spread over the `PORT_SCAN` runs, unique `(run_id, port, protocol)` |

`tool_runs.created_at` is random within the last 90 days and ids use
`gen_random_uuid()`. Postgres 17 has no `uuidv7()`, so this is a **pessimistic**
index-locality case: real writes use UUIDv7 and insert near the end of the index,
which benchmarks at least as well as this random-uuid layout.

The 100 extra `RUNNING` rows are added on top of the specified 1M `COMPLETED`
set so Q6 exercises the partial index against real live-job rows instead of an
empty index.

`VACUUM (ANALYZE)` is run on `tool_runs`, `port_findings`, `users` and
`usage_counters` before measuring.

## Results

`EXPLAIN (ANALYZE, BUFFERS)`, warm cache. Q2 runs the real atomic upsert forced
onto the `ON CONFLICT UPDATE` path inside a rolled-back transaction.

| Query | Required plan (§6) | Observed top node | Exec | Budget | Result |
|---|---|---|---:|---:|---|
| Q1 user by clerk id | Index Scan on `users_clerk_user_id_key` | `Index Scan using users_clerk_user_id_key on users` | 0.019 ms | < 1 ms | **PASS** |
| Q2 quota consume | Index Scan / ON CONFLICT on PK | `Insert on usage_counters` → `Conflict Arbiter Indexes: usage_counters_pkey`, `Conflicting Tuples: 1` | 0.125 ms | < 2 ms | **PASS** |
| Q3 history page (first) | Index Scan `(user_id, created_at, id)`, no Sort | `Limit → Index Scan using tool_runs_user_id_created_at_id_idx` | 0.097 ms | < 3 ms | **PASS** |
| Q3 history page (deep keyset) | Index Scan `(user_id, created_at, id)`, no Sort | `Limit → Index Scan using tool_runs_user_id_created_at_id_idx` | 0.102 ms | < 3 ms | **PASS** |
| Q5 dedupe lookup | Index Scan, `LIMIT 1` | `Limit → Index Scan using tool_runs_user_id_tool_target_key_created_at_idx` | 0.021 ms | < 2 ms | **PASS** |
| Q6 stale running jobs | Index Scan on partial index | `Limit → Index Scan using ix_tool_runs_running_heartbeat` | 0.029 ms | < 2 ms | **PASS** |
| Q8 findings of a run | Index Scan `(run_id, port, protocol)`, no Sort | `Index Scan using port_findings_run_id_port_protocol_key` | 0.023 ms | < 3 ms | **PASS** |

- No `Seq Scan` on `tool_runs`, `port_findings`, or `usage_counters`.
- No `Sort` node in Q3 or Q8.
- Every query is well under its budget (worst case ≈ 0.13 ms vs 2 ms).

Q3 deep keyset uses a cursor from the 800th row of a ~997-row user history, so
the planner estimates `rows=1` while 20 are returned; the access path is still a
plain index scan with no sort, which is what the budget requires.

## Notes / deviations

- 1,000,100 `tool_runs` (not exactly 1,000,000) because of the Q6 `RUNNING`
  slice. No schema change was needed; no index was added as a result of this run.
