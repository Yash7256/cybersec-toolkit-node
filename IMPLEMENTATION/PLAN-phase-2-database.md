# PHASE 2 — Database (PostgreSQL + Prisma) 

> **For OpenCode.** Prerequisite: Phase 1 is finished (all boxes in `PLAN-phase-1-foundation.md` ticked, tests green).
> Companion file: **`DATABASE-DESIGN.md`** — the schema, SQL and performance budget. **Copy from it, never improvise the schema.**
> Project: monorepo `CyberSec-Toolkit`, server in `server/` (Express, ESM, JavaScript). **Never touch `client/`. Never write Python.**

---

## 0. Working rules (your context window is small — obey these)

1. Do **one task** at a time, tick its `[x]` here, commit, **stop and report in ≤ 10 lines**, wait for "next".
2. Do NOT read the whole repo or the whole design file. Each task names the exact section of `DATABASE-DESIGN.md` to read (use `sed -n` / `grep -n '^## '` to find it).
3. Pipe long output through `tail -n 20`. Never print generated Prisma client files.
4. Fetch skill rule files ONLY when a task says so, and read ONLY the named file.
5. One commit per task, message given in the task.
6. If verification fails twice → stop, report the exact error, do not redesign.
7. Never run `prisma db push`, never `migrate reset` against anything except the local dev or test database.

### 0.1 Skill / reference registry (all verified to exist)

```bash
git clone --depth 1 https://github.com/prisma/skills /tmp/skills-prisma
find /tmp/skills-prisma -name SKILL.md          # skills: prisma-cli, prisma-client-api, prisma-database-setup, prisma-upgrade-v7
git clone --depth 1 https://github.com/supabase/agent-skills /tmp/skills-supabase
ls /tmp/skills-supabase/skills/supabase-postgres-best-practices/references | head -n 80
#   rule-file prefixes: query-*  conn-*  security-*  schema-*  (lock/concurrency, data-access, monitoring, advanced)
git clone --depth 1 https://github.com/mcollina/skills /tmp/skills-mcollina
#   /tmp/skills-mcollina/skills/node/rules/{testing,graceful-shutdown,environment,error-handling}.md
```

Docs (fetch only the page a task names). **Any Prisma docs page can be read as markdown by appending `.md`:**

| Short name | URL |
|---|---|
| PRISMA-INDEX | https://www.prisma.io/docs/llms.txt |
| PRISMA-SKILLS | https://www.prisma.io/docs/ai/tools/skills.md |
| PRISMA-CHANGELOG | https://www.prisma.io/changelog.md |
| PG-EXPLAIN | https://www.postgresql.org/docs/current/using-explain.html |
| PG-INDEXES-PARTIAL | https://www.postgresql.org/docs/current/indexes-partial.html |
| PG-INSERT-CONFLICT | https://www.postgresql.org/docs/current/sql-insert.html |
| SUPABASE-PRISMA | https://supabase.com/docs/guides/database/prisma |

> Prisma changes fast. **Before writing any Prisma config, read the installed version and the matching skill (`prisma-database-setup`).** Where this plan and the skill disagree on config syntax, the skill wins; where they disagree on the MODELS, `DATABASE-DESIGN.md` wins.

---

## 1. Target structure (end of Phase 2)

```
docker-compose.yml                 # local Postgres 17 (dev + test DBs)   [if using local DB]
server/
  prisma.config.ts|js              # per installed Prisma version
  prisma/
    schema.prisma
    migrations/                    # generated; committed
    seed.js
  src/
    db/
      client.js                    # PrismaClient singleton + disconnect
      repos/
        userRepo.js
        usageRepo.js
    generated/prisma/              # generated client (gitignored)
  scripts/
    bench-seed.js                  # 1M-row benchmark
  tests/
    setup/globalSetup.js
    db/usage.test.js
    db/constraints.test.js
    db/users.test.js
    db/ready.test.js
docs/
  database.md                      # short ops notes (written in T2.21)
  db-benchmark.md                  # EXPLAIN results (written in T2.20)
```

---

## 2. Tasks

### Block A — Environment, skills, packages

- [x] **T2.1 Orientation (read-only)**
  - Read `DATABASE-DESIGN.md` sections **1** and **3** only. Clone the three skill repos from §0.1.
  - Read `/tmp/skills-prisma/**/prisma-database-setup/SKILL.md` fully. Skim the file list of `/tmp/skills-supabase/.../references/` and note which `schema-*` and `conn-*` files exist.
  - Report: installed Node version, whether `docker` is available (`docker -v`), and the Prisma major version the skill targets.
  - No commit.

- [x] **T2.2 Provision Postgres (choose ONE; ask the user which if unclear)**
  - **Option A — local Docker (recommended for dev/test).** Create root `docker-compose.yml`: service `db` image `postgres:17`, env `POSTGRES_USER=cybersec POSTGRES_PASSWORD=cybersec POSTGRES_DB=cybersec`, port `5432:5432`, named volume, `healthcheck: pg_isready -U cybersec`. Add an init script mounted into `/docker-entrypoint-initdb.d/` that also creates database `cybersec_test`.
    - Run `docker compose up -d db`, then wait for healthy.
    - URLs: `DATABASE_URL=postgresql://cybersec:cybersec@localhost:5432/cybersec` , `DIRECT_URL` = same, `TEST_DATABASE_URL=postgresql://cybersec:cybersec@localhost:5432/cybersec_test`.
  - **Option B — Supabase (a NEW empty project; do not reuse the old project's database).** Read SUPABASE-PRISMA. `DATABASE_URL` = pooled (transaction mode, port 6543), `DIRECT_URL` = direct connection (port 5432). The user must paste these; never invent or commit them.
  - Put the values in `server/.env` ONLY (gitignored). Verify the connection with `node -e` + `pg`, or `docker compose exec db psql -U cybersec -c 'select version()'`.
  - Commit: `chore(db): local postgres via docker compose` (Option A only; Option B has nothing to commit).

- [x] **T2.3 Install and initialize Prisma**
  - Follow the `prisma-database-setup` skill for the installed major version. Typically: `prisma` (dev), `@prisma/client`, and a driver adapter such as `@prisma/adapter-pg` + `pg`.
  - Create `prisma/schema.prisma` containing ONLY the `generator` and `datasource` blocks from `DATABASE-DESIGN.md` §4 (adjusted per skill) and the Prisma config file the version requires (datasource URL from `DIRECT_URL` for CLI/migrations).
  - Add `src/generated/` to `.gitignore`.
  - Verify: `npx prisma validate --schema server/prisma/schema.prisma` (path per your workspace) passes with an empty model set.
  - Commit: `chore(db): install prisma and base config`

- [x] **T2.4 Extend env validation (`src/config/env.js`)**
  - Add: `DATABASE_URL` (required, must start with `postgres://` or `postgresql://`), `DIRECT_URL` (required), `DB_POOL_MAX` (int, default 10), `DB_STATEMENT_TIMEOUT_MS` (int, default 10000), `DB_IDLE_TX_TIMEOUT_MS` (int, default 15000).
  - Update `server/.env.example` with all new vars and comments (use placeholder values, never real credentials).
  - Update `tests/env.test.js`: missing `DATABASE_URL` throws with a readable message; defaults applied.
  - **Vitest `test.env`** (in `vitest.config.js`) must now set a dummy `DATABASE_URL`/`DIRECT_URL` so Phase 1 tests keep passing.
  - Verify: `npm test --workspace server -- --reporter=dot 2>&1 | tail -n 15` green.
  - Commit: `feat(server): database env vars`

### Block B — Schema in small slices (each slice = edit schema → `migrate dev` → verify)

> Migration command pattern (from `server/`): `npx prisma migrate dev --name <name>`. Verify tables with `docker compose exec db psql -U cybersec -c '\d <table>'` or `npx prisma db execute --stdin` with `select ...`. After each slice run `git status --short | head` to confirm a new folder appeared in `prisma/migrations/`.

- [ ] **T2.5 Enums + `users`**
  - From `DATABASE-DESIGN.md` §4 copy: all 8 **enums** and `model User`. (Other models referenced by User's relation fields — `ToolRun`, `UsageCounter`, `Report`, `AuditLog` — are added in later tasks: for now **omit those relation lines** from `User`, then re-add them as each model arrives.)
  - Migrate: `init_users_and_enums`.
  - Verify: `\d users` shows `clerk_user_id` UNIQUE, `email` UNIQUE, timestamptz columns; `\dT` lists the enums.
  - Commit: `feat(db): enums and users table`

- [ ] **T2.6 `usage_counters`**
  - Copy `model UsageCounter` + re-add `usageCounters UsageCounter[]` on User. Migrate: `add_usage_counters`.
  - Verify: composite PK `(user_id, tool, usage_date)` and FK `ON DELETE CASCADE` in `\d usage_counters`.
  - Commit: `feat(db): usage_counters`

- [ ] **T2.7 `tool_runs` + `run_results`**
  - Copy both models + `toolRuns ToolRun[]` on User. Temporarily omit `findings` and `reports` relation fields on `ToolRun` (added in T2.8 / T2.10). Migrate: `add_tool_runs`.
  - Verify: the three composite indexes exist with `created_at DESC` ordering (`\d tool_runs`).
  - Commit: `feat(db): tool_runs and run_results`

- [ ] **T2.8 `port_findings`**
  - Copy `model PortFinding`; re-add `findings PortFinding[]` on ToolRun. Temporarily omit `cves` relation on PortFinding. Migrate: `add_port_findings`.
  - Verify: unique index `(run_id, port, protocol)`; `id` is `bigint` identity.
  - Commit: `feat(db): port_findings`

- [ ] **T2.9 CVE tables**
  - Copy `Cve`, `FindingCve`, `ServiceCveLookup`; re-add `cves FindingCve[]` on PortFinding. Migrate: `add_cve_tables`.
  - Verify: `finding_cves` PK `(finding_id, cve_id)` + index on `cve_id`; `cves.cvss_score` is `numeric(3,1)`.
  - Commit: `feat(db): cve tables`

- [ ] **T2.10 `reports`**
  - Copy `Report`; re-add `reports Report[]` on both User and ToolRun. Migrate: `add_reports`.
  - Commit: `feat(db): reports`

- [ ] **T2.11 `webhook_events` + `audit_logs`**
  - Copy both; re-add `auditLogs AuditLog[]` on User. Migrate: `add_webhook_and_audit`.
  - Verify: BRIN index on `audit_logs(created_at)` (`\d audit_logs` shows `USING brin`); `ip` is `inet`.
  - Commit: `feat(db): webhook_events and audit_logs`

- [ ] **T2.12 Raw-SQL invariants migration**
  - **Read first** (one file each): `/tmp/skills-supabase/.../references/` → the `security-*` RLS file and one `schema-*` constraints/indexing file; PG-INDEXES-PARTIAL.
  - Run `npx prisma migrate dev --create-only --name db_invariants`, then paste the entire SQL block of `DATABASE-DESIGN.md` §5 into the generated `migration.sql`, then apply with `npx prisma migrate dev`.
  - Verify with psql: `\d tool_runs` lists the 2 partial indexes and 5 CHECK constraints; `select relname, relrowsecurity from pg_class where relname in ('users','tool_runs','audit_logs');` all `t`.
  - Commit: `feat(db): check constraints, partial indexes, RLS, autovacuum tuning`

- [ ] **T2.13 Whole-schema audit**
  - `npx prisma validate`, `npx prisma migrate status` (must say "Database schema is up to date"), `npx prisma generate`.
  - Compare against the design: list tables with `\dt` — expected exactly **11**: `users usage_counters tool_runs run_results port_findings cves finding_cves service_cve_lookups reports webhook_events audit_logs` (+ `_prisma_migrations`). Report any difference.
  - Prove idempotency: drop and recreate the DEV database (`npx prisma migrate reset --force`) and confirm all migrations replay cleanly from zero.
  - Commit only if something needed fixing: `fix(db): schema audit fixes`

### Block C — Runtime client & first repositories

- [ ] **T2.14 `src/db/client.js`**
  - **Read first:** `prisma-client-api` skill (client instantiation, adapters) and `/tmp/skills-supabase/.../references/conn-*` (pool sizing).
  - Export a singleton `prisma` created once (module-level), using the driver adapter with a `pg` Pool: `max = env.DB_POOL_MAX`, `statement_timeout = env.DB_STATEMENT_TIMEOUT_MS`, `idle_in_transaction_session_timeout = env.DB_IDLE_TX_TIMEOUT_MS`, `connectionTimeoutMillis: 5000`.
  - Export `disconnect()` (ends client and pool) and `pingDb({ timeoutMs = 2000 })` which runs `SELECT 1` and rejects on timeout.
  - Log only `warn`/`error` Prisma events through the existing pino logger; never log query parameters.
  - Commit: `feat(db): prisma client singleton`

- [ ] **T2.15 Repositories (`src/db/repos/`)**
  - `userRepo.js`: `findByClerkId(clerkUserId)`; `upsertFromClerk({ clerkUserId, email })` (lower-case the email; **idempotent**: same input twice → one row); `softDelete(id)` (sets `deletedAt`, `isActive=false`, **`email = null`**).
  - `usageRepo.js`:
    - `consume({ userId, tool, limit })` → returns `{ allowed: boolean, used: number }` using `prisma.$queryRaw` with the **exact statement from `DATABASE-DESIGN.md` §3 "Atomic quota consumption"** (tagged template, parameters bound — NO string concatenation). When 0 rows come back, `allowed:false` and read the current `used` with a second query.
    - `getToday({ userId })` → `[{ tool, used }]` for today's UTC date.
  - Repositories take and return plain objects (no Prisma types leak out). No Express imports here.
  - Commit: `feat(db): user and usage repositories`

- [ ] **T2.16 Readiness check + shutdown hook**
  - Push `async () => { await pingDb(); return 'db' }`-style check into the Phase 1 readiness registry in `routes/health.js`. `GET /api/ready` → `200 { status:'ready', checks:{ db:'ok' } }`, or **`503`** `{ status:'not_ready', checks:{ db:'fail' } }` on error/timeout (no internals leaked).
  - Register `disconnect` in the `shutdownHooks` array in `server.js`.
  - `/api/health` must stay dependency-free (liveness ≠ readiness).
  - Commit: `feat(server): db readiness probe and shutdown hook`

- [ ] **T2.17 Seed script `prisma/seed.js`**
  - Idempotent (re-running changes nothing): 1 dev user (`clerkUserId: 'user_dev_seed'`, email `dev@example.test`), 3 `tool_runs` (COMPLETED DNS, COMPLETED PORT_SCAN with `finished_at` set, FAILED WHOIS), 5 `port_findings` for the port scan, 1 `run_results` row.
  - Refuse to run when `NODE_ENV=production`.
  - Add script `"db:seed": "node prisma/seed.js"`.
  - Verify: run twice; row counts identical.
  - Commit: `feat(db): idempotent dev seed`

### Block D — Tests, benchmark, hygiene

- [ ] **T2.18 Test database harness**
  - **Read first:** `/tmp/skills-mcollina/skills/node/rules/testing.md` (skim) and VITEST "globalSetup".
  - `tests/setup/globalSetup.js`: points `DATABASE_URL`/`DIRECT_URL` at `TEST_DATABASE_URL`, runs `prisma migrate deploy` once. **Hard guard:** abort if the URL's database name does not end with `_test`.
  - A `truncateAll()` helper (`TRUNCATE ... RESTART IDENTITY CASCADE` on the 11 tables) called in `beforeEach` of DB tests.
  - DB tests live in `tests/db/` and run in a **separate vitest project** (or `--dir tests/db`) so unit tests stay DB-free and fast. Add script `"test:db": "vitest run --dir tests/db"`.
  - Commit: `test(db): isolated test database harness`

- [ ] **T2.19 Integration tests (`tests/db/`)**
  - `usage.test.js`
    1. limit 5, **50 concurrent `consume()` calls** (`Promise.all`) for one user/tool → exactly **5** `allowed:true`, 45 `allowed:false`, final `used === 5`.
    2. Different tools are independent counters.
    3. Different `usage_date` rows are independent (insert yesterday's row manually; today starts at 0).
    4. Limit changes: `consume` with limit 10 after 5 used → allowed.
  - `constraints.test.js` — each must be **rejected by the database**: port `70000`; `progress_pct` `101`; `used` `-1`; `finished_at < started_at`; `COMPLETED` run with null `finished_at`; email with uppercase; CVE id `"cve-1"`.
  - `users.test.js` — `upsertFromClerk` twice → 1 row; email lower-cased; `softDelete` nulls the email and a *new* user can then register with that same email.
  - Cascade test: delete a user → their runs, results, findings, reports, usage rows are all gone; `audit_logs.actor_id` becomes NULL (row kept).
  - `ready.test.js` — `/api/ready` 200 with DB up; 503 when the pool points to a closed port.
  - Verify: `npm run test:db --workspace server 2>&1 | tail -n 30` green, and `npm test --workspace server` (unit) still green.
  - Commit: `test(db): usage atomicity, constraints, cascades`

- [ ] **T2.20 Performance benchmark (the "not slow" proof)**
  - **Read first:** PG-EXPLAIN (sections "Basic" and "Caveats") and `DATABASE-DESIGN.md` §6.
  - Create `scripts/bench-seed.js` — run ONLY against a database whose name ends with `_bench` or `_test` (guard like T2.18). Generate data **inside Postgres** with `INSERT ... SELECT ... FROM generate_series(...)` (do not loop in JS):
    - 1,000 users; **1,000,000 `tool_runs`** (random user, random `tool`, `target_key` like `host-<n>.example`, `created_at` random within the last 90 days, status `COMPLETED`, `started_at = created_at`, `finished_at = created_at + interval '5 seconds'`); **3,000,000 `port_findings`** spread over the PORT_SCAN runs with unique `(run_id, port, protocol)`.
    - Use `gen_random_uuid()` for ids in the seed (Postgres 17 has no `uuidv7()`); note in the report that this is a *pessimistic* index-locality case versus real UUIDv7.
    - Then `VACUUM (ANALYZE)` on the big tables.
  - Run `EXPLAIN (ANALYZE, BUFFERS)` for Q1, Q2 (the atomic upsert, inside a rolled-back transaction), Q3 (first page **and** a deep keyset page), Q5, Q6, Q8 exactly as listed in design §3/§6.
  - Write `docs/db-benchmark.md`: for each query paste the plan's top node, execution time, and PASS/FAIL against the §6 table. **Any `Seq Scan` on a big table or any `Sort` node in Q3/Q8 = FAIL** → fix the index (via a new migration), re-run, record both runs.
  - Commit: `perf(db): 1M-row benchmark and results`

- [ ] **T2.21 Scripts and short ops doc**
  - `server/package.json` scripts: `db:migrate` (`prisma migrate dev`), `db:deploy` (`prisma migrate deploy`), `db:generate`, `db:seed`, `db:reset` (dev-only; refuses unless `NODE_ENV!=production`), `db:studio`.
  - Write `docs/database.md` (≤ 60 lines): how to start local DB, how to create a migration, the rule "**production only ever runs `migrate deploy`**", why `DIRECT_URL` is separate from `DATABASE_URL`, how to read `docs/db-benchmark.md`.
  - Commit: `docs(db): database operations guide`

### Block E — Close-out

- [ ] **T2.22 Final verification**
  - From a **clean state**: `docker compose down -v && docker compose up -d db`, `npm run db:deploy --workspace server`, `npm run db:seed --workspace server`, `npm run dev:server`.
  - Checks: `curl -s localhost:3001/api/health` → ok; `curl -s localhost:3001/api/ready` → db ok; stop the DB container → `/api/ready` returns 503 within ~3 s while `/api/health` still returns 200; restart DB → ready recovers without restarting the server.
  - `npm test --workspace server` and `npm run test:db --workspace server` both green.
  - `git log --oneline | head -n 25`, then print the final `tree server -I 'node_modules|generated' -L 3`.

---

## 3. Definition of Done (Phase 2)

- [ ] 22 tasks ticked, one commit each.
- [ ] Exactly the 11 tables from the design exist; migrations replay from zero without error.
- [ ] 50-way concurrent quota test proves the limit is never exceeded.
- [ ] Constraint tests prove the DB itself rejects bad data.
- [ ] `docs/db-benchmark.md` shows every budgeted query PASS at 1M runs (no Seq Scan, no Sort on Q3/Q8).
- [ ] RLS enabled on all tables; no real credentials in git; `server/.env` ignored.
- [ ] `/api/ready` reflects DB health; graceful shutdown disconnects the pool.
- [ ] Zero Python; `client/` untouched.

**When finished, report:** Prisma version, Postgres version, benchmark timings table (Q1–Q8), and anything deviating from `DATABASE-DESIGN.md` (there should be nothing). Then wait for the Phase 3 file (Clerk auth, user sync, webhooks, free-tier limits wired into routes).
