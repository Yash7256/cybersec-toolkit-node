// Populates a disposable database with 1M tool_runs + 3M port_findings, then
// optionally runs the EXPLAIN (ANALYZE, BUFFERS) suite from DATABASE-DESIGN.md §6.
//
// Usage (from server/):
//   DATABASE_URL=postgresql://cybersec:cybersec@localhost:5433/cybersec_bench node scripts/bench-seed.js
//   DATABASE_URL=... node scripts/bench-seed.js --explain   # explain only
//   DATABASE_URL=... node scripts/bench-seed.js --all       # seed + explain
//
// Hard guard: refuses to touch any database whose name does not end in _bench or _test.

import 'dotenv/config'
import pg from 'pg'

const args = new Set(process.argv.slice(2))
const doSeed = !args.has('--explain')
const doExplain = args.has('--explain') || args.has('--all')

const USERS = 1000
const RUNS = 1_000_000
const FINDINGS = 3_000_000
const RUNNING_ROWS = 100

const databaseUrl = process.env.DATABASE_URL
if (!databaseUrl) {
  console.error('DATABASE_URL is required')
  process.exit(1)
}

const databaseName = new URL(databaseUrl).pathname.replace(/^\//, '')
if (!databaseName.endsWith('_bench') && !databaseName.endsWith('_test')) {
  console.error(
    `Refusing to benchmark: database "${databaseName}" does not end with _bench or _test`
  )
  process.exit(1)
}

const pool = new pg.Pool({ connectionString: databaseUrl, max: 4 })

async function query(sql, params) {
  const client = await pool.connect()
  try {
    return await client.query(sql, params)
  } finally {
    client.release()
  }
}

async function seed() {
  console.log(`Seeding ${databaseName}: ${USERS} users, ${RUNS} runs, ${FINDINGS} findings`)

  await query(`TRUNCATE TABLE
      audit_logs, webhook_events, reports, finding_cves, service_cve_lookups,
      cves, port_findings, run_results, tool_runs, usage_counters, users
    RESTART IDENTITY CASCADE`)

  await query(
    `INSERT INTO users (id, clerk_user_id, email, is_active, created_at, updated_at)
     SELECT gen_random_uuid(), 'bench_user_' || g, 'bench' || g || '@example.test', true, now(), now()
     FROM generate_series(1, $1) g`,
    [USERS]
  )

  const startedAt = Date.now()
  await query(
    `WITH u AS (
       SELECT id,
              row_number() OVER (ORDER BY clerk_user_id) - 1 AS n,
              count(*) OVER () AS total
       FROM users
     ), b AS (SELECT max(total) AS total FROM u)
     INSERT INTO tool_runs
       (id, user_id, tool, target, target_key, status, progress_pct,
        queued_at, started_at, finished_at, created_at)
     SELECT
       gen_random_uuid(),
       u.id,
       CASE
         WHEN g % 2 = 0 THEN 'PORT_SCAN'::"ToolName"
         ELSE (ARRAY['DNS','WHOIS','PING','TRACEROUTE','SSL','HTTP_HEADERS','SUBDOMAIN','GEOIP','WEBAPP_SCAN'])
              [1 + (g % 9)]::"ToolName"
       END,
       'host-' || g || '.example',
       'host-' || g || '.example',
       'COMPLETED'::"RunStatus",
       100,
       t.ts, t.ts, t.ts + interval '5 seconds', t.ts
     FROM generate_series(1, $1) g
     CROSS JOIN b
     CROSS JOIN LATERAL (SELECT now() - (random() * interval '90 days') AS ts) t
     JOIN u ON u.n = ((g - 1) % b.total)`,
    [RUNS]
  )
  console.log(`  tool_runs inserted in ${((Date.now() - startedAt) / 1000).toFixed(1)}s`)

  // A small live-job slice so Q6 (partial index on RUNNING) is a real lookup,
  // not an empty-index shortcut. Kept out of the 1M COMPLETED set above.
  await query(
    `INSERT INTO tool_runs
       (id, user_id, tool, target, target_key, status, progress_pct,
        queued_at, started_at, heartbeat_at, created_at)
     SELECT
       gen_random_uuid(), u.id, 'PORT_SCAN'::"ToolName",
       'running-' || g || '.example', 'running-' || g || '.example',
       'RUNNING'::"RunStatus", 50,
       now() - interval '2 hours', now() - interval '2 hours',
       now() - interval '30 minutes', now() - interval '2 hours'
     FROM generate_series(1, $1) g
     JOIN (SELECT id, row_number() OVER (ORDER BY clerk_user_id) - 1 AS n,
                  count(*) OVER () AS total
           FROM users) u
       ON u.n = ((g - 1) % u.total)`,
    [RUNNING_ROWS]
  )

  const findingsStartedAt = Date.now()
  await query(
    `WITH scans AS (
       SELECT id,
              row_number() OVER (ORDER BY id) - 1 AS n,
              count(*) OVER () AS total
       FROM tool_runs
       WHERE tool = 'PORT_SCAN'
     ), t AS (SELECT max(total) AS total FROM scans)
     INSERT INTO port_findings (run_id, port, protocol, state, service, version, risk)
     SELECT
       s.id,
       1 + (((f - 1) / t.total)::int),
       'TCP'::"Protocol",
       'OPEN'::"PortState",
       'bench-svc',
       '1.0.0',
       'LOW'::"Severity"
     FROM generate_series(1, $1::bigint) f
     CROSS JOIN t
     JOIN scans s ON s.n = ((f - 1) % t.total)`,
    [FINDINGS]
  )
  console.log(`  port_findings inserted in ${((Date.now() - findingsStartedAt) / 1000).toFixed(1)}s`)

  console.log('  VACUUM (ANALYZE) on big tables…')
  await query('VACUUM (ANALYZE) tool_runs')
  await query('VACUUM (ANALYZE) port_findings')
  await query('VACUUM (ANALYZE) users')
  await query('VACUUM (ANALYZE) usage_counters')

  const counts = await query(
    `SELECT
       (SELECT count(*) FROM users) AS users,
       (SELECT count(*) FROM tool_runs) AS tool_runs,
       (SELECT count(*) FROM port_findings) AS port_findings`
  )
  console.log('Seed complete:', counts.rows[0])
}

const planText = (rows) => rows.map((row) => row['QUERY PLAN']).join('\n')

function summarize(label, plan) {
  const seqScan = /Seq Scan/.test(plan)
  const sort = /\bSort\b/.test(plan)
  const top = plan.split('\n').find((line) => line.trim().length > 0) ?? ''
  const exec = plan.match(/Execution Time: ([\d.]+) ms/)
  return {
    label,
    top: top.trim(),
    executionMs: exec ? Number(exec[1]) : null,
    seqScan,
    sort,
  }
}

async function explain(label, sql, params = []) {
  const { rows } = await query(`EXPLAIN (ANALYZE, BUFFERS) ${sql}`, params)
  const plan = planText(rows)
  const result = summarize(label, plan)
  console.log(`\n=== ${label} ===`)
  console.log(plan)
  return result
}

async function explainQ2(userId) {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    // Prime today's counter so the measured statement takes the ON CONFLICT
    // UPDATE path (the common case after the first call of the day).
    await client.query(
      `INSERT INTO usage_counters (user_id, tool, usage_date, used)
       VALUES ($1::uuid, 'DNS'::"ToolName", (now() AT TIME ZONE 'UTC')::date, 1)`,
      [userId]
    )
    const sql = `INSERT INTO usage_counters (user_id, tool, usage_date, used)
      VALUES ($1::uuid, 'DNS'::"ToolName", (now() AT TIME ZONE 'UTC')::date, 1)
      ON CONFLICT (user_id, tool, usage_date)
      DO UPDATE SET used = usage_counters.used + 1, updated_at = now()
      WHERE usage_counters.used < $2
      RETURNING used`
    const { rows } = await client.query(`EXPLAIN (ANALYZE, BUFFERS) ${sql}`, [userId, 100])
    await client.query('ROLLBACK')
    const plan = planText(rows)
    const result = summarize('Q2 quota consume (rolled back)', plan)
    console.log('\n=== Q2 quota consume (rolled back) ===')
    console.log(plan)
    return result
  } finally {
    client.release()
  }
}

async function explainSuite() {
  console.log(`\nRunning EXPLAIN suite against ${databaseName}`)

  const { rows: userRows } = await query(
    `SELECT id FROM users WHERE clerk_user_id = 'bench_user_1'`
  )
  const userId = userRows[0].id

  const { rows: cursorRows } = await query(
    `SELECT created_at, id FROM tool_runs
     WHERE user_id = $1
     ORDER BY created_at DESC, id DESC
     OFFSET 800 LIMIT 1`,
    [userId]
  )
  const cursor = cursorRows[0]

  const { rows: dnsRows } = await query(
    `SELECT target_key FROM tool_runs
     WHERE user_id = $1 AND tool = 'DNS'
     ORDER BY created_at DESC LIMIT 1`,
    [userId]
  )
  const dnsTarget = dnsRows[0]?.target_key ?? 'host-1.example'

  const { rows: findingRows } = await query(
    `SELECT run_id FROM port_findings LIMIT 1`
  )
  const runId = findingRows[0].run_id

  const results = []
  results.push(
    await explain(
      'Q1 user by clerk id',
      `SELECT id, email, tier, role FROM users WHERE clerk_user_id = $1`,
      ['bench_user_1']
    )
  )
  results.push(await explainQ2(userId))
  results.push(
    await explain(
      'Q3 history page (first)',
      `SELECT id, tool, target, status, created_at FROM tool_runs
       WHERE user_id = $1
       ORDER BY created_at DESC, id DESC
       LIMIT 20`,
      [userId]
    )
  )
  results.push(
    await explain(
      'Q3 history page (deep keyset)',
      `SELECT id, tool, target, status, created_at FROM tool_runs
       WHERE user_id = $1 AND (created_at, id) < ($2, $3)
       ORDER BY created_at DESC, id DESC
       LIMIT 20`,
      [userId, cursor.created_at, cursor.id]
    )
  )
  results.push(
    await explain(
      'Q5 dedupe lookup',
      `SELECT id FROM tool_runs
       WHERE user_id = $1 AND tool = 'DNS' AND target_key = $2
       ORDER BY created_at DESC LIMIT 1`,
      [userId, dnsTarget]
    )
  )
  results.push(
    await explain(
      'Q6 stale running jobs',
      `SELECT id, target FROM tool_runs
       WHERE status = 'RUNNING' AND heartbeat_at < now() - interval '5 minutes'
       ORDER BY heartbeat_at LIMIT 50`
    )
  )
  results.push(
    await explain(
      'Q8 findings of a run',
      `SELECT port, protocol, state, service FROM port_findings
       WHERE run_id = $1
       ORDER BY port, protocol`,
      [runId]
    )
  )

  console.log('\n\n=== SUMMARY ===')
  console.log('label\texec_ms\tseq_scan\tsort\ttop_node')
  for (const result of results) {
    console.log(
      `${result.label}\t${result.executionMs ?? '-'}\t${result.seqScan}\t${result.sort}\t${result.top}`
    )
  }
}

try {
  if (doSeed) await seed()
  if (doExplain) await explainSuite()
} catch (error) {
  console.error('Benchmark failed:', error)
  process.exitCode = 1
} finally {
  await pool.end()
}
