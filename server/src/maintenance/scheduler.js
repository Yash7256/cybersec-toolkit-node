import { env as defaultEnv } from '../config/env.js'
import { getMaintenanceQueue } from '../queue/maintenance.js'
import { prisma } from '../db/client.js'
import { metrics } from '../observability/metrics.js'

async function refreshRunGauges() {
  const rows = await prisma.$queryRaw`SELECT status::text AS status, count(*)::int AS count FROM tool_runs WHERE status IN ('QUEUED','RUNNING') GROUP BY status`
  const seen = new Set()
  for (const row of rows) {
    metrics.setRunsActive(row.status, row.count)
    seen.add(row.status)
  }
  for (const status of ['QUEUED', 'RUNNING']) if (!seen.has(status)) metrics.setRunsActive(status, 0)
}

export function startMaintenance({ env = defaultEnv, logger = console } = {}) {
  if (!env.MAINTENANCE_ENABLED) return () => {}
  const queue = getMaintenanceQueue({ env })
  queue.upsertJobScheduler('reaper', { every: 30000 }, { name: 'reaper', data: {} }).catch((err) => logger.error?.({ err }, 'scheduler setup failed'))
  queue.upsertJobScheduler('retention', { pattern: '0 30 3 * * *', tz: 'UTC' }, { name: 'retention', data: {} }).catch((err) => logger.error?.({ err }, 'scheduler setup failed'))
  queue.upsertJobScheduler('cache-sweep', { every: 3600000 }, { name: 'cache-sweep', data: {} }).catch((err) => logger.error?.({ err }, 'scheduler setup failed'))
  const runGauges = setInterval(() => refreshRunGauges().catch((err) => logger.error?.({ err }, 'run gauge refresh failed')), 15000)
  runGauges.unref()
  return () => clearInterval(runGauges)
}
