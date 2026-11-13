import { Gauge } from 'prom-client'
import { metrics } from './metrics.js'
import { getRunsQueue } from '../queue/queues.js'
import { env as defaultEnv } from '../config/env.js'

const queueJobs = new Gauge({ name: 'cst_queue_jobs', help: 'Queue jobs by state', labelNames: ['queue', 'state'], registers: [metrics.register] })
export async function refreshQueueMetrics({ env = defaultEnv } = {}) {
  const counts = await getRunsQueue({ env }).getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed', 'prioritized')
  for (const [state, value] of Object.entries(counts)) queueJobs.set({ queue: 'runs', state }, value)
  return counts
}
export function startQueueMetrics({ env = defaultEnv, intervalMs = 10000 } = {}) { const timer = setInterval(() => refreshQueueMetrics({ env }).catch(() => {}), intervalMs); timer.unref(); return () => clearInterval(timer) }
