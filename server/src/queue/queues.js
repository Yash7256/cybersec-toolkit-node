import { getProducerConnection } from './connections.js'
import { env as defaultEnv } from '../config/env.js'
import { Queue } from 'bullmq'

const state = { seq: 0 }
let runs
export function getRunsQueue({ env = defaultEnv } = {}) { return runs ??= new Queue('runs', { connection: getProducerConnection(), prefix: env.QUEUE_PREFIX, defaultJobOptions: { attempts: 1, removeOnComplete: { age: 3600, count: 1000 }, removeOnFail: { age: 604800, count: 1000 } } }) }
function keys(env) { return { waiting: `${env.QUEUE_PREFIX}:queue:runs:waiting`, jobs: `${env.QUEUE_PREFIX}:queue:runs:jobs` } }
export async function enqueueRun({ runId, attempt = 1, priority = 10, env = defaultEnv }) {
  if (!/^[0-9a-f-]{16,64}$/i.test(String(runId))) throw new Error('invalid run id')
  const jobId = `${runId}-${attempt}`
  await getRunsQueue({ env }).add('execute-run', { runId }, { jobId, priority })
  return jobId
}
export async function getQueueDepth({ env = defaultEnv } = {}) { const counts = await getRunsQueue({ env }).getJobCounts('waiting', 'prioritized'); return Number(counts.waiting ?? 0) + Number(counts.prioritized ?? 0) }
export async function claimNext({ env = defaultEnv } = {}) {
  const redis = getProducerConnection(); const { waiting, jobs } = keys(env); const ids = await redis.zrange(waiting, 0, 0); if (!ids.length) return null
  const id = ids[0]; const removed = await redis.zrem(waiting, id); if (!removed) return null
  const payload = await redis.hget(jobs, id); return payload ? { id, data: JSON.parse(payload) } : null
}
export async function removeRunJob({ runId, attempt, env = defaultEnv } = {}) { const job = await getRunsQueue({ env }).getJob(`${runId}-${attempt}`); await job?.remove().catch(() => {}) }
export async function closeQueues() { await runs?.close().catch(() => {}); runs = null; const { closeMaintenanceQueue } = await import('./maintenance.js'); await closeMaintenanceQueue(); const { closeQueueConnections } = await import('./connections.js'); await closeQueueConnections() }
