import { processRun } from './processor.js'
import { env as defaultEnv } from '../config/env.js'
import { Worker } from 'bullmq'
import { getWorkerConnection } from '../queue/connections.js'
import { processMaintenance } from '../maintenance/processor.js'
import { startMaintenance } from '../maintenance/scheduler.js'

export function startWorker({ env = defaultEnv, logger = console, concurrency = env.WORKER_CONCURRENCY, definitions } = {}) {
  const worker = new Worker('runs', (job) => processRun(job, { env, logger, definitions }), { connection: getWorkerConnection(), prefix: env.QUEUE_PREFIX, concurrency, lockDuration: 60000, stalledInterval: 15000, maxStalledCount: 0 })
  const maintenance = env.MAINTENANCE_ENABLED ? new Worker('maintenance', (job) => processMaintenance(job, { env, logger }), { connection: getWorkerConnection(), prefix: env.QUEUE_PREFIX, concurrency: 1 }) : null
  const stopMaintenance = startMaintenance({ env, logger })
  worker.on('error', (err) => logger.error?.({ err }, 'worker error'))
  worker.on('failed', (job, err) => logger.warn?.({ runId: job?.data?.runId, err: err?.message }, 'worker job failed'))
  return { stop: async () => { stopMaintenance(); await worker.close(); await maintenance?.close() }, active: new Set(), worker, maintenance }
}
