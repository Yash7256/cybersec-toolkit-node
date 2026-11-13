import { env as defaultEnv } from '../config/env.js'
import * as runRepo from '../db/repos/runRepo.js'
import { enqueueRun } from '../queue/queues.js'

export async function runReaper({ env = defaultEnv, logger = console } = {}) {
  const rows = await runRepo.reclaimStale({ stallSec: env.RUN_STALL_SEC, maxAttempts: env.RUN_MAX_ATTEMPTS, limit: 100 })
  let requeued = 0; let timedOut = 0
  for (const row of rows) {
    if (row.status === 'QUEUED') { await enqueueRun({ runId: row.id, attempt: row.attempt, priority: 10, env }); requeued += 1 }
    else { await runRepo.refundOnce(row.id); timedOut += 1 }
  }
  const orphaned = await runRepo.findOrphanQueued(env.ORPHAN_QUEUED_SEC, 100)
  for (const row of orphaned) { await enqueueRun({ runId: row.id, attempt: row.attempt, priority: 10, env }); requeued += 1 }
  const timedOutQueued = await runRepo.failStaleQueued(env.QUEUE_MAX_WAIT_SEC, 100)
  for (const row of timedOutQueued) await runRepo.refundOnce(row.id)
  const overlong = await runRepo.findOverlong(env.TOOL_HARD_TIMEOUT_MS / 1000 * 2, 100)
  for (const row of overlong) { await runRepo.failFenced({ runId: row.id, workerId: row.worker_id, attempt: row.attempt, status: 'TIMED_OUT', errorCode: 'TOOL_TIMEOUT' }); await runRepo.refundOnce(row.id); timedOut += 1 }
  if (rows.length) logger.info?.({ requeued, timedOut }, 'reaper pass completed')
  return { requeued, timedOut }
}
