import os from 'node:os'
import crypto from 'node:crypto'
import tools from '../tools/index.js'
import * as runRepo from '../db/repos/runRepo.js'
import * as findingsRepo from '../db/repos/findingsRepo.js'
import { executeRun } from '../jobs/executeRun.js'
import { publishRunEvent } from '../queue/events.js'
import { env as defaultEnv } from '../config/env.js'

const workerId = `${os.hostname()}:${process.pid}:${crypto.randomBytes(2).toString('hex')}`
export async function processRun(job, { env = defaultEnv, logger = console, definitions = tools } = {}) {
  const runId = job?.data?.runId
  if (!/^[0-9a-f-]{16,64}$/i.test(String(runId))) return false
  const run = await runRepo.claim({ runId, workerId })
  if (!run) return false
  let progress = 0
  const controller = new AbortController()
  const heartbeat = setInterval(async () => { const result = await runRepo.heartbeat({ runId, workerId, attempt: run.attempt, progressPct: progress }); if (!result) { controller.abort('fenced'); logger.warn?.({ runId }, 'worker fenced out') } else if (result.cancel_requested) controller.abort('cancelled') }, env.WORKER_HEARTBEAT_SEC * 1000)
  heartbeat.unref()
  try {
    const definition = Object.values(definitions).find((item) => item.toolEnum === run.tool)
    if (!definition) { await runRepo.failFenced({ runId, workerId, attempt: run.attempt, errorCode: 'UNKNOWN_TOOL' }); return false }
    const result = await executeRun({ run, definition, env, signal: controller.signal, onProgress: (pct) => { progress = pct } })
    if (controller.signal.aborted && controller.signal.reason === 'fenced') return false
    if (controller.signal.aborted && controller.signal.reason === 'cancelled') { await runRepo.failFenced({ runId, workerId, attempt: run.attempt, status: 'CANCELLED', errorCode: 'CANCELLED', message: 'Run cancelled' }); return true }
    if (result.status === 'COMPLETED') {
      const extra = run.tool === 'PORT_SCAN'
        ? ({ tx }) => findingsRepo.replaceForRun(tx, runId, result.data?.open_ports ?? [])
        : null
      await runRepo.completeFenced({ runId, workerId, attempt: run.attempt, data: result.data, summary: result.summary, extra })
    }
    else { await runRepo.failFenced({ runId, workerId, attempt: run.attempt, status: result.status, errorCode: result.errorCode, message: result.errorMessage, summary: result.summary }); if (result.status !== 'CANCELLED') await runRepo.refundOnce(runId) }
    await publishRunEvent(runId, { type: 'status', status: result.status }, env)
    return true
  } catch (err) { logger.error?.({ err, runId }, 'run execution failed'); await runRepo.failFenced({ runId, workerId, attempt: run.attempt, errorCode: 'INTERNAL_ERROR' }).catch(() => {}); await runRepo.refundOnce(runId).catch(() => {}); return false } finally { clearInterval(heartbeat) }
}
