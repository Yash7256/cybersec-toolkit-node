import { env as defaultEnv } from '../../config/env.js'
import { metrics } from '../../observability/metrics.js'
import * as runRepo from '../../db/repos/runRepo.js'
import { capResult } from './truncate.js'
import { ToolError } from './errors.js'
import AppError from '../../utils/AppError.js'

let active = 0
export async function runTool({ tool, req, definition, input, target, options = {}, env = defaultEnv }) {
  if (active >= env.MAX_CONCURRENT_TOOL_RUNS) {
    const { refundQuota } = await import('../../middleware/quota.js')
    await refundQuota(req)
    throw new AppError(503, 'SERVER_BUSY', 'Server is busy')
  }
  active += 1
  const started = Date.now()
  let run
  try {
    const quotaDate = req.quota?.usageDate ? new Date(req.quota.usageDate) : null
    run = await runRepo.start({ userId: req.user.id, tool: definition.toolEnum, target: input.target ?? input.host, targetKey: target.targetKey, options, quotaDate })
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), env.TOOL_HARD_TIMEOUT_MS)
    try {
      const data = await Promise.race([
        definition.execute(input, {
          target,
          signal: controller.signal,
          env,
          userId: req.user.id,
        }),
        new Promise((_, reject) => controller.signal.addEventListener('abort', () => reject(new ToolError('timeout', 'Request failed')), { once: true })),
      ])
      const capped = capResult(data)
      await runRepo.completeFenced({ runId: run.id, workerId: run.workerId, attempt: run.attempt, data: capped, summary: definition.summarize(capped) })
      metrics.recordToolRun?.(definition.name, 'success')
      return { run, data: capped, status: 'COMPLETED' }
    } catch (err) {
      const toolErr = err instanceof ToolError ? err : new ToolError('internal', 'Request failed', err)
      if (toolErr.kind === 'target') {
        const data = { ...definition.emptyResult(input), error: toolErr.message }
        await runRepo.completeFenced({ runId: run.id, workerId: run.workerId, attempt: run.attempt, data, summary: definition.summarize(data) })
        return { run, data, status: 'COMPLETED' }
      }
      const timedOut = toolErr.kind === 'timeout'
      await runRepo.failFenced({ runId: run.id, workerId: run.workerId, attempt: run.attempt, status: timedOut ? 'TIMED_OUT' : 'FAILED', errorCode: timedOut ? 'TOOL_TIMEOUT' : 'UPSTREAM_ERROR', message: toolErr.message })
      await runRepo.refundOnce(run.id)
      throw new AppError(timedOut ? 504 : 502, timedOut ? 'TOOL_TIMEOUT' : 'UPSTREAM_ERROR', toolErr.message)
    } finally { clearTimeout(timer) }
  } finally {
    active -= 1
    metrics.observeToolRun?.(definition.name, (Date.now() - started) / 1000)
  }
}
