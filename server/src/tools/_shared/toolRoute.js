import { z } from 'zod'
import { createAttachUser } from '../../middleware/attachUser.js'
import { validateTarget } from '../../security/targetPolicy.js'
import { runTool } from './runTool.js'
import { ToolError } from './errors.js'
import { enforceQuota } from '../../middleware/quota.js'
import asyncHandler from '../../utils/asyncHandler.js'
import { createAbuseGuard } from '../../security/abuseGuard.js'
import * as runRepo from '../../db/repos/runRepo.js'
import { createHash } from 'node:crypto'
import { getProducerConnection } from '../../queue/connections.js'
import { normalizeHost } from '../../security/hostPolicy.js'
import { classifyIp } from '../../security/ipPolicy.js'
import AppError from '../../utils/AppError.js'
import { enqueueRun, getQueueDepth } from '../../queue/queues.js'

function quotaStep(req, res, next, amount = 1) {
  return new Promise((resolve, reject) => enforceQuota(req.toolName, req.env, amount)(req, res, (err) => err ? reject(err) : resolve(next())))
}

export function createToolHandler({ definition, auth, clerkClient, env, limiters }) {
  const attach = createAttachUser({ clerkClient })
  const abuse = createAbuseGuard({ env })
  return [auth.requireAuth, attach, ...limiters.submitLimiters, asyncHandler(async (req, res, next) => {
    req.env = env
    const parsed = definition.schema.parse(req.method === 'GET' ? req.query : req.body)
    const input = definition.normalize(parsed)
    if (definition.prepare) await definition.prepare(input, { req, env })
    if (definition.touchesTarget) await abuse.assertNotCoolingDown(req.user.id)
    const rawTarget = input.target ?? input.host ?? definition.targetValue?.(input)
    const target = definition.validateInput
      ? await definition.validateInput(input, { req, env })
      : definition.touchesTarget
        ? await validateTarget(rawTarget, { env })
        : (() => { const normalized = normalizeHost(rawTarget); if (normalized.kind === 'ip') { const ip = classifyIp(normalized.value); if (!ip.allowed) throw new AppError(422, 'TARGET_BLOCKED', 'This target is not allowed.') } return { targetKey: normalized.value.toLowerCase(), addresses: [] } })()
    if (definition.beforeSubmit) await definition.beforeSubmit(input, { req, target, env })
    if (definition.touchesTarget) await abuse.consumeTarget({ userId: req.user.id, targetKey: target.targetKey })
    req.toolName = definition.toolEnum
    const quotaUnits = Math.max(1, Math.trunc(definition.quotaUnits?.(input, req) ?? 1))
    const displayTarget = target.display ?? input.target ?? input.host ?? target.targetKey
    const dedupe = definition.dedupeTtlSec > 0 ? await runRepo.findRecentCompleted({ userId: req.user.id, tool: definition.toolEnum, targetKey: target.targetKey, options: input, withinSec: definition.dedupeTtlSec }) : null
    if (dedupe) {
      res.set('X-Run-Id', dedupe.id)
      res.json({ runId: dedupe.id, tool: definition.name, target: displayTarget, status: 'COMPLETED', cached: true, data: dedupe.result.data, quota: null })
      return
    }
    const asyncMode = definition.mode === 'async' || (definition.mode === 'auto' && definition.asyncWhen?.(input))
    if (asyncMode) {
      const idempotency = req.get('Idempotency-Key')
      if (!idempotency || !/^[A-Za-z0-9_-]{8,64}$/.test(idempotency)) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid Idempotency-Key')
      const idemKey = `${env.QUEUE_PREFIX}:idem:${req.user.id}:${createHash('sha256').update(`${definition.toolEnum}|${idempotency}`).digest('hex')}`
      const redis = getProducerConnection()
      const existing = await redis.get(idemKey)
      if (existing && existing !== 'pending') { const replay = await runRepo.findByIdForUser(existing, req.user.id); if (replay) { res.set('Idempotent-Replayed', 'true').json({ runId: replay.id, tool: definition.name, target: displayTarget, status: replay.status, pollUrl: `/api/runs/${replay.id}`, quota: null }); return } }
      if (existing === 'pending') { res.set('Retry-After', '1'); throw new AppError(409, 'IDEMPOTENCY_IN_PROGRESS', 'Request is already in progress') }
      const claimed = await redis.set(idemKey, 'pending', 'NX', 'EX', 86400)
      if (!claimed) { res.set('Retry-After', '1'); throw new AppError(409, 'IDEMPOTENCY_IN_PROGRESS', 'Request is already in progress') }
      try {
        await quotaStep(req, res, () => {}, quotaUnits)
      } catch (err) {
        await redis.del(idemKey)
        throw err
      }
      const depth = await getQueueDepth({ env })
      if (depth >= env.QUEUE_MAX_WAITING) {
        const { refundQuota } = await import('../../middleware/quota.js')
        await refundQuota(req)
        res.set('Retry-After', '30')
        await redis.del(idemKey)
        throw new AppError(503, 'QUEUE_FULL', 'Queue is full')
      }
      const cap = req.user.role === 'ADMIN' ? env.MAX_ACTIVE_RUNS_PAID : req.user.tier === 'PAID' ? env.MAX_ACTIVE_RUNS_PAID : env.MAX_ACTIVE_RUNS_FREE
      const queued = await runRepo.createQueuedWithCap({ userId: req.user.id, tool: definition.toolEnum, target: displayTarget, targetKey: target.targetKey, options: input, quotaDate: req.quota?.usageDate ?? null, cap })
      if (!queued) {
        const { refundQuota } = await import('../../middleware/quota.js')
        await refundQuota(req)
        await redis.del(idemKey)
        throw new AppError(429, 'TOO_MANY_ACTIVE_RUNS', 'Too many active runs')
      }
      try { await enqueueRun({ runId: queued.id, attempt: queued.attempt, priority: req.user.role === 'ADMIN' || req.user.tier === 'PAID' ? 1 : 10, env }); await redis.set(idemKey, queued.id, 'EX', 86400) } catch { await runRepo.markEnqueueFailed(queued.id); const { refundQuota } = await import('../../middleware/quota.js'); await refundQuota(req); await redis.del(idemKey); throw new AppError(503, 'QUEUE_UNAVAILABLE', 'Queue unavailable') }
      const pollUrl = `/api/runs/${queued.id}`
      res.status(202).set('Location', pollUrl).json({ runId: queued.id, tool: definition.name, target: displayTarget, status: 'QUEUED', pollUrl, pollAfterMs: 1500, quota: req.quota })
      return
    }
    await quotaStep(req, res, () => {}, quotaUnits)
    const result = await runTool({ tool: definition.toolEnum, req, definition, input, target, options: input, env })
    res.set('X-Run-Id', result.run.id)
    res.json({ runId: result.run.id, tool: definition.name, target: displayTarget, status: result.status, cached: false, data: result.data, quota: req.quota })
  })]
}
