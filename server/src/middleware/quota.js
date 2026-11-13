import { env as defaultEnv } from '../config/env.js'
import { limitFor, nextResetAt } from '../config/limits.js'
import * as usageRepo from '../db/repos/usageRepo.js'
import { createLogger } from '../utils/logger.js'
import { metrics } from '../observability/metrics.js'
import AppError from '../utils/AppError.js'
import asyncHandler from '../utils/asyncHandler.js'

const logger = createLogger(defaultEnv)

function secondsUntil(iso) {
  return Math.max(0, Math.ceil((Date.parse(iso) - Date.now()) / 1000))
}

// Must run AFTER requireAuth + attachUser. Consumes `amount` units (default 1).
export function enforceQuota(tool, env = defaultEnv, amount = 1) {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      throw new AppError(500, 'INTERNAL_ERROR', 'enforceQuota requires an attached user')
    }

    const limit = limitFor(req.user, env)
    if (limit === Infinity) {
      req.quota = { tool, limit: null, consumed: false }
      next()
      return
    }

    const result = await usageRepo.consume({ userId: req.user.id, tool, limit, amount })
    const resetsAt = nextResetAt()

    res.set('X-Quota-Limit', String(limit))
    res.set('X-Quota-Remaining', String(Math.max(limit - result.used, 0)))
    res.set('X-Quota-Reset', resetsAt)

    if (!result.allowed) {
      metrics.recordQuotaRejected(tool)
      res.set('Retry-After', String(secondsUntil(resetsAt)))
      throw new AppError(429, 'QUOTA_EXCEEDED', `Daily limit reached for ${tool}`, {
        limit,
        resetsAt,
      })
    }

    req.quota = {
      tool,
      limit,
      amount,
      used: result.used,
      usageDate: result.usageDate,
      consumed: true,
    }
    next()
  })
}

// Refund the unit consumed at hour 0 of a request. Idempotent, never throws.
export async function refundQuota(req) {
  const quota = req.quota
  if (!quota?.consumed || quota.refunded) return
  quota.refunded = true
  try {
    await usageRepo.refund({
      userId: req.user.id,
      tool: quota.tool,
      usageDate: quota.usageDate,
      amount: quota.amount ?? 1,
    })
  } catch (err) {
    logger.error({ err, tool: quota.tool }, 'Failed to refund quota')
  }
}
