import { env as defaultEnv } from '../config/env.js'
import { getRedisClient } from '../redis/client.js'
import { key } from '../redis/keys.js'
import { createLogger } from '../utils/logger.js'
import { metrics } from '../observability/metrics.js'
import * as auditRepo from '../db/repos/auditRepo.js'
import AppError from '../utils/AppError.js'

const HOUR_SEC = 3600

function storeErrorReporter(limiter, logger) {
  let lastLogAt = 0
  return () => {
    metrics.recordRateLimitStoreError(limiter)
    const now = Date.now()
    if (now - lastLogAt >= 30_000) {
      lastLogAt = now
      logger.warn({ limiter }, 'abuse guard store error; failing open')
    }
  }
}

async function incrementWithTtl(redis, redisKey, ttlSec) {
  const count = await redis.incr(redisKey)
  if (count === 1) await redis.expire(redisKey, ttlSec)
  return count
}

export function createAbuseGuard({
  env = defaultEnv,
  logger = createLogger(env),
  redis = getRedisClient(),
  audit = auditRepo,
} = {}) {
  const reportTarget = storeErrorReporter('target', logger)
  const reportAbuse = storeErrorReporter('abuse', logger)

  const cooldownKey = (userId) => key('abuse', 'cooldown', userId)
  const blockedKey = (userId) => key('abuse', 'blocked', userId)
  const globalTargetKey = (targetKey) => key('tgt', 'global', targetKey)
  const userTargetKey = (userId, targetKey) =>
    key('tgt', `user_${userId}`, targetKey)

  // Runs at the start of the policy step, before any resolution or quota.
  async function assertNotCoolingDown(userId) {
    if (!userId) return
    try {
      const ttl = await redis.ttl(cooldownKey(userId))
      if (ttl === -1 || ttl > 0) {
        const retryAfterSec = ttl === -1 ? env.BLOCKED_COOLDOWN_SEC : ttl
        throw new AppError(
          429,
          'TARGET_ABUSE_COOLDOWN',
          'Too many blocked targets. Try again later.',
          { retryAfterSec }
        )
      }
    } catch (err) {
      if (err instanceof AppError) throw err
      reportAbuse()
    }
  }

  async function enforceCooldown(req, res, next) {
    try {
      await assertNotCoolingDown(req.user?.id)
      next()
    } catch (err) {
      if (err instanceof AppError && err.code === 'TARGET_ABUSE_COOLDOWN') {
        res.set('Retry-After', String(err.details?.retryAfterSec ?? 0))
      }
      next(err)
    }
  }

  // Runs after policy validation (needs targetKey) and before quota.
  async function consumeTarget({ userId, targetKey } = {}) {
    if (!targetKey) return
    try {
      const [globalCount, userCount] = await Promise.all([
        incrementWithTtl(redis, globalTargetKey(targetKey), HOUR_SEC),
        userId
          ? incrementWithTtl(redis, userTargetKey(userId, targetKey), HOUR_SEC)
          : 0,
      ])

      if (
        globalCount > env.TARGET_HOURLY_LIMIT_GLOBAL ||
        userCount > env.TARGET_HOURLY_LIMIT_USER
      ) {
        metrics.recordRateLimitRejected('target')
        throw new AppError(
          429,
          'TARGET_RATE_LIMITED',
          'This target has been scanned too often recently.'
        )
      }
    } catch (err) {
      if (err instanceof AppError) throw err
      reportTarget()
    }
  }

  // Called for every policy rejection: metric, audit, and cooldown accounting.
  async function recordBlocked({ userId, ip, reason, tool, target } = {}) {
    metrics.recordBlocked(reason)

    try {
      await audit.log({
        actorId: userId ?? null,
        action: 'scan.blocked_target',
        ip: ip ?? null,
        metadata: {
          reason,
          tool,
          target: target === undefined || target === null ? null : String(target).slice(0, 255),
        },
      })
    } catch {
      // auditRepo.log never throws, but never let auditing break the request.
    }

    if (!userId) return

    try {
      const count = await incrementWithTtl(
        redis,
        blockedKey(userId),
        env.BLOCKED_ATTEMPTS_WINDOW_SEC
      )
      if (count >= env.BLOCKED_ATTEMPTS_MAX) {
        await redis.set(cooldownKey(userId), String(count), 'EX', env.BLOCKED_COOLDOWN_SEC)
      }
    } catch {
      reportAbuse()
    }
  }

  return {
    assertNotCoolingDown,
    enforceCooldown,
    consumeTarget,
    recordBlocked,
  }
}
