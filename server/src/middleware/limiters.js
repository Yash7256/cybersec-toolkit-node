import { env as defaultEnv } from '../config/env.js'
import { createLogger } from '../utils/logger.js'
import { metrics } from '../observability/metrics.js'
import AppError from '../utils/AppError.js'
import {
  createLimiter,
  createRateLimiter,
  setRateHeaders,
} from './rateLimit.js'

const WEBHOOKS_POINTS = 300
const WEBHOOKS_WINDOW_SEC = 60
const GENERAL_WINDOW_SEC = 60

function createAuthFailGuard({ env, logger, redisClient }) {
  const limits = {
    points: env.AUTH_FAIL_MAX,
    durationSec: env.AUTH_FAIL_WINDOW_SEC,
  }
  const { limiter, report } = createRateLimiter({
    name: 'auth_fail',
    ...limits,
    blockSec: env.AUTH_FAIL_BLOCK_SEC,
    redisClient,
    logger,
  })

  const keyOf = (req) => req.ip

  async function check(req, res, next) {
    try {
      const value = keyOf(req)
      if (!value) return next()

      const result = await limiter.get(String(value))
      if (!result || result.remainingPoints > 0 || result.msBeforeNext <= 0) {
        return next()
      }

      const retryAfterSec = setRateHeaders(res, result, limits)
      res.set('Retry-After', String(retryAfterSec))
      metrics.recordRateLimitRejected('auth_fail')
      return next(
        new AppError(429, 'RATE_LIMITED', 'Too many requests', { retryAfterSec })
      )
    } catch {
      report()
      return next()
    }
  }

  // Consume one point only when authentication actually fails. Crossing the
  // cap applies blockDuration explicitly (RLF only auto-blocks past points).
  async function penalize(req) {
    const value = keyOf(req)
    if (!value) return
    try {
      const result = await limiter.consume(String(value))
      if (result.consumedPoints >= limits.points) {
        await limiter.block(String(value), env.AUTH_FAIL_BLOCK_SEC)
      }
    } catch {
      // RateLimiterRes means the key is already over the cap; RLF has applied
      // the block. Store errors are failed open by the insurance limiter.
    }
  }

  return { check, penalize }
}

export function createLimiters({
  env = defaultEnv,
  logger = createLogger(env),
  redisClient,
} = {}) {
  const base = { logger, redisClient }

  const globalIp = createLimiter({
    name: 'global_ip',
    points: env.RATE_LIMIT_MAX,
    durationSec: Math.max(1, Math.ceil(env.RATE_LIMIT_WINDOW_MS / 1000)),
    keyFn: (req) => req.ip,
    ...base,
  })

  const webhooksIp = createLimiter({
    name: 'webhooks_ip',
    points: WEBHOOKS_POINTS,
    durationSec: WEBHOOKS_WINDOW_SEC,
    keyFn: (req) => req.ip,
    ...base,
  })

  const metrics = createLimiter({
    name: 'metrics',
    points: 30,
    durationSec: 60,
    keyFn: (req) => req.ip,
    ...base,
  })

  const userGeneral = createLimiter({
    name: 'user_general',
    points: env.USER_RATE_LIMIT_MAX,
    durationSec: GENERAL_WINDOW_SEC,
    keyFn: (req) => req.user?.id,
    ...base,
  })

  const shareIp = createLimiter({
    name: 'share_ip',
    points: 60,
    durationSec: 60,
    keyFn: (req) => req.ip,
    ...base,
  })

  const submitUser = createLimiter({
    name: 'submit_user',
    points: env.SUBMIT_RATE_LIMIT_USER,
    durationSec: GENERAL_WINDOW_SEC,
    keyFn: (req) => req.user?.id,
    ...base,
  })

  const submitIp = createLimiter({
    name: 'submit_ip',
    points: env.SUBMIT_RATE_LIMIT_IP,
    durationSec: GENERAL_WINDOW_SEC,
    keyFn: (req) => req.ip,
    ...base,
  })

  const authFail = createAuthFailGuard({ env, logger, redisClient })

  return {
    globalIp,
    webhooksIp,
    metrics,
    userGeneral,
    shareIp,
    submitUser,
    submitIp,
    submitLimiters: [submitIp, submitUser],
    authFail,
  }
}
