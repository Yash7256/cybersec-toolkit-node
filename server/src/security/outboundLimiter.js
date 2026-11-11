import { env as defaultEnv } from '../config/env.js'
import { getRedisClient } from '../redis/client.js'
import { createLogger } from '../utils/logger.js'
import { createRateLimiter } from '../middleware/rateLimit.js'
import AppError from '../utils/AppError.js'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export function createOutboundLimiter({
  name,
  points,
  durationSec,
  maxWaitMs = 5000,
  redisClient = getRedisClient(),
  logger = createLogger(defaultEnv),
} = {}) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('createOutboundLimiter requires a name')
  }
  if (!Number.isInteger(points) || points < 1 || durationSec < 1) {
    throw new Error(`invalid outbound limiter configuration for ${name}`)
  }

  const { limiter, report } = createRateLimiter({
    name,
    points,
    durationSec,
    redisClient,
    logger,
  })

  async function acquire(cost = 1) {
    if (!Number.isInteger(cost) || cost < 1) {
      throw new Error('outbound limiter cost must be a positive integer')
    }
    if (cost > points) {
      throw new AppError(503, 'UPSTREAM_BUSY', 'Upstream capacity is busy')
    }

    const deadline = Date.now() + Math.max(0, maxWaitMs)

    for (;;) {
      try {
        await limiter.consume('shared', cost)
        return
      } catch (err) {
        if (err instanceof Error) {
          report()
          return
        }

        const waitMs = Math.max(0, err.msBeforeNext)
        if (Date.now() + waitMs > deadline) {
          throw new AppError(503, 'UPSTREAM_BUSY', 'Upstream capacity is busy', {
            retryAfterSec: Math.ceil(waitMs / 1000),
          })
        }
        await sleep(waitMs)
      }
    }
  }

  return { acquire }
}
