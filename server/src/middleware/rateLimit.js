import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible'
import { env as defaultEnv } from '../config/env.js'
import { getRedisClient } from '../redis/client.js'
import { createLogger } from '../utils/logger.js'
import { metrics } from '../observability/metrics.js'
import AppError from '../utils/AppError.js'

const defaultLogger = createLogger(defaultEnv)

function storeReporter(name, logger) {
  let lastLogAt = 0
  return (err) => {
    metrics.recordRateLimitStoreError(name)
    const now = Date.now()
    if (now - lastLogAt >= 30_000) {
      lastLogAt = now
      logger.warn({ limiter: name, err: err?.message }, 'rate limit store error; failing open')
    }
  }
}

// Wrap the ioredis client so store failures are visible (and counted) while
// still letting rate-limiter-flexible fall back to its memory insurance.
function instrumentStore(client, onStoreError) {
  const wrapped = new Map()

  return new Proxy(client, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target)
      if (typeof value !== 'function' || prop === 'constructor' || prop === 'then') {
        return value
      }
      if (wrapped.has(prop)) return wrapped.get(prop)

      const fn = (...args) => {
        let result
        try {
          result = value.apply(target, args)
        } catch (err) {
          onStoreError(err)
          throw err
        }
        if (result && typeof result.then === 'function') {
          return result.catch((err) => {
            onStoreError(err)
            throw err
          })
        }
        return result
      }

      wrapped.set(prop, fn)
      return fn
    },
  })
}

export function setRateHeaders(res, result, { points, durationSec }) {
  const resetSec = Math.max(0, Math.ceil(result.msBeforeNext / 1000))
  res.set('RateLimit-Limit', String(points))
  res.set('RateLimit-Remaining', String(Math.max(0, result.remainingPoints)))
  res.set('RateLimit-Reset', String(resetSec))
  res.set('RateLimit-Policy', `${points};w=${durationSec}`)
  return resetSec
}

export function createRateLimiter({
  name,
  points,
  durationSec,
  blockSec = 0,
  redisClient = getRedisClient(),
  logger = defaultLogger,
} = {}) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('createRateLimiter requires a name')
  }
  if (!Number.isInteger(points) || points < 1 || durationSec < 1) {
    throw new Error(`invalid limiter configuration for ${name}`)
  }

  const report = storeReporter(name, logger)
  const storeClient = instrumentStore(redisClient, report)

  const limiter = new RateLimiterRedis({
    storeClient,
    keyPrefix: `cst:rl:${name}`,
    points,
    duration: durationSec,
    blockDuration: blockSec,
    rejectIfRedisNotReady: true,
    insuranceLimiter: new RateLimiterMemory({
      points,
      duration: durationSec,
      blockDuration: blockSec,
    }),
  })

  return { limiter, report, client: storeClient }
}

export function createLimiter({ keyFn = (req) => req.ip, skip, ...options } = {}) {
  const { name, points, durationSec } = options
  const { limiter, report, client } = createRateLimiter(options)

  return async function rateLimiter(req, res, next) {
    try {
      if (skip && skip(req)) return next()
      const value = keyFn(req)
      if (!value) return next()

      // RLF rejects before touching the store when the client is not ready and
      // then silently uses insurance, so surface that failure here.
      if (typeof client.status === 'string' && client.status !== 'ready') {
        report()
      }

      const result = await limiter.consume(String(value))
      setRateHeaders(res, result, { points, durationSec })
      return next()
    } catch (err) {
      // A RateLimiterRes is a plain object; only a real Error means the store
      // itself failed. Those are failed open here (insurance already applied).
      if (err instanceof Error) {
        report(err)
        return next()
      }

      const retryAfterSec = setRateHeaders(res, err, { points, durationSec })
      res.set('Retry-After', String(retryAfterSec))
      metrics.recordRateLimitRejected(name)
      return next(
        new AppError(429, 'RATE_LIMITED', 'Too many requests', { retryAfterSec })
      )
    }
  }
}
