import { env as defaultEnv } from '../../config/env.js'
import { createOutboundLimiter } from '../../security/outboundLimiter.js'
import { getRedisClient } from '../../redis/client.js'

export function createSemaphore({ limit = 1 } = {}) {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error('createSemaphore requires a positive integer limit')
  }
  let active = 0
  const waiters = []

  function release() {
    active -= 1
    const next = waiters.shift()
    if (next) next()
  }

  function acquire() {
    if (active < limit) {
      active += 1
      return Promise.resolve(release)
    }
    return new Promise((resolve) => {
      waiters.push(() => {
        active += 1
        resolve(release)
      })
    })
  }

  return {
    acquire,
    get active() {
      return active
    },
    get waiting() {
      return waiters.length
    },
    get limit() {
      return limit
    },
  }
}

export function createLimits({
  env = defaultEnv,
  redisClient = getRedisClient(),
} = {}) {
  const semaphore = createSemaphore({ limit: env.GEOIP_MAX_CONCURRENT })
  const outbound = createOutboundLimiter({
    name: 'geoip',
    points: env.GEOIP_RATE_PER_MIN,
    durationSec: 60,
    maxWaitMs: 5000,
    redisClient,
  })

  return {
    semaphore,
    async withGeoipSlot(fn) {
      const release = await semaphore.acquire()
      try {
        return await fn()
      } finally {
        release()
      }
    },
    acquireGeoipRate() {
      return outbound.acquire()
    },
  }
}
