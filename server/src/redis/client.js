import Redis from 'ioredis'
import { env } from '../config/env.js'
import { createLogger } from '../utils/logger.js'

const defaultLogger = createLogger(env)
let singleton = null

// Factory so tests can point at TEST_REDIS_URL or a deliberately dead port.
export function createRedisClient(url, { logger = defaultLogger } = {}) {
  const client = new Redis(url, {
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    connectTimeout: 3000,
    retryStrategy: (attempt) => Math.min(attempt * 200, 5000),
  })

  // Never log the URL: it can contain credentials.
  client.on('ready', () => logger.info('redis ready'))
  client.on('reconnecting', () => logger.info('redis reconnecting'))
  client.on('error', (err) => logger.warn({ err: err.message }, 'redis error'))

  return client
}

export function getRedisClient() {
  if (!singleton) singleton = createRedisClient(env.REDIS_URL)
  return singleton
}

// Resolves true/false, never throws: boot continues degraded when false.
export function waitForReady(timeoutMs = 5000, client = getRedisClient()) {
  if (client.status === 'ready') return Promise.resolve(true)

  return new Promise((resolve) => {
    let settled = false
    let timer
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      client.off('ready', onReady)
      resolve(value)
    }
    const onReady = () => finish(true)
    timer = setTimeout(() => finish(false), timeoutMs)
    client.once('ready', onReady)
  })
}

export async function pingRedis({ timeoutMs = 1500, client = getRedisClient() } = {}) {
  let timer
  try {
    const result = await Promise.race([
      client.ping(),
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('redis ping timeout')), timeoutMs)
      }),
    ])
    return result === 'PONG'
  } catch {
    return false
  } finally {
    clearTimeout(timer)
  }
}

export function disconnectRedis() {
  if (!singleton) return
  const client = singleton
  singleton = null
  try {
    client.disconnect()
  } catch {
    // already closed
  }
}
