import { createRedisClient, waitForReady } from '../../src/redis/client.js'

const silent = { info() {}, warn() {}, error() {} }

// FLUSHDB is destructive: only ever run it against the dedicated test DB index.
export async function flushTestRedis() {
  const url = process.env.TEST_REDIS_URL
  if (!url || !url.endsWith('/1')) {
    throw new Error('TEST_REDIS_URL must point at a dedicated Redis DB index (…/1)')
  }
  const client = createRedisClient(url, { logger: silent })
  try {
    if (!(await waitForReady(2000, client))) throw new Error('test Redis is not reachable')
    await client.flushdb()
  } finally {
    client.disconnect()
  }
}
