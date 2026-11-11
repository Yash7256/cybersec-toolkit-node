import { describe, it, expect, afterEach } from 'vitest'
import { createRedisClient, pingRedis, waitForReady } from '../../src/redis/client.js'
import { key } from '../../src/redis/keys.js'
import { flushTestRedis } from '../helpers/redis.js'

const silent = { info() {}, warn() {}, error() {} }
const TEST_URL = process.env.TEST_REDIS_URL

describe('redis client', () => {
  const clients = []

  const make = (url = TEST_URL) => {
    const client = createRedisClient(url, { logger: silent })
    clients.push(client)
    return client
  }

  afterEach(() => {
    for (const client of clients.splice(0)) client.disconnect()
  })

  it('pings the test Redis', async () => {
    await flushTestRedis()
    const client = make()
    await waitForReady(2000, client)
    expect(await pingRedis({ client })).toBe(true)
  })

  it('waitForReady resolves true for a live server', async () => {
    const client = make()
    expect(await waitForReady(2000, client)).toBe(true)
  })

  it('rejects commands fast when the server is down (no offline queue)', async () => {
    const client = make('redis://127.0.0.1:6399')
    const started = Date.now()
    await expect(client.ping()).rejects.toBeTruthy()
    expect(Date.now() - started).toBeLessThan(500)
  })

  it('waitForReady resolves false instead of throwing when down', async () => {
    const client = make('redis://127.0.0.1:6399')
    expect(await waitForReady(300, client)).toBe(false)
  })
})

describe('redis key builder', () => {
  it('builds cst:<area>:<name>:<id>', () => {
    expect(key('rl', 'global_ip', '1.2.3.4')).toBe('cst:rl:global_ip:1.2.3.4')
  })

  it('sanitizes colons in ids', () => {
    expect(key('rl', 'user', 'a:b:c')).toBe('cst:rl:user:a_b_c')
  })

  it('rejects empty and oversized parts', () => {
    expect(() => key('rl', '', 'x')).toThrow(/non-empty/)
    expect(() => key('rl', 'user', 'x'.repeat(201))).toThrow(/exceeds/)
    expect(() => key('rl', 'user', 42)).toThrow(/non-empty/)
  })
})
