import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { Router } from 'express'
import { monitorEventLoopDelay } from 'node:perf_hooks'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { createLimiters } from '../../src/middleware/limiters.js'
import { createToolHandler } from '../../src/tools/_shared/toolRoute.js'
import { RESULT_KEYS as DNS_KEYS, schema as dnsSchema } from '../../src/tools/dns/index.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'

const silentLogger = { info() {}, warn() {}, error() {}, debug() {}, fatal() {}, trace() {} }

const baseEnv = {
  ...process.env,
  LOG_LEVEL: 'silent',
  FREE_DAILY_LIMIT: '100',
  SUBMIT_RATE_LIMIT_USER: '100',
  SUBMIT_RATE_LIMIT_IP: '200',
  TOOL_HARD_TIMEOUT_MS: '5000',
}
const env = parseEnv({ ...baseEnv, MAX_CONCURRENT_TOOL_RUNS: '2' })
const wideEnv = parseEnv({ ...baseEnv, MAX_CONCURRENT_TOOL_RUNS: '50' })

function blank(input) {
  const data = {}
  for (const key of DNS_KEYS) data[key] = key === 'target' ? input.target : null
  return data
}

function definition(execute) {
  return {
    name: 'dns',
    toolEnum: 'DNS',
    schema: dnsSchema,
    touchesTarget: false,
    dedupeTtlSec: 0,
    normalize: (input) => input,
    execute,
    emptyResult: (input) => blank(input),
    summarize: () => ({}),
  }
}

function buildApp(execute, appEnv = env) {
  const auth = makeTestAuth()
  const clerkClient = makeClerkStub()
  const limiters = createLimiters({ env: appEnv, logger: silentLogger })
  const router = Router()
  router.post(
    '/__load/dns',
    ...createToolHandler({
      definition: definition(execute),
      auth,
      clerkClient,
      env: appEnv,
      limiters,
    })
  )
  return makeTestApp({ auth, clerkClient, env: appEnv, extraRoutes: router })
}

describe('tool load and degradation', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })
  afterAll(() => disconnectRedis())

  it('runs 50 concurrent calls without blocking the event loop', async () => {
    const app = buildApp(async (input) => ({ ...blank(input), status_code: 0 }), wideEnv)
    const user = await asUser(app, { clerkId: 'load_concurrent' })
    const histogram = monitorEventLoopDelay({ resolution: 10 })
    histogram.enable()

    const calls = []
    for (let index = 0; index < 50; index += 1) {
      calls.push(
        user
          .post('/api/__load/dns')
          .send({ target: `11.0.0.${index + 1}` })
          .then((response) => response)
      )
    }
    const responses = await Promise.all(calls)
    histogram.disable()

    expect(responses.every((response) => response.status === 200)).toBe(true)
    expect(histogram.percentile(99) / 1e6).toBeLessThan(100)

    const [row] = await prisma.$queryRaw`SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname = current_database()`
    expect(row.count).toBeLessThanOrEqual(env.DB_POOL_MAX + 5)
  })

  it('returns 503 SERVER_BUSY for runs over the concurrency cap and refunds them', async () => {
    let release
    const gate = new Promise((resolve) => {
      release = resolve
    })
    let started = 0
    let ready
    const bothStarted = new Promise((resolve) => {
      ready = resolve
    })

    const app = buildApp(async (input) => {
      started += 1
      if (started === 2) ready()
      await gate
      return blank(input)
    })
    const user = await asUser(app, { clerkId: 'load_busy' })

    const first = user.post('/api/__load/dns').send({ target: '1.1.1.1' }).then((r) => r)
    const second = user.post('/api/__load/dns').send({ target: '8.8.8.8' }).then((r) => r)
    await bothStarted

    const overflow = await Promise.all(
      ['9.9.9.9', '4.4.4.4', '2.2.2.2'].map((target) =>
        user.post('/api/__load/dns').send({ target }).then((r) => r)
      )
    )
    release()

    const done = await Promise.all([first, second])
    expect(done.every((response) => response.status === 200)).toBe(true)
    expect(overflow.map((response) => response.status)).toEqual([503, 503, 503])
    expect(overflow.every((response) => response.body.error.code === 'SERVER_BUSY')).toBe(true)

    const counter = await prisma.usageCounter.findFirst({
      where: { userId: user.user.id, tool: 'DNS' },
    })
    expect(counter.used).toBe(2)
  })
})
