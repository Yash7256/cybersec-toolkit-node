import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { Router } from 'express'
import { z } from 'zod'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { createLimiters } from '../../src/middleware/limiters.js'
import { createToolHandler } from '../../src/tools/_shared/toolRoute.js'
import { ToolError } from '../../src/tools/_shared/errors.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'

const silentLogger = { info() {}, warn() {}, error() {}, debug() {}, fatal() {}, trace() {} }

function makeEnv(overrides = {}) {
  return parseEnv({
    ...process.env,
    LOG_LEVEL: 'silent',
    FREE_DAILY_LIMIT: '5',
    ...overrides,
  })
}

function fakeDefinition(execute) {
  return {
    name: 'fake',
    toolEnum: 'DNS',
    schema: z.object({ target: z.string().trim().min(1) }),
    touchesTarget: false,
    dedupeTtlSec: 60,
    normalize: (input) => input,
    execute,
    emptyResult: (input) => ({ target: input.target, error: null }),
    summarize: () => ({}),
  }
}

function buildApp(env, execute) {
  const auth = makeTestAuth()
  const clerkClient = makeClerkStub()
  const limiters = createLimiters({ env, logger: silentLogger })
  const definition = fakeDefinition(execute)
  const router = Router()
  router.post(
    '/__t/fake',
    ...createToolHandler({ definition, auth, clerkClient, env, limiters })
  )
  return makeTestApp({ auth, clerkClient, env, extraRoutes: router })
}

async function usedFor(userId) {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool: 'DNS' } })
  return row?.used ?? 0
}

describe('tool route factory', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })
  afterAll(() => disconnectRedis())

  it('rejects invalid input without consuming quota', async () => {
    const app = buildApp(makeEnv(), async () => ({ ok: true }))
    const user = await asUser(app, { clerkId: 'route_invalid' })
    const res = await user.post('/api/__t/fake').send({ nope: true })
    expect(res.status).toBe(400)
    expect(await usedFor(user.user.id)).toBe(0)
  })

  it('maps an upstream error to 502 and refunds quota', async () => {
    const app = buildApp(makeEnv(), async () => {
      throw new ToolError('upstream', 'Lookup service unavailable')
    })
    const user = await asUser(app, { clerkId: 'route_upstream' })
    const res = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(res.status).toBe(502)
    expect(res.body.error.code).toBe('UPSTREAM_ERROR')
    expect(await usedFor(user.user.id)).toBe(0)
    const run = await prisma.toolRun.findFirst({ where: { userId: user.user.id } })
    expect(run.status).toBe('FAILED')
  })

  it('completes a target error with 200 and keeps the quota consumed', async () => {
    const app = buildApp(makeEnv(), async () => {
      throw new ToolError('target', 'Target returned an invalid response')
    })
    const user = await asUser(app, { clerkId: 'route_target' })
    const res = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(res.status).toBe(200)
    expect(res.body.data.error).toBe('Target returned an invalid response')
    expect(await usedFor(user.user.id)).toBe(1)
  })

  it('times out a hung tool, refunds quota and marks the run TIMED_OUT', async () => {
    const app = buildApp(makeEnv({ TOOL_HARD_TIMEOUT_MS: '150' }), () => new Promise(() => {}))
    const user = await asUser(app, { clerkId: 'route_timeout' })
    const res = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(res.status).toBe(504)
    expect(res.body.error.code).toBe('TOOL_TIMEOUT')
    expect(await usedFor(user.user.id)).toBe(0)
    const run = await prisma.toolRun.findFirst({ where: { userId: user.user.id } })
    expect(run.status).toBe('TIMED_OUT')
  })

  it('serves a dedupe hit without executing or consuming quota', async () => {
    let calls = 0
    const app = buildApp(makeEnv(), async () => {
      calls += 1
      return { records: [] }
    })
    const user = await asUser(app, { clerkId: 'route_dedupe' })

    const first = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(first.status).toBe(200)
    expect(first.body.cached).toBe(false)

    const second = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(second.status).toBe(200)
    expect(second.body.cached).toBe(true)
    expect(second.body.runId).toBe(first.body.runId)
    expect(calls).toBe(1)
    expect(await usedFor(user.user.id)).toBe(1)
  })

  it('returns 503 when the concurrency semaphore is full and refunds the loser', async () => {
    let release
    const gate = new Promise((resolve) => {
      release = resolve
    })
    const app = buildApp(makeEnv({ MAX_CONCURRENT_TOOL_RUNS: '1' }), async () => {
      await gate
      return { ok: true }
    })
    const user = await asUser(app, { clerkId: 'route_busy' })

    const first = user.post('/api/__t/fake').send({ target: 'a.example' }).then((response) => response)
    await new Promise((resolve) => setTimeout(resolve, 20))
    const second = await user.post('/api/__t/fake').send({ target: 'b.example' })
    release()
    const firstResult = await first

    expect(firstResult.status).toBe(200)
    expect(second.status).toBe(503)
    expect(second.body.error.code).toBe('SERVER_BUSY')
    expect(await usedFor(user.user.id)).toBe(1)
  })

  it('truncates an oversized result', async () => {
    const app = buildApp(makeEnv(), async () => ({ blob: 'x'.repeat(600 * 1024) }))
    const user = await asUser(app, { clerkId: 'route_truncate' })
    const res = await user.post('/api/__t/fake').send({ target: 'example.com' })
    expect(res.status).toBe(200)
    expect(res.body.data.truncated).toBe(true)
    expect(Buffer.byteLength(JSON.stringify(res.body.data))).toBeLessThanOrEqual(512 * 1024)
  })
})
