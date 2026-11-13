import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestAuth } from '../helpers/auth.js'
import {
  buildAsyncApp,
  closeAsyncQueues,
  createAsyncTestTool,
  obliterateQueues,
  startEmbeddedWorker,
  stopEmbeddedWorker,
  waitFor,
} from '../helpers/asyncTestTool.js'

const env = parseEnv({
  ...process.env,
  LOG_LEVEL: 'silent',
  FREE_DAILY_LIMIT: '100',
  PAID_DAILY_LIMIT: '100',
  MAX_ACTIVE_RUNS_FREE: '2',
  MAX_ACTIVE_RUNS_PAID: '10',
  QUEUE_PREFIX: 'cst_async_runs_test',
  QUEUE_MAX_WAITING: '100',
  WORKER_HEARTBEAT_SEC: '1',
  TOOL_HARD_TIMEOUT_MS: '5000',
  SUBMIT_RATE_LIMIT_USER: '200',
  SUBMIT_RATE_LIMIT_IP: '200',
})

const auth = makeTestAuth()
const clerkClient = makeClerkStub()

async function usedFor(userId, tool = 'DNS') {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool } })
  return row?.used ?? 0
}

describe('async runs', () => {
  let worker
  let tool

  beforeAll(async () => {
    tool = createAsyncTestTool({ execute: async (input) => {
      await new Promise((resolve) => setTimeout(resolve, input.ms))
      return { target: input.target, slept: input.ms }
    } })
    worker = await startEmbeddedWorker({ env, definitions: { test: tool.definition } })
  })

  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
    await obliterateQueues(env)
    tool.calls.length = 0
  })

  afterAll(async () => {
    await stopEmbeddedWorker(worker)
    await closeAsyncQueues()
    await disconnectRedis()
  })

  it('submits, polls and returns completed data', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'async_submit' })

    const res = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'async-submit-1')
      .send({ target: '93.184.216.34', ms: 30 })
    expect(res.status).toBe(202)
    expect(res.headers.location).toBe(`/api/runs/${res.body.runId}`)
    expect(res.body.status).toBe('QUEUED')
    expect(res.body.pollUrl).toBe(`/api/runs/${res.body.runId}`)

    const detail = await waitFor(async () => {
      const poll = await user.get(`/api/runs/${res.body.runId}`)
      return poll.body.status === 'COMPLETED' ? poll.body : null
    })
    expect(detail.data).toEqual({ target: '93.184.216.34', slept: 30 })
    expect(detail.pollAfterMs).toBeUndefined()
    expect(await usedFor(user.user.id)).toBe(1)
  })

  it('enforces the active-run cap and refunds the loser', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'async_cap' })

    const submissions = await Promise.all(
      ['a', 'b', 'c'].map((name, index) =>
        user
          .post('/api/__async/sleep')
          .set('Idempotency-Key', `async-cap-${name}-${index}`)
          .send({ target: '93.184.216.34', ms: 800 })
          .then((response) => response)
      )
    )
    const accepted = submissions.filter((response) => response.status === 202)
    const rejected = submissions.filter((response) => response.status === 429)
    expect(accepted).toHaveLength(2)
    expect(rejected).toHaveLength(1)
    expect(rejected[0].body.error.code).toBe('TOO_MANY_ACTIVE_RUNS')
    expect(await usedFor(user.user.id)).toBe(2)
  })

  it('runs PAID work before FREE work', async () => {
    await worker.worker.pause()
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const free = await asUser(app, { clerkId: 'async_priority_free', tier: 'FREE' })
    const paid = await asUser(app, { clerkId: 'async_priority_paid', tier: 'PAID' })

    const freeRes = await free
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'async-priority-free')
      .send({ target: '11.1.1.1', ms: 20 })
    const paidRes = await paid
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'async-priority-paid')
      .send({ target: '11.1.1.2', ms: 20 })
    expect(freeRes.status).toBe(202)
    expect(paidRes.status).toBe(202)

    await worker.worker.resume()
    await waitFor(async () => {
      const [a, b] = await Promise.all([
        free.get(`/api/runs/${freeRes.body.runId}`),
        paid.get(`/api/runs/${paidRes.body.runId}`),
      ])
      return a.body.status === 'COMPLETED' && b.body.status === 'COMPLETED'
    })
    expect(tool.calls.map((call) => call.target)).toEqual(['11.1.1.2', '11.1.1.1'])
  })
})
