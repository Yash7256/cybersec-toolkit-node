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
  QUEUE_PREFIX: 'cst_async_cancel_test',
  QUEUE_MAX_WAITING: '100',
  WORKER_HEARTBEAT_SEC: '1',
  TOOL_HARD_TIMEOUT_MS: '8000',
  SUBMIT_RATE_LIMIT_USER: '200',
  SUBMIT_RATE_LIMIT_IP: '200',
})

const auth = makeTestAuth()
const clerkClient = makeClerkStub()

async function usedFor(userId) {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool: 'DNS' } })
  return row?.used ?? 0
}

describe('cancel runs', () => {
  let worker
  let tool

  beforeAll(async () => {
    tool = createAsyncTestTool({
      execute: async (input) => {
        await new Promise((resolve) => setTimeout(resolve, input.ms))
        return { target: input.target, slept: input.ms }
      },
    })
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

  it('cancels a queued run, refunds it and never executes it', async () => {
    await worker.worker.pause()
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'cancel_queued' })

    const submitted = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'cancel-queued-1')
      .send({ target: '11.2.2.1', ms: 20 })
    expect(submitted.status).toBe(202)
    expect(await usedFor(user.user.id)).toBe(1)

    const cancelled = await user.post(`/api/runs/${submitted.body.runId}/cancel`)
    expect(cancelled.status).toBe(200)
    expect(cancelled.body.status).toBe('CANCELLED')
    expect(await usedFor(user.user.id)).toBe(0)

    await worker.worker.resume()
    await new Promise((resolve) => setTimeout(resolve, 300))
    expect(tool.calls).toHaveLength(0)
  })

  it('cancels a running run within one heartbeat without refunding', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'cancel_running' })

    const submitted = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'cancel-running-1')
      .send({ target: '11.2.2.2', ms: 6000 })
    expect(submitted.status).toBe(202)

    await waitFor(async () => {
      const poll = await user.get(`/api/runs/${submitted.body.runId}`)
      return poll.body.status === 'RUNNING'
    })

    const cancel = await user.post(`/api/runs/${submitted.body.runId}/cancel`)
    expect(cancel.status).toBe(202)
    expect(cancel.body).toEqual({ status: 'RUNNING', cancelRequested: true })

    const done = await waitFor(async () => {
      const poll = await user.get(`/api/runs/${submitted.body.runId}`)
      return poll.body.status === 'CANCELLED' ? poll.body : null
    })
    expect(await usedFor(user.user.id)).toBe(1)
  }, 15000)

  it('rejects cancelling a terminal run', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'cancel_terminal' })

    const submitted = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'cancel-terminal-1')
      .send({ target: '11.2.2.3', ms: 20 })
    await waitFor(async () => {
      const poll = await user.get(`/api/runs/${submitted.body.runId}`)
      return poll.body.status === 'COMPLETED'
    })

    const res = await user.post(`/api/runs/${submitted.body.runId}/cancel`)
    expect(res.status).toBe(409)
    expect(res.body.error.code).toBe('RUN_NOT_CANCELLABLE')
  })

  it('returns 404 for another user poll and cancel', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const owner = await asUser(app, { clerkId: 'cancel_owner' })
    const other = await asUser(app, { clerkId: 'cancel_other' })

    const submitted = await owner
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'cancel-idor-1')
      .send({ target: '11.2.2.4', ms: 20 })

    expect((await other.get(`/api/runs/${submitted.body.runId}`)).status).toBe(404)
    expect((await other.post(`/api/runs/${submitted.body.runId}/cancel`)).status).toBe(404)
  })
})
