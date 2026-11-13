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
  QUEUE_PREFIX: 'cst_async_idem_test',
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

describe('idempotency', () => {
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

  it('replays a completed submission with the same key and no extra quota', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'idem_sequential' })

    const first = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'idem-sequential-1')
      .send({ target: '11.3.3.1', ms: 20 })
    expect(first.status).toBe(202)

    await waitFor(async () => {
      const poll = await user.get(`/api/runs/${first.body.runId}`)
      return poll.body.status === 'COMPLETED'
    })

    const second = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'idem-sequential-1')
      .send({ target: '11.3.3.1', ms: 20 })
    expect([200, 202]).toContain(second.status)
    expect(second.headers['idempotent-replayed']).toBe('true')
    expect(second.body.runId).toBe(first.body.runId)
    expect(await usedFor(user.user.id)).toBe(1)
    expect(tool.calls).toHaveLength(1)
  })

  it('creates exactly one run for parallel requests with the same key', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'idem_parallel' })

    const responses = await Promise.all(
      Array.from({ length: 10 }, () =>
        user
          .post('/api/__async/sleep')
          .set('Idempotency-Key', 'idem-parallel-1')
          .send({ target: '11.3.3.2', ms: 100 })
          .then((response) => response)
      )
    )

    const runIds = new Set(
      responses.filter((response) => response.body?.runId).map((response) => response.body.runId)
    )
    expect(runIds.size).toBe(1)
    expect(
      responses.every((response) => [200, 202, 409].includes(response.status))
    ).toBe(true)
    expect(await usedFor(user.user.id)).toBe(1)

    const runId = [...runIds][0]
    await waitFor(async () => {
      const poll = await user.get(`/api/runs/${runId}`)
      return poll.body.status === 'COMPLETED'
    })
    expect(tool.calls).toHaveLength(1)
  })

  it('does not leak worker ids, redis keys or stack traces', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'idem_leak' })

    const res = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'idem-leak-1')
      .send({ target: '11.3.3.3', ms: 20 })
    const serialized = JSON.stringify(res.body)
    expect(serialized).not.toContain('worker_id')
    expect(serialized).not.toContain('cst_async_idem_test')
    expect(serialized).not.toContain('at ')
  })

  it('releases the key when submission fails before enqueue', async () => {
    const app = buildAsyncApp({ env, definition: tool.definition, auth, clerkClient })
    const user = await asUser(app, { clerkId: 'idem_release' })

    const blocked = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'idem-release-1')
      .send({ target: '10.0.0.1', ms: 20 })
    expect(blocked.status).toBe(422)

    const ok = await user
      .post('/api/__async/sleep')
      .set('Idempotency-Key', 'idem-release-1')
      .send({ target: '11.3.3.4', ms: 20 })
    expect(ok.status).toBe(202)
    expect(await usedFor(user.user.id)).toBe(1)
  })
})
