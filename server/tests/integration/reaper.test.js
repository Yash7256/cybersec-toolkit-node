import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { runReaper } from '../../src/maintenance/reaper.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'
import {
  closeAsyncQueues,
  createAsyncTestTool,
  obliterateQueues,
  startEmbeddedWorker,
  stopEmbeddedWorker,
  waitFor,
} from '../helpers/asyncTestTool.js'

const baseEnv = {
  ...process.env,
  LOG_LEVEL: 'silent',
  QUEUE_PREFIX: 'cst_phase6_reaper_test',
  WORKER_HEARTBEAT_SEC: '1',
  RUN_MAX_ATTEMPTS: '2',
  TOOL_HARD_TIMEOUT_MS: '1000',
}
const env = parseEnv({ ...baseEnv, RUN_STALL_SEC: '4', ORPHAN_QUEUED_SEC: '1', QUEUE_MAX_WAIT_SEC: '100' })
const noOrphanEnv = parseEnv({ ...baseEnv, RUN_STALL_SEC: '4', ORPHAN_QUEUED_SEC: '100', QUEUE_MAX_WAIT_SEC: '1' })

const auth = makeTestAuth()
const clerkClient = makeClerkStub()

async function createRun(userId, { status = 'QUEUED', tool = 'DNS' } = {}) {
  const run = await runRepo.createQueuedWithCap({
    userId,
    tool,
    target: '11.9.9.9',
    targetKey: '11.9.9.9',
    options: { target: '11.9.9.9' },
    cap: 100,
  })
  if (status === 'RUNNING') {
    await prisma.toolRun.update({
      where: { id: run.id },
      data: { status: 'RUNNING', workerId: 'w-test', attempt: 1, startedAt: new Date(), heartbeatAt: new Date() },
    })
  }
  return run
}

describe('reaper', () => {
  let worker
  let tool

  beforeAll(async () => {
    tool = createAsyncTestTool({ execute: async (input) => ({ target: input.target, slept: 0 }) })
    worker = await startEmbeddedWorker({ env, definitions: { test: tool.definition } })
  })

  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
    await obliterateQueues(env)
    tool.calls.length = 0
    await worker.worker.pause()
  })

  afterAll(async () => {
    await stopEmbeddedWorker(worker)
    await closeAsyncQueues()
    await disconnectRedis()
  })

  it('re-enqueues an orphan QUEUED run and processes it once', async () => {
    const user = await asUser(makeApp(), { clerkId: 'reaper_orphan' })
    const run = await createRun(user.user.id)
    await prisma.toolRun.update({ where: { id: run.id }, data: { queuedAt: new Date(Date.now() - 2000) } })

    const result = await runReaper({ env })
    expect(result.requeued).toBeGreaterThanOrEqual(1)

    await worker.worker.resume()
    await waitFor(async () => {
      const row = await prisma.toolRun.findUnique({ where: { id: run.id } })
      return row.status === 'COMPLETED'
    })
    expect(tool.calls).toHaveLength(1)
  })

  it('fails a QUEUED run that waited too long and refunds it', async () => {
    const user = await asUser(makeApp(), { clerkId: 'reaper_stale_queued' })
    const run = await createRun(user.user.id)
    await prisma.toolRun.update({ where: { id: run.id }, data: { queuedAt: new Date(Date.now() - 5000) } })
    await prisma.usageCounter.create({
      data: { userId: user.user.id, tool: 'DNS', usageDate: new Date(), used: 1 },
    })
    await prisma.toolRun.update({ where: { id: run.id }, data: { quotaDate: new Date() } })

    await runReaper({ env: noOrphanEnv })
    const row = await prisma.toolRun.findUnique({ where: { id: run.id } })
    expect(row.status).toBe('FAILED')
    expect(row.errorCode).toBe('QUEUE_TIMEOUT')
    expect(row.quotaRefunded).toBe(true)
  })

  it('leaves a heartbeating RUNNING run untouched', async () => {
    const user = await asUser(makeApp(), { clerkId: 'reaper_heartbeat' })
    const run = await createRun(user.user.id, { status: 'RUNNING' })
    await prisma.toolRun.update({ where: { id: run.id }, data: { startedAt: new Date(Date.now() - 500) } })

    await runReaper({ env })
    const row = await prisma.toolRun.findUnique({ where: { id: run.id } })
    expect(row.status).toBe('RUNNING')
    expect(row.workerId).toBe('w-test')
  })

  it('times out an overlong RUNNING run and refunds once', async () => {
    const user = await asUser(makeApp(), { clerkId: 'reaper_overlong' })
    const run = await createRun(user.user.id, { status: 'RUNNING' })
    await prisma.usageCounter.create({
      data: { userId: user.user.id, tool: 'DNS', usageDate: new Date(), used: 1 },
    })
    await prisma.toolRun.update({
      where: { id: run.id },
      data: { startedAt: new Date(Date.now() - 5000), heartbeatAt: new Date(), quotaDate: new Date() },
    })

    await runReaper({ env })
    const row = await prisma.toolRun.findUnique({ where: { id: run.id } })
    expect(row.status).toBe('TIMED_OUT')
    expect(row.errorCode).toBe('TOOL_TIMEOUT')
    expect(row.quotaRefunded).toBe(true)

    await runReaper({ env })
    const counter = await prisma.usageCounter.findFirst({ where: { userId: user.user.id, tool: 'DNS' } })
    expect(counter.used).toBe(0)
  })

  it('reclaims a stale RUNNING run once across parallel reaper passes', async () => {
    const user = await asUser(makeApp(), { clerkId: 'reaper_parallel' })
    const run = await createRun(user.user.id, { status: 'RUNNING' })
    await prisma.toolRun.update({
      where: { id: run.id },
      data: { heartbeatAt: new Date(Date.now() - 5000), startedAt: new Date(Date.now() - 5000) },
    })

    const [a, b] = await Promise.all([runReaper({ env }), runReaper({ env })])
    expect(a.requeued + b.requeued).toBe(1)
    const row = await prisma.toolRun.findUnique({ where: { id: run.id } })
    expect(row.status).toBe('QUEUED')
    expect(row.attempt).toBe(1)
  })
})

function makeApp() {
  return makeTestApp({ env, auth, clerkClient })
}
