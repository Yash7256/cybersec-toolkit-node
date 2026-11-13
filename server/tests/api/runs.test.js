import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import * as runRepo from '../../src/db/repos/runRepo.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeTestApp } from '../helpers/auth.js'

const env = parseEnv({ ...process.env, LOG_LEVEL: 'silent' })

async function seedCompleted(userId, index) {
  const run = await runRepo.start({
    userId,
    tool: index % 2 === 0 ? 'DNS' : 'SSL',
    target: `example-${index}.com`,
    targetKey: `example-${index}.com`,
  })
  await runRepo.complete(run.id, { data: { index }, summary: { index } })
  await prisma.toolRun.update({
    where: { id: run.id },
    data: { createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)) },
  })
  return run
}

describe('runs API', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })
  afterAll(() => disconnectRedis())

  it('paginates across pages without duplicates', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'runs_page' })
    for (let index = 0; index < 5; index += 1) await seedCompleted(user.user.id, index)

    const seen = new Set()
    let cursor = null
    for (let page = 0; page < 5; page += 1) {
      const url = `/api/runs?limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
      const res = await user.get(url)
      expect(res.status).toBe(200)
      expect(res.headers['cache-control']).toBe('no-store')
      for (const run of res.body.runs) seen.add(run.id)
      cursor = res.body.nextCursor
      if (!cursor) break
    }
    expect(seen.size).toBe(5)
  })

  it('filters by tool', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'runs_filter' })
    for (let index = 0; index < 4; index += 1) await seedCompleted(user.user.id, index)

    const res = await user.get('/api/runs?tool=SSL')
    expect(res.status).toBe(200)
    expect(res.body.runs).toHaveLength(2)
    expect(res.body.runs.every((run) => run.tool === 'SSL')).toBe(true)
  })

  it('rejects a malformed cursor', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'runs_cursor' })
    const res = await user.get('/api/runs?cursor=not-base64')
    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
  })

  it('returns 404 for another user run', async () => {
    const app = makeTestApp({ env })
    const owner = await asUser(app, { clerkId: 'runs_owner' })
    const other = await asUser(app, { clerkId: 'runs_other' })
    const run = await seedCompleted(owner.user.id, 0)

    expect((await owner.get(`/api/runs/${run.id}`)).status).toBe(200)
    const forbidden = await other.get(`/api/runs/${run.id}`)
    expect(forbidden.status).toBe(404)
    expect(forbidden.body.error.code).toBe('NOT_FOUND')
  })

  it('returns the stored result data on run detail', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'runs_detail' })
    const run = await seedCompleted(user.user.id, 3)
    const res = await user.get(`/api/runs/${run.id}`)
    expect(res.status).toBe(200)
    expect(res.body.data).toEqual({ index: 3 })
    expect(res.headers['cache-control']).toBe('no-store')
  })

  it('exposes the tool catalogue', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'runs_catalogue' })
    const res = await user.get('/api/tools')
    expect(res.status).toBe(200)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.body).toHaveLength(10)
    for (const tool of res.body) {
      expect(tool).toMatchObject({
        name: expect.any(String),
        label: expect.any(String),
        description: expect.any(String),
        touchesTarget: expect.any(Boolean),
        dailyLimit: env.FREE_DAILY_LIMIT,
      })
      expect(Array.isArray(tool.input)).toBe(true)
      expect(tool.input.length).toBeGreaterThan(0)
    }
    expect(res.body.find((tool) => tool.name === 'port_scan')).toMatchObject({
      touchesTarget: true,
      async: true,
    })
  })
})
