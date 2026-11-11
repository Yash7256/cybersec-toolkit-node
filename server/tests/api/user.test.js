import { describe, it, expect, beforeEach } from 'vitest'
import { consume } from '../../src/db/repos/usageRepo.js'
import { ToolName } from '../../src/generated/prisma/enums.ts'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeTestApp } from '../helpers/auth.js'

const ALL_TOOLS = Object.values(ToolName)

describe('user endpoints', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('GET /api/user/me is no-store and hides internals', async () => {
    const app = makeTestApp()
    const agent = await asUser(app, { clerkId: 'clerk_me' })

    const res = await agent.get('/api/user/me')

    expect(res.status).toBe(200)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(Object.keys(res.body).sort()).toEqual(
      ['createdAt', 'email', 'id', 'role', 'tier'].sort()
    )
  })

  it('GET /api/user/usage lists every tool at used 0 for a FREE user', async () => {
    const app = makeTestApp()
    const agent = await asUser(app, { clerkId: 'clerk_free', tier: 'FREE' })

    const res = await agent.get('/api/user/usage')

    expect(res.status).toBe(200)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.body.date).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(new Date(res.body.resetsAt).toISOString()).toBe(res.body.resetsAt)
    expect(res.body.tiers).toEqual({ tier: 'FREE' })
    expect(res.body.tools).toHaveLength(ALL_TOOLS.length)
    expect(res.body.tools.map((entry) => entry.tool).sort()).toEqual([...ALL_TOOLS].sort())
    for (const entry of res.body.tools) {
      expect(entry).toMatchObject({ used: 0, limit: 5, remaining: 5 })
    }
  })

  it('reflects consumed usage in limit/remaining', async () => {
    const app = makeTestApp()
    const agent = await asUser(app, { clerkId: 'clerk_used', tier: 'FREE' })
    await consume({ userId: agent.user.id, tool: 'DNS', limit: 5 })

    const res = await agent.get('/api/user/usage')
    const dns = res.body.tools.find((entry) => entry.tool === 'DNS')

    expect(dns).toMatchObject({ used: 1, limit: 5, remaining: 4 })
  })

  it('reports null limits for an ADMIN', async () => {
    const app = makeTestApp()
    const agent = await asUser(app, { clerkId: 'clerk_admin', role: 'ADMIN' })

    const res = await agent.get('/api/user/usage')

    expect(res.status).toBe(200)
    expect(res.body.tiers).toEqual({ tier: 'FREE' })
    for (const entry of res.body.tools) {
      expect(entry).toMatchObject({ limit: null, remaining: null })
    }
  })
})
