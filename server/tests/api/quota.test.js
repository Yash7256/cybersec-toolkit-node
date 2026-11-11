import { describe, it, expect, beforeEach } from 'vitest'
import { Router } from 'express'
import { z } from 'zod'
import { prisma } from '../../src/db/client.js'
import { createAttachUser } from '../../src/middleware/attachUser.js'
import { enforceQuota, refundQuota } from '../../src/middleware/quota.js'
import asyncHandler from '../../src/utils/asyncHandler.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'

function buildApp() {
  const auth = makeTestAuth()
  const attachUser = createAttachUser({ clerkClient: makeClerkStub() })
  const router = Router()
  const targetSchema = z.object({ target: z.string().min(1) })

  router.post(
    '/__t/dns',
    auth.requireAuth,
    attachUser,
    enforceQuota('DNS'),
    (req, res) => res.json({ used: req.quota.used })
  )
  router.post(
    '/__t/whois',
    auth.requireAuth,
    attachUser,
    enforceQuota('WHOIS'),
    (req, res) => res.json({ used: req.quota.used })
  )
  router.post(
    '/__t/refund',
    auth.requireAuth,
    attachUser,
    enforceQuota('DNS'),
    asyncHandler(async (req, res) => {
      await refundQuota(req)
      await refundQuota(req)
      res.json({ used: req.quota.used })
    })
  )
  router.post(
    '/__t/validated',
    auth.requireAuth,
    attachUser,
    (req, _res, next) => {
      try {
        targetSchema.parse(req.body)
        next()
      } catch (err) {
        next(err)
      }
    },
    enforceQuota('DNS'),
    (req, res) => res.json({ used: req.quota.used })
  )

  return makeTestApp({ auth, extraRoutes: router })
}

async function usedFor(userId, tool) {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool } })
  return row?.used ?? 0
}

describe('quota enforcement over HTTP', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('allows exactly 5 requests for a FREE user then 429s', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_free', tier: 'FREE' })

    const remaining = []
    for (let i = 0; i < 5; i += 1) {
      const res = await agent.post('/api/__t/dns')
      expect(res.status).toBe(200)
      remaining.push(res.headers['x-quota-remaining'])
    }
    expect(remaining).toEqual(['4', '3', '2', '1', '0'])

    const blocked = await agent.post('/api/__t/dns')
    expect(blocked.status).toBe(429)
    expect(blocked.body.error.code).toBe('QUOTA_EXCEEDED')
    expect(blocked.headers['retry-after']).toBeDefined()
    expect(blocked.headers['x-quota-reset']).toBeDefined()
    expect(await usedFor(agent.user.id, 'DNS')).toBe(5)
  })

  it('allows exactly 5 of 20 parallel requests', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_parallel', tier: 'FREE' })

    const responses = await Promise.all(
      Array.from({ length: 20 }, () => agent.post('/api/__t/dns'))
    )

    expect(responses.filter((res) => res.status === 200)).toHaveLength(5)
    expect(responses.filter((res) => res.status === 429)).toHaveLength(15)
    expect(await usedFor(agent.user.id, 'DNS')).toBe(5)
  })

  it('keeps the WHOIS counter separate and lets PAID users exceed 5', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_paid', tier: 'PAID' })

    for (let i = 0; i < 6; i += 1) {
      expect((await agent.post('/api/__t/dns')).status).toBe(200)
    }

    const whois = await agent.post('/api/__t/whois')
    expect(whois.status).toBe(200)
    expect(whois.headers['x-quota-limit']).toBe('100')
    expect(await usedFor(agent.user.id, 'DNS')).toBe(6)
    expect(await usedFor(agent.user.id, 'WHOIS')).toBe(1)
  })

  it('never limits an ADMIN and never writes a usage row', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_admin', role: 'ADMIN' })

    for (let i = 0; i < 10; i += 1) {
      expect((await agent.post('/api/__t/dns')).status).toBe(200)
    }
    expect(
      await prisma.usageCounter.count({ where: { userId: agent.user.id } })
    ).toBe(0)
  })

  it('refunds once even when refundQuota is called twice', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_refund', tier: 'FREE' })

    await agent.post('/api/__t/dns')
    await agent.post('/api/__t/dns')
    expect(await usedFor(agent.user.id, 'DNS')).toBe(2)

    const res = await agent.post('/api/__t/refund')
    expect(res.status).toBe(200)
    expect(await usedFor(agent.user.id, 'DNS')).toBe(2)
  })

  it('does not consume when validation fails before the quota middleware', async () => {
    const app = buildApp()
    const agent = await asUser(app, { clerkId: 'quota_invalid', tier: 'FREE' })

    const res = await agent.post('/api/__t/validated').send({ nope: true })

    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
    expect(await usedFor(agent.user.id, 'DNS')).toBe(0)
  })
})
