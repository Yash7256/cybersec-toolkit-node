import { describe, it, expect, beforeEach } from 'vitest'
import request from 'supertest'
import { prisma } from '../../src/db/client.js'
import { truncateAll } from '../db/helpers.js'
import {
  asUser,
  clerkUserPayload,
  makeClerkStub,
  makeTestApp,
} from '../helpers/auth.js'

describe('authentication', () => {
  beforeEach(async () => {
    await truncateAll()
  })

  it('returns 401 JSON (no redirect) when no token is sent', async () => {
    const app = makeTestApp()
    const res = await request(app).get('/api/user/me')

    expect(res.status).toBe(401)
    expect(res.headers.location).toBeUndefined()
    expect(res.body.error.code).toBe('UNAUTHORIZED')
  })

  it('returns the profile for a known user without exposing clerkUserId', async () => {
    const app = makeTestApp()
    const agent = await asUser(app, { clerkId: 'clerk_known', tier: 'PAID' })

    const res = await agent.get('/api/user/me')

    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ tier: 'PAID', role: 'USER' })
    expect(res.body.clerkUserId).toBeUndefined()
    expect(res.body.id).toBe(agent.user.id)
  })

  it('lazy-provisions an unknown Clerk user exactly once', async () => {
    const stub = makeClerkStub({
      clerk_lazy: clerkUserPayload({
        id: 'clerk_lazy',
        email: 'Lazy@Example.TEST',
        tier: 'free',
      }),
    })
    const app = makeTestApp({ clerkClient: stub })

    const first = await request(app)
      .get('/api/user/me')
      .set('x-test-clerk-id', 'clerk_lazy')

    expect(first.status).toBe(200)
    expect(first.body.email).toBe('lazy@example.test')
    expect(first.body.tier).toBe('FREE')

    const second = await request(app)
      .get('/api/user/me')
      .set('x-test-clerk-id', 'clerk_lazy')
    expect(second.status).toBe(200)

    expect(await prisma.user.count({ where: { clerkUserId: 'clerk_lazy' } })).toBe(1)
  })

  it('maps a Clerk Backend failure to 502 UPSTREAM_AUTH_ERROR', async () => {
    const app = makeTestApp({ clerkClient: makeClerkStub({}) })
    const res = await request(app)
      .get('/api/user/me')
      .set('x-test-clerk-id', 'clerk_unknown')

    expect(res.status).toBe(502)
    expect(res.body.error.code).toBe('UPSTREAM_AUTH_ERROR')
  })

  it('rejects a deactivated account with 403 ACCOUNT_DISABLED', async () => {
    await prisma.user.create({
      data: { clerkUserId: 'clerk_off', email: 'off@example.test', isActive: false },
    })
    const app = makeTestApp()
    const res = await request(app)
      .get('/api/user/me')
      .set('x-test-clerk-id', 'clerk_off')

    expect(res.status).toBe(403)
    expect(res.body.error.code).toBe('ACCOUNT_DISABLED')
  })

  it('rejects a soft-deleted account with 403 ACCOUNT_DISABLED', async () => {
    await prisma.user.create({
      data: {
        clerkUserId: 'clerk_gone',
        email: 'gone@example.test',
        deletedAt: new Date(),
        isActive: false,
      },
    })
    const app = makeTestApp()
    const res = await request(app)
      .get('/api/user/me')
      .set('x-test-clerk-id', 'clerk_gone')

    expect(res.status).toBe(403)
    expect(res.body.error.code).toBe('ACCOUNT_DISABLED')
  })

  it('does not require auth for health or readiness', async () => {
    const app = makeTestApp()
    expect((await request(app).get('/api/health')).status).toBe(200)
    expect((await request(app).get('/api/ready')).status).toBe(200)
  })
})
