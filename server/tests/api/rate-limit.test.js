import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import request from 'supertest'
import express from 'express'
import { Router } from 'express'
import { parseEnv } from '../../src/config/env.js'
import { createLimiter } from '../../src/middleware/rateLimit.js'
import { createAbuseGuard } from '../../src/security/abuseGuard.js'
import { enforceQuota } from '../../src/middleware/quota.js'
import { createAttachUser } from '../../src/middleware/attachUser.js'
import errorHandler from '../../src/middleware/errorHandler.js'
import asyncHandler from '../../src/utils/asyncHandler.js'
import AppError from '../../src/utils/AppError.js'
import { metrics } from '../../src/observability/metrics.js'
import {
  createRedisClient,
  disconnectRedis,
  getRedisClient,
} from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import {
  asUser,
  makeClerkStub,
  makeTestApp,
  makeTestAuth,
} from '../helpers/auth.js'

const silentLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  fatal() {},
  trace() {},
}

function makeEnv(overrides = {}) {
  return parseEnv({
    ...process.env,
    LOG_LEVEL: 'silent',
    TRUST_PROXY: '1',
    ...overrides,
  })
}

async function metricTotal(name) {
  const metric = metrics.register.getSingleMetric(name)
  const data = await metric.get()
  return data.values.reduce((sum, value) => sum + value.value, 0)
}

describe('rate limiting (real Redis)', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })

  afterAll(() => {
    disconnectRedis()
  })

  it('enforces per-user limits, exposes headers, and isolates users', async () => {
    const env = makeEnv()
    const auth = makeTestAuth()
    const attachUser = createAttachUser({ clerkClient: makeClerkStub() })
    const limiter = createLimiter({
      name: 'user_general',
      points: 2,
      durationSec: 60,
      keyFn: (req) => req.user?.id,
      logger: silentLogger,
    })

    const router = Router()
    router.get(
      '/__t/limited',
      auth.requireAuth,
      attachUser,
      limiter,
      (_req, res) => res.json({ ok: true })
    )
    const app = makeTestApp({ auth, env, extraRoutes: router })

    const one = await asUser(app, { clerkId: 'rl_user_one' })
    expect((await one.get('/api/__t/limited')).status).toBe(200)
    expect((await one.get('/api/__t/limited')).status).toBe(200)
    const blocked = await one.get('/api/__t/limited')
    expect(blocked.status).toBe(429)
    expect(blocked.body.error.code).toBe('RATE_LIMITED')
    expect(blocked.headers['ratelimit-limit']).toBe('2')
    expect(blocked.headers['ratelimit-remaining']).toBe('0')
    expect(blocked.headers['ratelimit-reset']).toBeDefined()
    expect(blocked.headers['retry-after']).toBeDefined()

    const two = await asUser(app, { clerkId: 'rl_user_two' })
    expect((await two.get('/api/__t/limited')).status).toBe(200)
    expect((await two.get('/api/__t/limited')).status).toBe(200)
    expect((await two.get('/api/__t/limited')).status).toBe(429)
  })

  it('shares one counter between two limiter instances with the same name', async () => {
    const env = makeEnv()
    const clerkId = 'rl_shared_user'
    await asUser(makeTestApp({ env }), { clerkId })

    const limiterA = createLimiter({
      name: 'shared_probe',
      points: 2,
      durationSec: 60,
      keyFn: () => 'same-key',
      logger: silentLogger,
    })
    const limiterB = createLimiter({
      name: 'shared_probe',
      points: 2,
      durationSec: 60,
      keyFn: () => 'same-key',
      logger: silentLogger,
    })

    const build = (limiter) => {
      const auth = makeTestAuth()
      const router = Router()
      router.get('/__t/shared', auth.requireAuth, limiter, (_req, res) =>
        res.json({ ok: true })
      )
      return makeTestApp({ auth, env, extraRoutes: router })
    }

    const appA = build(limiterA)
    const appB = build(limiterB)

    const hit = (app) =>
      request(app).get('/api/__t/shared').set('x-test-clerk-id', clerkId)

    expect((await hit(appA)).status).toBe(200)
    expect((await hit(appB)).status).toBe(200)
    expect((await hit(appA)).status).toBe(429)
  })

  it('auth_fail blocks after 20 failures, ignores successes, and blocks valid tokens', async () => {
    const env = makeEnv({ AUTH_FAIL_BLOCK_SEC: '60' })
    const app = makeTestApp({ env })
    const clerkId = 'rl_auth_fail'
    await asUser(app, { clerkId })
    const ip = '203.0.113.77'

    const succeed = () =>
      request(app)
        .get('/api/user/me')
        .set('x-test-clerk-id', clerkId)
        .set('x-forwarded-for', ip)
    const fail = () =>
      request(app).get('/api/user/me').set('x-forwarded-for', ip)

    for (let i = 0; i < 10; i += 1) {
      expect((await succeed()).status).toBe(200)
    }
    for (let i = 0; i < 10; i += 1) {
      expect((await fail()).status).toBe(401)
    }

    // If successful authentication consumed points, the counter would already
    // be at 20 and this valid request would be blocked.
    expect((await succeed()).status).toBe(200)

    for (let i = 0; i < 10; i += 1) {
      expect((await fail()).status).toBe(401)
    }
    expect((await succeed()).status).toBe(429)
  })

  it('fails open on a dead Redis, counts store errors, and insurance still caps bursts', async () => {
    const dead = createRedisClient('redis://127.0.0.1:6399/1', {
      logger: silentLogger,
    })
    const limiter = createLimiter({
      name: 'metrics',
      points: 2,
      durationSec: 60,
      keyFn: () => 'dead-key',
      redisClient: dead,
      logger: silentLogger,
    })

    const app = express()
    app.get('/x', limiter, (_req, res) => res.json({ ok: true }))
    app.use(errorHandler(silentLogger, { isProduction: false }))

    const before = await metricTotal('rate_limit_store_errors_total')

    expect((await request(app).get('/x')).status).toBe(200)
    expect((await request(app).get('/x')).status).toBe(200)
    expect((await request(app).get('/x')).status).toBe(429)

    const after = await metricTotal('rate_limit_store_errors_total')
    expect(after).toBeGreaterThan(before)
    dead.disconnect()
  })

  it('limits per target and globally before quota is consumed', async () => {
    const env = makeEnv({
      TARGET_HOURLY_LIMIT_USER: '5',
      TARGET_HOURLY_LIMIT_GLOBAL: '20',
    })
    const auth = makeTestAuth()
    const attachUser = createAttachUser({ clerkClient: makeClerkStub() })
    const guard = createAbuseGuard({
      env,
      redis: getRedisClient(),
      logger: silentLogger,
    })

    const router = Router()
    router.post(
      '/__t/scan',
      auth.requireAuth,
      attachUser,
      asyncHandler(async (req, _res, next) => {
        await guard.assertNotCoolingDown(req.user.id)
        await guard.consumeTarget({
          userId: req.user.id,
          targetKey: req.body.targetKey,
        })
        next()
      }),
      enforceQuota('DNS', env),
      (req, res) => res.json({ ok: true, used: req.quota.used })
    )
    const app = makeTestApp({ auth, env, extraRoutes: router })

    const one = await asUser(app, { clerkId: 'rl_target_one' })
    for (let i = 0; i < 5; i += 1) {
      const res = await one
        .post('/api/__t/scan')
        .send({ targetKey: 'example.com' })
      expect(res.status).toBe(200)
    }

    const { prisma } = await import('../../src/db/client.js')
    const usedBefore = (
      await prisma.usageCounter.findFirst({
        where: { userId: one.user.id, tool: 'DNS' },
      })
    ).used

    const sixth = await one
      .post('/api/__t/scan')
      .send({ targetKey: 'example.com' })
    expect(sixth.status).toBe(429)
    expect(sixth.body.error.code).toBe('TARGET_RATE_LIMITED')

    const usedAfter = (
      await prisma.usageCounter.findFirst({
        where: { userId: one.user.id, tool: 'DNS' },
      })
    ).used
    expect(usedAfter).toBe(usedBefore)

    for (let i = 0; i < 20; i += 1) {
      const user = await asUser(app, { clerkId: `rl_global_${i}` })
      const res = await user.post('/api/__t/scan').send({ targetKey: 'global.example' })
      expect(res.status).toBe(200)
    }
    const twentyFirst = await (
      await asUser(app, { clerkId: 'rl_global_21' })
    )
      .post('/api/__t/scan')
      .send({ targetKey: 'global.example' })
    expect(twentyFirst.status).toBe(429)
    expect(twentyFirst.body.error.code).toBe('TARGET_RATE_LIMITED')
  })

  it('applies a cooldown after repeated blocked targets and clears it after TTL', async () => {
    const env = makeEnv({
      BLOCKED_ATTEMPTS_MAX: '5',
      BLOCKED_ATTEMPTS_WINDOW_SEC: '60',
      BLOCKED_COOLDOWN_SEC: '1',
    })
    const auth = makeTestAuth()
    const attachUser = createAttachUser({ clerkClient: makeClerkStub() })
    const guard = createAbuseGuard({
      env,
      redis: getRedisClient(),
      logger: silentLogger,
    })

    const router = Router()
    router.post(
      '/__t/blocked',
      auth.requireAuth,
      attachUser,
      asyncHandler(async (req, _res, next) => {
        await guard.recordBlocked({
          userId: req.user.id,
          ip: req.ip,
          reason: 'private',
          tool: 'DNS',
          target: req.body.target,
        })
        next(new AppError(422, 'TARGET_BLOCKED', 'This target is not allowed.'))
      })
    )
    router.post(
      '/__t/valid',
      auth.requireAuth,
      attachUser,
      guard.enforceCooldown,
      (_req, res) => res.json({ ok: true })
    )
    const app = makeTestApp({ auth, env, extraRoutes: router })

    const user = await asUser(app, { clerkId: 'rl_cooldown' })
    for (let i = 0; i < 5; i += 1) {
      const res = await user
        .post('/api/__t/blocked')
        .send({ target: `10.0.0.${i}` })
      expect(res.status).toBe(422)
    }

    const cooling = await user.post('/api/__t/valid').send({})
    expect(cooling.status).toBe(429)
    expect(cooling.body.error.code).toBe('TARGET_ABUSE_COOLDOWN')
    expect(cooling.headers['retry-after']).toBeDefined()

    await new Promise((resolve) => setTimeout(resolve, 1100))
    expect((await user.post('/api/__t/valid').send({})).status).toBe(200)
  })
})
