import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import request from 'supertest'
import { Router } from 'express'
import { z } from 'zod'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { createAttachUser } from '../../src/middleware/attachUser.js'
import { createLimiters } from '../../src/middleware/limiters.js'
import { enforceQuota } from '../../src/middleware/quota.js'
import { createAbuseGuard } from '../../src/security/abuseGuard.js'
import { validateTarget } from '../../src/security/targetPolicy.js'
import { getRedisClient, disconnectRedis } from '../../src/redis/client.js'
import { metrics } from '../../src/observability/metrics.js'
import asyncHandler from '../../src/utils/asyncHandler.js'
import AppError from '../../src/utils/AppError.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'

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
    FREE_DAILY_LIMIT: '5',
    ...overrides,
  })
}

async function blockedTotal() {
  const metric = metrics.register.getSingleMetric('cst_policy_blocked_total')
  const data = await metric.get()
  return data.values.reduce((sum, value) => sum + value.value, 0)
}

function buildApp(env) {
  const auth = makeTestAuth()
  const attachUser = createAttachUser({ clerkClient: makeClerkStub() })
  const limiters = createLimiters({ env, logger: silentLogger })
  const abuse = createAbuseGuard({ env, redis: getRedisClient(), logger: silentLogger })
  const bodySchema = z.object({ target: z.string().min(1) })

  const resolverCalls = { count: 0 }
  const resolver = async (value) => {
    resolverCalls.count += 1
    if (value === 'blocked.example') {
      const err = new AppError(422, 'TARGET_BLOCKED', 'This target is not allowed.')
      Object.defineProperty(err, 'reason', { value: 'private', enumerable: false })
      throw err
    }
    return { host: value, addresses: [{ address: '93.184.216.34', family: 4 }] }
  }

  const router = Router()
  router.post(
    '/__t/scan',
    auth.requireAuth,
    attachUser,
    ...limiters.submitLimiters,
    (req, _res, next) => {
      try {
        bodySchema.parse(req.body)
        next()
      } catch (err) {
        next(err)
      }
    },
    asyncHandler(async (req, _res, next) => {
      await abuse.assertNotCoolingDown(req.user.id)
      try {
        req.target = await validateTarget(req.body.target, { env, resolver })
      } catch (err) {
        if (err?.code === 'TARGET_BLOCKED') {
          await abuse.recordBlocked({
            userId: req.user.id,
            ip: req.ip,
            reason: err.reason ?? 'private',
            tool: 'DNS',
            target: req.body.target,
          })
        }
        throw err
      }
      next()
    }),
    asyncHandler(async (req, _res, next) => {
      await abuse.consumeTarget({ userId: req.user.id, targetKey: req.target.targetKey })
      next()
    }),
    enforceQuota('DNS', env),
    (req, res) => res.json({ used: req.quota.used, addresses: req.target.addresses })
  )

  return { app: makeTestApp({ auth, env, extraRoutes: router }), resolverCalls }
}

async function usedFor(userId) {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool: 'DNS' } })
  return row?.used ?? 0
}

describe('tool pipeline ordering', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })

  afterAll(() => disconnectRedis())

  it('rejects unauthenticated requests before any policy or resolution work', async () => {
    const env = makeEnv()
    const { app, resolverCalls } = buildApp(env)

    const res = await request(app).post('/api/__t/scan').send({ target: 'example.com' })

    expect(res.status).toBe(401)
    expect(resolverCalls.count).toBe(0)
  })

  it('does not consume quota when zod validation fails', async () => {
    const env = makeEnv()
    const { app } = buildApp(env)
    const user = await asUser(app, { clerkId: 'pipe_invalid' })

    const res = await user.post('/api/__t/scan').send({ nope: true })

    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
    expect(await usedFor(user.user.id)).toBe(0)
  })

  it('blocks a private target with no quota use, an audit row and a metric', async () => {
    const env = makeEnv()
    const { app } = buildApp(env)
    const user = await asUser(app, { clerkId: 'pipe_blocked' })
    const before = await blockedTotal()

    const res = await user.post('/api/__t/scan').send({ target: 'blocked.example' })

    expect(res.status).toBe(422)
    expect(res.body.error.code).toBe('TARGET_BLOCKED')
    expect(JSON.stringify(res.body)).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/)
    expect(await usedFor(user.user.id)).toBe(0)
    expect(await prisma.auditLog.count({ where: { action: 'scan.blocked_target' } })).toBe(1)
    expect(await blockedTotal()).toBe(before + 1)
  })

  it('applies the per-target limiter before quota', async () => {
    const env = makeEnv({ TARGET_HOURLY_LIMIT_USER: '1' })
    const { app } = buildApp(env)
    const user = await asUser(app, { clerkId: 'pipe_target' })

    expect((await user.post('/api/__t/scan').send({ target: 'example.com' })).status).toBe(200)
    expect(await usedFor(user.user.id)).toBe(1)

    const limited = await user.post('/api/__t/scan').send({ target: 'example.com' })
    expect(limited.status).toBe(429)
    expect(limited.body.error.code).toBe('TARGET_RATE_LIMITED')
    expect(await usedFor(user.user.id)).toBe(1)
  })

  it('enforces quota after all policy checks and reports exhausted quota', async () => {
    const env = makeEnv()
    const { app } = buildApp(env)
    const user = await asUser(app, { clerkId: 'pipe_quota' })

    for (let i = 0; i < 5; i += 1) {
      const res = await user.post('/api/__t/scan').send({ target: `example-${i}.com` })
      expect(res.status).toBe(200)
    }
    expect(await usedFor(user.user.id)).toBe(5)

    const blocked = await user.post('/api/__t/scan').send({ target: 'example-6.com' })
    expect(blocked.status).toBe(429)
    expect(blocked.body.error.code).toBe('QUOTA_EXCEEDED')
    expect(await usedFor(user.user.id)).toBe(5)
  })

  it('passes only validated addresses to the handler and consumes one unit', async () => {
    const env = makeEnv()
    const { app, resolverCalls } = buildApp(env)
    const user = await asUser(app, { clerkId: 'pipe_success' })

    const res = await user.post('/api/__t/scan').send({ target: 'example.com' })

    expect(res.status).toBe(200)
    expect(res.body.used).toBe(1)
    expect(res.body.addresses).toEqual([{ address: '93.184.216.34', family: 4 }])
    expect(resolverCalls.count).toBe(1)
    expect(await usedFor(user.user.id)).toBe(1)
  })
})
