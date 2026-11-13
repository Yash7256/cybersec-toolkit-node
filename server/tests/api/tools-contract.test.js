import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { Router } from 'express'
import { z } from 'zod'
import { prisma } from '../../src/db/client.js'
import { parseEnv } from '../../src/config/env.js'
import { createLimiters } from '../../src/middleware/limiters.js'
import { createToolHandler } from '../../src/tools/_shared/toolRoute.js'
import { ToolError } from '../../src/tools/_shared/errors.js'
import { RESULT_KEYS as DNS_KEYS, schema as dnsSchema } from '../../src/tools/dns/index.js'
import { RESULT_KEYS as SSL_KEYS, schema as sslSchema } from '../../src/tools/ssl/index.js'
import {
  RESULT_KEYS as HTTP_KEYS,
  schema as httpSchema,
} from '../../src/tools/httpHeaders/index.js'
import { RESULT_KEYS as WHOIS_KEYS, schema as whoisSchema } from '../../src/tools/whois/index.js'
import { RESULT_KEYS as GEO_KEYS, schema as geoSchema } from '../../src/tools/geoip/index.js'
import { RESULT_KEYS as PING_KEYS, schema as pingSchema } from '../../src/tools/ping/index.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { flushTestRedis } from '../helpers/redis.js'
import { truncateAll } from '../db/helpers.js'
import { asUser, makeClerkStub, makeTestApp, makeTestAuth } from '../helpers/auth.js'

const silentLogger = { info() {}, warn() {}, error() {}, debug() {}, fatal() {}, trace() {} }

const env = parseEnv({ ...process.env, LOG_LEVEL: 'silent', FREE_DAILY_LIMIT: '5' })

const TOOLS = [
  { name: 'dns', toolEnum: 'DNS', schema: dnsSchema, keys: DNS_KEYS, touchesTarget: false, dedupeTtlSec: 60, input: { target: '93.184.216.34' } },
  { name: 'ssl', toolEnum: 'SSL', schema: sslSchema, keys: SSL_KEYS, touchesTarget: true, dedupeTtlSec: 300, input: { host: '93.184.216.34' } },
  { name: 'http_headers', toolEnum: 'HTTP_HEADERS', schema: httpSchema, keys: HTTP_KEYS, touchesTarget: true, dedupeTtlSec: 120, input: { target: '93.184.216.34' } },
  { name: 'whois', toolEnum: 'WHOIS', schema: whoisSchema, keys: WHOIS_KEYS, touchesTarget: false, dedupeTtlSec: 3600, input: { target: '93.184.216.34' } },
  { name: 'geoip', toolEnum: 'GEOIP', schema: geoSchema, keys: GEO_KEYS, touchesTarget: false, dedupeTtlSec: 3600, input: { target: '93.184.216.34' } },
  { name: 'ping', toolEnum: 'PING', schema: pingSchema, keys: PING_KEYS, touchesTarget: true, dedupeTtlSec: 0, input: { target: '93.184.216.34' } },
]

function blank(keys, input) {
  const data = {}
  for (const key of keys) data[key] = key === 'target' ? input.target ?? input.host : null
  return data
}

function fakeDefinition(tool, { execute } = {}) {
  return {
    name: tool.name,
    toolEnum: tool.toolEnum,
    schema: tool.schema,
    touchesTarget: tool.touchesTarget,
    dedupeTtlSec: tool.dedupeTtlSec,
    normalize: (input) => input,
    async execute(input) {
      if (execute) return execute(input)
      return { ...blank(tool.keys, input), status_code: 200, records: [], headers: {} }
    },
    emptyResult: (input) => blank(tool.keys, input),
    summarize: () => ({}),
  }
}

function buildApp() {
  const auth = makeTestAuth()
  const clerkClient = makeClerkStub()
  const limiters = createLimiters({ env, logger: silentLogger })
  const router = Router()
  for (const tool of TOOLS) {
    router.post(
      `/__t/${tool.name}`,
      ...createToolHandler({
        definition: fakeDefinition(tool),
        auth,
        clerkClient,
        env,
        limiters,
      })
    )
  }
  router.post(
    '/__t/upstream',
    ...createToolHandler({
      definition: fakeDefinition(TOOLS[0], {
        execute: async () => {
          throw new ToolError('upstream', 'Lookup service unavailable')
        },
      }),
      auth,
      clerkClient,
      env,
      limiters,
    })
  )
  return makeTestApp({ auth, clerkClient, env, extraRoutes: router })
}

async function usedFor(userId, tool = 'DNS') {
  const row = await prisma.usageCounter.findFirst({ where: { userId, tool } })
  return row?.used ?? 0
}

describe('tools contract', () => {
  beforeEach(async () => {
    await truncateAll()
    await flushTestRedis()
  })
  afterAll(() => disconnectRedis())

  it('requires authentication for every tool', async () => {
    const app = buildApp()
    for (const tool of TOOLS) {
      const res = await (await import('supertest')).default(app)
        .post(`/api/__t/${tool.name}`)
        .send(tool.input)
      expect(res.status).toBe(401)
    }
  })

  it('rejects invalid input without consuming quota for every tool', async () => {
    const app = buildApp()
    for (const tool of TOOLS) {
      const user = await asUser(app, { clerkId: `contract_invalid_${tool.name}` })
      const res = await user.post(`/api/__t/${tool.name}`).send({ nope: true })
      expect(res.status).toBe(400)
      expect(res.body.error.code).toBe('VALIDATION_ERROR')
      expect(await usedFor(user.user.id)).toBe(0)
    }
  })

  it('blocks a private target without consuming quota for every tool', async () => {
    const app = buildApp()
    for (const tool of TOOLS) {
      const user = await asUser(app, { clerkId: `contract_blocked_${tool.name}` })
      const body = tool.name === 'ssl' ? { host: '10.0.0.1' } : { target: '10.0.0.1' }
      const res = await user.post(`/api/__t/${tool.name}`).send(body)
      expect(res.status).toBe(422)
      expect(JSON.stringify(res.body)).not.toContain('10.0.0.1')
      expect(await usedFor(user.user.id)).toBe(0)
    }
  })

  it('enforces the FREE daily quota on the sixth call', async () => {
    const app = buildApp()
    const user = await asUser(app, { clerkId: 'contract_quota' })
    const targets = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '4.4.4.4', '2.2.2.2', '3.3.3.3']
    for (let index = 0; index < 5; index += 1) {
      const res = await user.post('/api/__t/dns').send({ target: targets[index] })
      expect(res.status).toBe(200)
    }
    const sixth = await user.post('/api/__t/dns').send({ target: targets[5] })
    expect(sixth.status).toBe(429)
    expect(sixth.body.error.code).toBe('QUOTA_EXCEEDED')
  })

  it('refunds quota on an upstream failure', async () => {
    const app = buildApp()
    const user = await asUser(app, { clerkId: 'contract_upstream' })
    const res = await user.post('/api/__t/upstream').send({ target: '93.184.216.34' })
    expect(res.status).toBe(502)
    expect(res.body.error.code).toBe('UPSTREAM_ERROR')
    expect(await usedFor(user.user.id)).toBe(0)
  })

  it('persists a completed run and returns identical data from the runs API', async () => {
    const app = buildApp()
    for (const tool of TOOLS) {
      const user = await asUser(app, { clerkId: `contract_persist_${tool.name}` })
      const res = await user.post(`/api/__t/${tool.name}`).send(tool.input)
      expect(res.status).toBe(200)
      expect(res.body).toMatchObject({
        runId: expect.any(String),
        tool: tool.name,
        status: 'COMPLETED',
        cached: false,
      })
      expect(Object.keys(res.body.data)).toEqual(expect.arrayContaining(tool.keys))
      expect(res.body.data).not.toHaveProperty('addresses.0')

      const detail = await user.get(`/api/runs/${res.body.runId}`)
      expect(detail.status).toBe(200)
      expect(detail.body.data).toEqual(res.body.data)

      const list = await user.get('/api/runs')
      expect(list.body.runs.map((run) => run.id)).toContain(res.body.runId)
    }
  })

  it('serves a repeated call from cache without consuming quota (except ping)', async () => {
    const app = buildApp()
    for (const tool of TOOLS) {
      if (tool.dedupeTtlSec === 0) continue
      const user = await asUser(app, { clerkId: `contract_cache_${tool.name}` })
      const first = await user.post(`/api/__t/${tool.name}`).send(tool.input)
      const second = await user.post(`/api/__t/${tool.name}`).send(tool.input)
      expect(first.body.cached).toBe(false)
      expect(second.body.cached).toBe(true)
      expect(second.body.runId).toBe(first.body.runId)
      expect(await usedFor(user.user.id, tool.toolEnum)).toBe(1)
    }
  })
})
