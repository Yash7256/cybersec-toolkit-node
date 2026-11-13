import { describe, it, expect, afterAll } from 'vitest'
import request from 'supertest'
import { parseEnv } from '../../src/config/env.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { makeTestApp } from '../helpers/auth.js'

const TOKEN = 'test-metrics-token-0123456789'

function makeEnv(overrides = {}) {
  return parseEnv({
    ...process.env,
    LOG_LEVEL: 'silent',
    RATE_LIMIT_MAX: '5000',
    ...overrides,
  })
}

function routeLabels(text) {
  const values = new Set()
  const pattern = /cst_http_request_duration_seconds(?:_bucket|_sum|_count)?\{[^}]*route="([^"]+)"/g
  let match
  while ((match = pattern.exec(text)) !== null) values.add(match[1])
  return values
}

describe('GET /metrics', () => {
  afterAll(() => disconnectRedis())

  it('is hidden when no token is configured', async () => {
    const app = makeTestApp({ env: makeEnv({ METRICS_TOKEN: '' }) })
    const res = await request(app).get('/metrics')
    expect(res.status).toBe(404)
  })

  it('rejects a missing or wrong bearer token', async () => {
    const app = makeTestApp({ env: makeEnv({ METRICS_TOKEN: TOKEN }) })

    expect((await request(app).get('/metrics')).status).toBe(401)
    expect(
      (await request(app).get('/metrics').set('authorization', 'Bearer wrong-token-value'))
        .status
    ).toBe(401)
  })

  it('serves the exposition format with the right token', async () => {
    const app = makeTestApp({ env: makeEnv({ METRICS_TOKEN: TOKEN }) })
    const res = await request(app)
      .get('/metrics')
      .set('authorization', `Bearer ${TOKEN}`)

    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/text\/plain/)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.text).toContain('cst_http_request_duration_seconds')
    expect(res.text).toContain('cst_nodejs_')
    expect(res.text).toContain('cst_db_pool_total')
  })

  it('is not reachable under /api', async () => {
    const app = makeTestApp({ env: makeEnv({ METRICS_TOKEN: TOKEN }) })
    const res = await request(app)
      .get('/api/metrics')
      .set('authorization', `Bearer ${TOKEN}`)
    expect(res.status).toBe(404)
  })

  it('does not grow the route label for unknown URLs or user ids', async () => {
    const app = makeTestApp({ env: makeEnv({ METRICS_TOKEN: TOKEN }) })
    const marker = 'cardinalityprobe'

    for (let i = 0; i < 300; i += 1) {
      await request(app)
        .get(`/unknown/${marker}/${i}`)
        .set('x-test-clerk-id', `${marker}-user-${i}`)
    }
    for (let i = 0; i < 50; i += 1) {
      await request(app)
        .get(`/api/not-a-route/${marker}`)
        .set('x-test-clerk-id', `${marker}-user-${i}`)
    }

    const res = await request(app)
      .get('/metrics')
      .set('authorization', `Bearer ${TOKEN}`)

    const labels = routeLabels(res.text)
    expect(labels).toContain('unmatched')
    expect(labels.size).toBeLessThanOrEqual(1)
    expect(res.text).not.toContain(marker)
  })
})
