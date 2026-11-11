import { describe, it, expect } from 'vitest'
import request from 'supertest'
import { createApp } from '../src/app.js'
import { parseEnv } from '../src/config/env.js'
import { createLogger } from '../src/utils/logger.js'

function makeApp(envOverrides = {}) {
  const env = parseEnv({ ...process.env, ...envOverrides })
  return createApp({ env, logger: createLogger({ ...env, LOG_LEVEL: 'silent' }) })
}

describe('security middleware', () => {
  const app = makeApp()

  it('sets helmet x-content-type-options header', async () => {
    const res = await request(app).get('/api/health')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
  })

  it('echoes an allowed CORS origin', async () => {
    const res = await request(app)
      .get('/api/health')
      .set('origin', 'http://localhost:5173')
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173')
  })

  it('gives a disallowed origin no CORS header', async () => {
    const res = await request(app)
      .get('/api/health')
      .set('origin', 'http://evil.test')
    expect(res.headers['access-control-allow-origin']).toBeUndefined()
  })

  it('preflight from an allowed origin succeeds with configured methods', async () => {
    const res = await request(app)
      .options('/api/health')
      .set('origin', 'http://localhost:5173')
      .set('access-control-request-method', 'POST')
    expect(res.status).toBeLessThan(400)
    expect(res.headers['access-control-allow-methods']).toContain('POST')
    expect(res.headers['access-control-allow-credentials']).toBe('true')
  })

  it('rate limit: 4th request returns 429 RATE_LIMITED when RATE_LIMIT_MAX=3', async () => {
    const limitedApp = makeApp({ RATE_LIMIT_MAX: '3', RATE_LIMIT_WINDOW_MS: '60000' })
    const responses = []
    for (let i = 0; i < 4; i++) {
      responses.push(await request(limitedApp).get('/api/health'))
    }
    expect(responses[2].status).toBe(200)
    expect(responses[3].status).toBe(429)
    expect(responses[3].body.error.code).toBe('RATE_LIMITED')
    expect(responses[3].headers['ratelimit']).toContain('r=0')
    expect(responses[3].headers['ratelimit-policy']).toBeDefined()
  })
})
