import { describe, it, expect } from 'vitest'
import request from 'supertest'
import { createApp } from '../src/app.js'
import { parseEnv } from '../src/config/env.js'
import { createLogger } from '../src/utils/logger.js'

const env = parseEnv(process.env)
const silentLogger = createLogger({ ...env, LOG_LEVEL: 'silent' })
const app = createApp({ env, logger: silentLogger })

describe('health and readiness', () => {
  it('GET /api/health returns 200 with the expected shape', async () => {
    const res = await request(app).get('/api/health')
    expect(res.status).toBe(200)
    expect(res.body).toMatchObject({ status: 'ok' })
    expect(typeof res.body.uptime).toBe('number')
    expect(typeof res.body.timestamp).toBe('string')
    expect(new Date(res.body.timestamp).toString()).not.toBe('Invalid Date')
  })

  it('GET /api/ready returns 200 with checks object', async () => {
    const res = await request(app).get('/api/ready')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ status: 'ready', checks: {} })
  })

  it('does not leak x-powered-by', async () => {
    const res = await request(app).get('/api/health')
    expect(res.headers['x-powered-by']).toBeUndefined()
  })

  it('sets x-request-id on every response', async () => {
    const res = await request(app).get('/api/health')
    expect(res.headers['x-request-id']).toMatch(/^[A-Za-z0-9._-]{8,64}$/)
  })

  it('reuses a valid inbound x-request-id', async () => {
    const res = await request(app).get('/api/health').set('x-request-id', 'my-custom-id-123')
    expect(res.headers['x-request-id']).toBe('my-custom-id-123')
  })

  it('replaces an invalid inbound x-request-id', async () => {
    const res = await request(app).get('/api/health').set('x-request-id', 'bad id!')
    expect(res.headers['x-request-id']).not.toBe('bad id!')
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/)
  })
})
