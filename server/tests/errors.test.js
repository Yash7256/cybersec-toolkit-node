import { describe, it, expect } from 'vitest'
import request from 'supertest'
import express from 'express'
import { createApp } from '../src/app.js'
import { parseEnv } from '../src/config/env.js'
import { createLogger } from '../src/utils/logger.js'

const silentEnv = parseEnv(process.env)
const silentLogger = createLogger({ ...silentEnv, LOG_LEVEL: 'silent' })

function makeApp(envOverrides = {}, routes) {
  const env = parseEnv({ ...process.env, ...envOverrides })
  return createApp({
    env,
    logger: createLogger({ ...env, LOG_LEVEL: 'silent' }),
    ...(routes && { routes }),
  })
}

describe('error responses', () => {
  const app = makeApp()

  it('unknown route returns 404 NOT_FOUND envelope', async () => {
    const res = await request(app).get('/api/does-not-exist')
    expect(res.status).toBe(404)
    expect(res.body.error.code).toBe('NOT_FOUND')
    expect(typeof res.body.error.message).toBe('string')
    expect(res.body.error.requestId).toMatch(/^[A-Za-z0-9._-]{8,64}$/)
  })

  it('malformed JSON returns 400 INVALID_JSON', async () => {
    const res = await request(app)
      .post('/api/health')
      .set('content-type', 'application/json')
      .send('{ not valid json')
    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('INVALID_JSON')
  })

  it('body over the limit returns 413 PAYLOAD_TOO_LARGE', async () => {
    const smallApp = makeApp({ BODY_LIMIT: '1kb' })
    const res = await request(smallApp)
      .post('/api/health')
      .set('content-type', 'application/json')
      .send(JSON.stringify({ data: 'x'.repeat(2048) }))
    expect(res.status).toBe(413)
    expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE')
  })

  it('throwing route returns 500 INTERNAL_ERROR without stack in production', async () => {
    const boomRouter = express.Router()
    boomRouter.get('/boom', () => {
      throw new Error('secret stack trace details')
    })
    const prodApp = makeApp({ NODE_ENV: 'production' }, boomRouter)

    const res = await request(prodApp).get('/api/boom')
    expect(res.status).toBe(500)
    expect(res.body.error.code).toBe('INTERNAL_ERROR')
    expect(res.body.error.message).toBe('Internal server error')
    expect(JSON.stringify(res.body)).not.toContain('secret stack trace details')
    expect(res.body.error.requestId).toBeDefined()
  })

  it('throwing route returns real message in development', async () => {
    const boomRouter = express.Router()
    boomRouter.get('/boom', () => {
      throw new Error('dev-only message')
    })
    const devApp = makeApp({ NODE_ENV: 'development' }, boomRouter)

    const res = await request(devApp).get('/api/boom')
    expect(res.status).toBe(500)
    expect(res.body.error.message).toBe('dev-only message')
  })

  it('production not-found response contains no stack', async () => {
    const prodApp = makeApp({ NODE_ENV: 'production' })
    const res = await request(prodApp).get('/api/nope')
    expect(res.body.error).not.toHaveProperty('stack')
  })
})
