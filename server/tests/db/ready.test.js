import { describe, it, expect } from 'vitest'
import request from 'supertest'
import { createApp } from '../../src/app.js'
import { parseEnv } from '../../src/config/env.js'
import { createLogger } from '../../src/utils/logger.js'
import { registerReadinessCheck } from '../../src/routes/health.js'
import { pingDb } from '../../src/db/client.js'

const env = parseEnv(process.env)
const logger = createLogger({ ...env, LOG_LEVEL: 'silent' })

registerReadinessCheck('db', async () => {
  await pingDb()
  return 'ok'
})

const app = createApp({ env, logger })

describe('GET /api/ready with the database up', () => {
  it('returns 200 with db ok', async () => {
    const res = await request(app).get('/api/ready')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ status: 'ready', checks: { db: 'ok' } })
  })

  it('keeps /api/health dependency-free', async () => {
    const res = await request(app).get('/api/health')
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('ok')
  })
})
