// The unreachable-DB case needs its own module instance (the db client reads
// DATABASE_URL at import time), so this file only uses dynamic imports after
// pointing the pool at a closed port. Vitest isolates files, and we restore the
// environment in afterAll so a later file in the same worker is unaffected.
import { describe, it, expect, afterAll } from 'vitest'

const originalEnv = {
  DATABASE_URL: process.env.DATABASE_URL,
  DIRECT_URL: process.env.DIRECT_URL,
  DB_STATEMENT_TIMEOUT_MS: process.env.DB_STATEMENT_TIMEOUT_MS,
}

process.env.DATABASE_URL = 'postgresql://cybersec:cybersec@localhost:59999/cybersec_test'
process.env.DIRECT_URL = 'postgresql://cybersec:cybersec@localhost:59999/cybersec_test'
process.env.DB_STATEMENT_TIMEOUT_MS = '1000'

const request = (await import('supertest')).default
const { pingDb, disconnect } = await import('../../src/db/client.js')
const { createApp } = await import('../../src/app.js')
const { parseEnv } = await import('../../src/config/env.js')
const { createLogger } = await import('../../src/utils/logger.js')
const { registerReadinessCheck } = await import('../../src/routes/health.js')

const env = parseEnv(process.env)
const logger = createLogger({ ...env, LOG_LEVEL: 'silent' })

registerReadinessCheck('db', async () => {
  await pingDb()
  return 'ok'
})

const app = createApp({ env, logger })

afterAll(async () => {
  await disconnect()
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
})

describe('GET /api/ready when the database is unreachable', () => {
  it('returns 503 with db fail and no internals leaked', async () => {
    const res = await request(app).get('/api/ready')
    expect(res.status).toBe(503)
    expect(res.body).toEqual({ status: 'not_ready', checks: { db: 'fail' } })
    expect(JSON.stringify(res.body)).not.toMatch(/59999|ECONNREFUSED|error/i)
  })

  it('keeps /api/health at 200 (liveness has no dependencies)', async () => {
    const res = await request(app).get('/api/health')
    expect(res.status).toBe(200)
    expect(res.body.status).toBe('ok')
  })
})
