import { describe, it, expect } from 'vitest'
import { parseEnv } from '../src/config/env.js'

const DB_URLS = {
  DATABASE_URL: 'postgresql://user:password@localhost:5432/cybersec',
  DIRECT_URL: 'postgres://user:password@localhost:5432/cybersec',
}

describe('parseEnv', () => {
  it('applies defaults when env is empty', () => {
    const env = parseEnv(DB_URLS)
    expect(env).toEqual({
      NODE_ENV: 'development',
      PORT: 3001,
      LOG_LEVEL: 'info',
      CORS_ORIGINS: ['http://localhost:5173'],
      TRUST_PROXY: 0,
      RATE_LIMIT_WINDOW_MS: 60000,
      RATE_LIMIT_MAX: 100,
      BODY_LIMIT: '100kb',
      ...DB_URLS,
      DB_POOL_MAX: 10,
      DB_STATEMENT_TIMEOUT_MS: 10000,
      DB_IDLE_TX_TIMEOUT_MS: 15000,
    })
  })

  it('throws a readable error when DATABASE_URL is missing', () => {
    expect(() => parseEnv({ DIRECT_URL: DB_URLS.DIRECT_URL })).toThrow(/DATABASE_URL/)
  })

  it('throws a readable error when DIRECT_URL is missing', () => {
    expect(() => parseEnv({ DATABASE_URL: DB_URLS.DATABASE_URL })).toThrow(/DIRECT_URL/)
  })

  it('rejects connection strings that are not postgres:// or postgresql://', () => {
    expect(() => parseEnv({ ...DB_URLS, DATABASE_URL: 'mysql://user:pass@localhost/db' })).toThrow(
      /must start with postgres/
    )
  })

  it('accepts both postgres:// and postgresql:// schemes', () => {
    expect(parseEnv(DB_URLS).DATABASE_URL).toBe(DB_URLS.DATABASE_URL)
    expect(parseEnv(DB_URLS).DIRECT_URL).toBe(DB_URLS.DIRECT_URL)
  })

  it('throws on non-numeric PORT', () => {
    expect(() => parseEnv({ ...DB_URLS, PORT: 'abc' })).toThrow(/Invalid environment variables/)
  })

  it('throws on PORT out of range', () => {
    expect(() => parseEnv({ ...DB_URLS, PORT: '70000' })).toThrow()
    expect(() => parseEnv({ ...DB_URLS, PORT: '0' })).toThrow()
  })

  it('splits and trims CORS_ORIGINS into an array', () => {
    const env = parseEnv({ ...DB_URLS, CORS_ORIGINS: 'http://a.test , , https://b.test ,' })
    expect(env.CORS_ORIGINS).toEqual(['http://a.test', 'https://b.test'])
  })

  it('rejects invalid URL origins in CORS_ORIGINS', () => {
    expect(() => parseEnv({ ...DB_URLS, CORS_ORIGINS: 'not-a-url' })).toThrow(/CORS_ORIGINS/)
  })

  it('rejects NODE_ENV outside the enum', () => {
    expect(() => parseEnv({ ...DB_URLS, NODE_ENV: 'staging' })).toThrow()
  })

  it('rejects DB_POOL_MAX below 1', () => {
    expect(() => parseEnv({ ...DB_URLS, DB_POOL_MAX: '0' })).toThrow(/DB_POOL_MAX/)
  })

  it('coerces numeric strings', () => {
    const env = parseEnv({
      ...DB_URLS,
      PORT: '4000',
      TRUST_PROXY: '2',
      RATE_LIMIT_MAX: '5',
      DB_POOL_MAX: '20',
      DB_STATEMENT_TIMEOUT_MS: '2500',
      DB_IDLE_TX_TIMEOUT_MS: '3000',
    })
    expect(env.PORT).toBe(4000)
    expect(env.TRUST_PROXY).toBe(2)
    expect(env.RATE_LIMIT_MAX).toBe(5)
    expect(env.DB_POOL_MAX).toBe(20)
    expect(env.DB_STATEMENT_TIMEOUT_MS).toBe(2500)
    expect(env.DB_IDLE_TX_TIMEOUT_MS).toBe(3000)
  })

  it('returns a frozen object', () => {
    const env = parseEnv(DB_URLS)
    expect(Object.isFrozen(env)).toBe(true)
    expect(() => {
      env.PORT = 9999
    }).toThrow()
  })
})
