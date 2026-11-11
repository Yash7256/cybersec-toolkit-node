import { describe, it, expect } from 'vitest'
import { parseEnv } from '../src/config/env.js'

const BASE_ENV = {
  DATABASE_URL: 'postgresql://user:password@localhost:5432/cybersec',
  DIRECT_URL: 'postgres://user:password@localhost:5432/cybersec',
  CLERK_PUBLISHABLE_KEY: 'pk_test_ZXhhbXBsZS5jb20k',
  CLERK_SECRET_KEY: 'sk_test_cGxhY2Vob2xkZXI=',
  REDIS_URL: 'redis://localhost:6379/0',
}

describe('parseEnv', () => {
  it('applies defaults when optional env is empty', () => {
    const env = parseEnv(BASE_ENV)
    expect(env).toMatchObject({
      NODE_ENV: 'development',
      PORT: 3001,
      LOG_LEVEL: 'info',
      CORS_ORIGINS: ['http://localhost:5173'],
      TRUST_PROXY: 0,
      RATE_LIMIT_WINDOW_MS: 60000,
      RATE_LIMIT_MAX: 100,
      BODY_LIMIT: '100kb',
      ...BASE_ENV,
      DB_POOL_MAX: 10,
      DB_STATEMENT_TIMEOUT_MS: 10000,
      DB_IDLE_TX_TIMEOUT_MS: 15000,
      FREE_DAILY_LIMIT: 5,
      PAID_DAILY_LIMIT: 100,
      ALLOW_PRIVATE_TARGETS: false,
      DNS_TIMEOUT_MS: 3000,
      USER_RATE_LIMIT_MAX: 300,
      SUBMIT_RATE_LIMIT_USER: 10,
      SUBMIT_RATE_LIMIT_IP: 30,
      AUTH_FAIL_MAX: 20,
      AUTH_FAIL_WINDOW_SEC: 600,
      AUTH_FAIL_BLOCK_SEC: 900,
      TARGET_HOURLY_LIMIT_GLOBAL: 20,
      TARGET_HOURLY_LIMIT_USER: 5,
      BLOCKED_ATTEMPTS_MAX: 5,
      BLOCKED_ATTEMPTS_WINDOW_SEC: 600,
      BLOCKED_COOLDOWN_SEC: 900,
    })
  })

  it('throws a readable error when DATABASE_URL is missing', () => {
    expect(() => parseEnv({ DIRECT_URL: BASE_ENV.DIRECT_URL })).toThrow(/DATABASE_URL/)
  })

  it('throws a readable error when DIRECT_URL is missing', () => {
    expect(() => parseEnv({ DATABASE_URL: BASE_ENV.DATABASE_URL })).toThrow(/DIRECT_URL/)
  })

  it('rejects connection strings that are not postgres:// or postgresql://', () => {
    expect(() => parseEnv({ ...BASE_ENV, DATABASE_URL: 'mysql://user:pass@localhost/db' })).toThrow(
      /must start with postgres/
    )
  })

  it('accepts both postgres:// and postgresql:// schemes', () => {
    expect(parseEnv(BASE_ENV).DATABASE_URL).toBe(BASE_ENV.DATABASE_URL)
    expect(parseEnv(BASE_ENV).DIRECT_URL).toBe(BASE_ENV.DIRECT_URL)
  })

  it('requires a redis:// or rediss:// REDIS_URL', () => {
    expect(() => parseEnv({ ...BASE_ENV, REDIS_URL: undefined })).toThrow(/REDIS_URL/)
    expect(() => parseEnv({ ...BASE_ENV, REDIS_URL: 'http://localhost:6379' })).toThrow(/redis/)
    expect(parseEnv({ ...BASE_ENV, REDIS_URL: 'rediss://localhost:6379/0' }).REDIS_URL).toBe(
      'rediss://localhost:6379/0'
    )
  })

  it('parses ALLOW_PRIVATE_TARGETS as a real boolean, never coerced', () => {
    expect(parseEnv({ ...BASE_ENV, ALLOW_PRIVATE_TARGETS: 'false' }).ALLOW_PRIVATE_TARGETS).toBe(
      false
    )
    expect(parseEnv({ ...BASE_ENV, ALLOW_PRIVATE_TARGETS: 'true' }).ALLOW_PRIVATE_TARGETS).toBe(
      true
    )
    expect(() => parseEnv({ ...BASE_ENV, ALLOW_PRIVATE_TARGETS: 'yes' })).toThrow(
      /ALLOW_PRIVATE_TARGETS/
    )
  })

  it('refuses private targets in production', () => {
    expect(() =>
      parseEnv({
        ...BASE_ENV,
        NODE_ENV: 'production',
        CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
        ALLOW_PRIVATE_TARGETS: 'true',
      })
    ).toThrow(/ALLOW_PRIVATE_TARGETS/)
  })

  it('validates METRICS_TOKEN length and treats empty as unset', () => {
    expect(parseEnv({ ...BASE_ENV, METRICS_TOKEN: '' }).METRICS_TOKEN).toBeUndefined()
    expect(() => parseEnv({ ...BASE_ENV, METRICS_TOKEN: 'short' })).toThrow(/METRICS_TOKEN/)
    const token = 'a'.repeat(24)
    expect(parseEnv({ ...BASE_ENV, METRICS_TOKEN: token }).METRICS_TOKEN).toBe(token)
  })

  it('requires Clerk keys with the right prefixes', () => {
    expect(() => parseEnv({ ...BASE_ENV, CLERK_PUBLISHABLE_KEY: undefined })).toThrow(
      /CLERK_PUBLISHABLE_KEY/
    )
    expect(() => parseEnv({ ...BASE_ENV, CLERK_SECRET_KEY: undefined })).toThrow(/CLERK_SECRET_KEY/)
    expect(() => parseEnv({ ...BASE_ENV, CLERK_PUBLISHABLE_KEY: 'sk_test_x' })).toThrow(/pk_/)
    expect(() => parseEnv({ ...BASE_ENV, CLERK_SECRET_KEY: 'pk_test_x' })).toThrow(/sk_/)
    expect(() =>
      parseEnv({ ...BASE_ENV, CLERK_WEBHOOK_SIGNING_SECRET: 'not-a-secret' })
    ).toThrow(/whsec_/)
  })

  it('treats an empty webhook secret as unset outside production', () => {
    const env = parseEnv({ ...BASE_ENV, CLERK_WEBHOOK_SIGNING_SECRET: '' })
    expect(env.CLERK_WEBHOOK_SIGNING_SECRET).toBeUndefined()
  })

  it('requires the webhook secret in production', () => {
    expect(() => parseEnv({ ...BASE_ENV, NODE_ENV: 'production' })).toThrow(
      /CLERK_WEBHOOK_SIGNING_SECRET/
    )
    expect(
      parseEnv({
        ...BASE_ENV,
        NODE_ENV: 'production',
        CLERK_WEBHOOK_SIGNING_SECRET: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
      }).CLERK_WEBHOOK_SIGNING_SECRET
    ).toBe('whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw')
  })

  it('throws on non-numeric PORT', () => {
    expect(() => parseEnv({ ...BASE_ENV, PORT: 'abc' })).toThrow(/Invalid environment variables/)
  })

  it('throws on PORT out of range', () => {
    expect(() => parseEnv({ ...BASE_ENV, PORT: '70000' })).toThrow()
    expect(() => parseEnv({ ...BASE_ENV, PORT: '0' })).toThrow()
  })

  it('splits and trims CORS_ORIGINS into an array', () => {
    const env = parseEnv({ ...BASE_ENV, CORS_ORIGINS: 'http://a.test , , https://b.test ,' })
    expect(env.CORS_ORIGINS).toEqual(['http://a.test', 'https://b.test'])
  })

  it('rejects invalid URL origins in CORS_ORIGINS', () => {
    expect(() => parseEnv({ ...BASE_ENV, CORS_ORIGINS: 'not-a-url' })).toThrow(/CORS_ORIGINS/)
  })

  it('rejects NODE_ENV outside the enum', () => {
    expect(() => parseEnv({ ...BASE_ENV, NODE_ENV: 'staging' })).toThrow()
  })

  it('rejects DB_POOL_MAX below 1', () => {
    expect(() => parseEnv({ ...BASE_ENV, DB_POOL_MAX: '0' })).toThrow(/DB_POOL_MAX/)
  })

  it('rejects daily limits below 1', () => {
    expect(() => parseEnv({ ...BASE_ENV, FREE_DAILY_LIMIT: '0' })).toThrow(/FREE_DAILY_LIMIT/)
    expect(() => parseEnv({ ...BASE_ENV, PAID_DAILY_LIMIT: '0' })).toThrow(/PAID_DAILY_LIMIT/)
  })

  it('coerces numeric strings', () => {
    const env = parseEnv({
      ...BASE_ENV,
      PORT: '4000',
      TRUST_PROXY: '2',
      RATE_LIMIT_MAX: '5',
      DB_POOL_MAX: '20',
      DB_STATEMENT_TIMEOUT_MS: '2500',
      DB_IDLE_TX_TIMEOUT_MS: '3000',
      FREE_DAILY_LIMIT: '3',
      PAID_DAILY_LIMIT: '50',
    })
    expect(env.PORT).toBe(4000)
    expect(env.TRUST_PROXY).toBe(2)
    expect(env.RATE_LIMIT_MAX).toBe(5)
    expect(env.DB_POOL_MAX).toBe(20)
    expect(env.DB_STATEMENT_TIMEOUT_MS).toBe(2500)
    expect(env.DB_IDLE_TX_TIMEOUT_MS).toBe(3000)
    expect(env.FREE_DAILY_LIMIT).toBe(3)
    expect(env.PAID_DAILY_LIMIT).toBe(50)
  })

  it('returns a frozen object', () => {
    const env = parseEnv(BASE_ENV)
    expect(Object.isFrozen(env)).toBe(true)
    expect(() => {
      env.PORT = 9999
    }).toThrow()
  })
})
