import { describe, it, expect } from 'vitest'
import { parseEnv } from '../src/config/env.js'

describe('parseEnv', () => {
  it('applies defaults when env is empty', () => {
    const env = parseEnv({})
    expect(env).toEqual({
      NODE_ENV: 'development',
      PORT: 3001,
      LOG_LEVEL: 'info',
      CORS_ORIGINS: ['http://localhost:5173'],
      TRUST_PROXY: 0,
      RATE_LIMIT_WINDOW_MS: 60000,
      RATE_LIMIT_MAX: 100,
      BODY_LIMIT: '100kb',
    })
  })

  it('throws on non-numeric PORT', () => {
    expect(() => parseEnv({ PORT: 'abc' })).toThrow(/Invalid environment variables/)
  })

  it('throws on PORT out of range', () => {
    expect(() => parseEnv({ PORT: '70000' })).toThrow()
    expect(() => parseEnv({ PORT: '0' })).toThrow()
  })

  it('splits and trims CORS_ORIGINS into an array', () => {
    const env = parseEnv({ CORS_ORIGINS: 'http://a.test , , https://b.test ,' })
    expect(env.CORS_ORIGINS).toEqual(['http://a.test', 'https://b.test'])
  })

  it('rejects invalid URL origins in CORS_ORIGINS', () => {
    expect(() => parseEnv({ CORS_ORIGINS: 'not-a-url' })).toThrow(/CORS_ORIGINS/)
  })

  it('rejects NODE_ENV outside the enum', () => {
    expect(() => parseEnv({ NODE_ENV: 'staging' })).toThrow()
  })

  it('coerces numeric strings', () => {
    const env = parseEnv({ PORT: '4000', TRUST_PROXY: '2', RATE_LIMIT_MAX: '5' })
    expect(env.PORT).toBe(4000)
    expect(env.TRUST_PROXY).toBe(2)
    expect(env.RATE_LIMIT_MAX).toBe(5)
  })

  it('returns a frozen object', () => {
    const env = parseEnv({})
    expect(Object.isFrozen(env)).toBe(true)
    expect(() => {
      env.PORT = 9999
    }).toThrow()
  })
})
