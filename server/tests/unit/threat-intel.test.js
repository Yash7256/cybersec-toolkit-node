import { describe, it, expect, vi } from 'vitest'
import {
  checkThreatIntelligence,
  spamhausCheck,
} from '../../src/scanner/intel/threatIntel.js'

function response(status, body) {
  return { status, body: Buffer.from(JSON.stringify(body)) }
}

function httpReturning(data) {
  return { request: vi.fn(async () => response(200, { data })) }
}

function redisFake() {
  const store = new Map()
  return {
    store,
    get: vi.fn(async (key) => store.get(key) ?? null),
    setex: vi.fn(async (key, ttl, value) => store.set(key, value)),
  }
}

const baseEnv = {
  THREAT_INTEL_SPAMHAUS: false,
  THREAT_INTEL_CACHE_TTL_SEC: 60,
}

describe('threat intelligence', () => {
  it('returns Not checked when no source is configured', async () => {
    const http = { request: vi.fn() }
    const result = await checkThreatIntelligence({
      ip: '8.8.8.8',
      env: baseEnv,
      http,
      redis: null,
    })
    expect(result.reputation).toBe('Not checked')
    expect(http.request).not.toHaveBeenCalled()
  })

  it('never checks private or loopback addresses', async () => {
    const http = { request: vi.fn() }
    const result = await checkThreatIntelligence({
      ip: '127.0.0.1',
      env: { ...baseEnv, ABUSEIPDB_API_KEY: 'secret-key' },
      http,
      redis: null,
    })
    expect(result.reputation).toBe('Private/Local')
    expect(http.request).not.toHaveBeenCalled()
  })

  it('returns Clean for a clean public IP', async () => {
    const http = httpReturning({ totalReports: 0, abuseConfidenceScore: 0 })
    const result = await checkThreatIntelligence({
      ip: '8.8.8.8',
      env: { ...baseEnv, ABUSEIPDB_API_KEY: 'secret-key' },
      http,
      redis: null,
      limiter: { acquire: async () => {} },
      resolver: async () => { const err = new Error('not found'); err.code = 'ENOTFOUND'; throw err },
    })
    expect(result.reputation).toBe('Clean')
    expect(result.sources).toEqual(['AbuseIPDB'])
    expect(result.error).toBeNull()
  })

  it('marks high-confidence reports as malicious (Spamhaus disabled)', async () => {
    const http = httpReturning({ totalReports: 12, abuseConfidenceScore: 92 })
    const result = await checkThreatIntelligence({
      ip: '8.8.4.4',
      env: { ...baseEnv, ABUSEIPDB_API_KEY: 'secret-key' },
      http,
      redis: null,
      limiter: { acquire: async () => {} },
      resolver: async () => [],
    })
    expect(result.reputation).toBe('Malicious')
    expect(result.reported_times).toBe(12)
  })

  it('degrades when AbuseIPDB fails and never exposes the key', async () => {
    const http = { request: vi.fn(async () => response(429, { errors: [] })) }
    const result = await checkThreatIntelligence({
      ip: '1.1.1.1',
      env: { ...baseEnv, ABUSEIPDB_API_KEY: 'super-secret-key' },
      http,
      redis: null,
      limiter: { acquire: async () => {} },
      resolver: async () => [],
    })
    expect(result.reputation).toBe('Unknown')
    expect(result.abuseipdb.checked).toBe(true)
    expect(result.abuseipdb.available).toBe(false)
    expect(JSON.stringify(result)).not.toContain('super-secret-key')
  })

  it('treats Spamhaus refusal codes as unavailable, not clean', async () => {
    const result = await spamhausCheck({
      ip: '8.8.8.8',
      env: { ...baseEnv, THREAT_INTEL_SPAMHAUS: true },
      resolve4: async () => ['127.255.255.254'],
    })
    expect(result.checked).toBe(false)
    expect(result.listed).toBe(false)
    expect(result.unavailable).toBe(true)
  })

  it('caches results and serves the cache without upstream calls', async () => {
    const redis = redisFake()
    const http = httpReturning({ totalReports: 0, abuseConfidenceScore: 0 })
    const env = { ...baseEnv, ABUSEIPDB_API_KEY: 'secret-key' }
    const first = await checkThreatIntelligence({
      ip: '9.9.9.9', env, http, redis, limiter: { acquire: async () => {} }, resolver: async () => [],
    })
    const second = await checkThreatIntelligence({
      ip: '9.9.9.9', env, http, redis, limiter: { acquire: async () => {} }, resolver: async () => [],
    })
    expect(http.request).toHaveBeenCalledTimes(1)
    expect(second).toEqual(first)
    expect(redis.setex).toHaveBeenCalledWith('cst:intel:9.9.9.9', 60, expect.any(String))
  })
})
