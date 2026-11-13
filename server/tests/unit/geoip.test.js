import { describe, it, expect, vi } from 'vitest'
import {
  RESULT_KEYS,
  createGeoipDefinition,
} from '../../src/tools/geoip/index.js'
import { createProvider as createIpinfo } from '../../src/tools/geoip/providers/ipinfo.js'
import { createProvider as createIpwhois } from '../../src/tools/geoip/providers/ipwhois.js'
import { createProvider as createIpapi } from '../../src/tools/geoip/providers/ipapi.js'
import { detectCdn } from '../../src/tools/geoip/enrich.js'
import { createSemaphore } from '../../src/tools/_shared/limits.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const env = {
  GEOIP_PROVIDER_ORDER: 'ipinfo,ipwhois',
  GEOIP_CACHE_TTL_SEC: 3600,
  GEOIP_MAX_CONCURRENT: 5,
  GEOIP_RATE_PER_MIN: 55,
  DNS_TIMEOUT_MS: 3000,
  IPINFO_API_TOKEN: 'token',
}

const resolve = async () => ({
  host: 'example.com',
  addresses: [
    { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 },
    { address: '93.184.216.34', family: 4 },
  ],
})

const limits = () => ({
  acquireGeoipRate: async () => {},
  withGeoipSlot: async (fn) => fn(),
})

const enrich = async () => ({ reverse_dns: ['example.com'], abuse_contact: null })
const breaker = { exec: (fn) => fn() }

function definition(providers, overrides = {}) {
  return createGeoipDefinition({
    providers,
    resolve,
    enrich,
    limits: limits(),
    breaker,
    env,
    wait: async () => {},
    getCached: async () => null,
    setCached: async () => {},
    ...overrides,
  })
}

const answer = {
  name: 'ipinfo',
  lookup: vi.fn().mockResolvedValue({
    ip: '93.184.216.34',
    country: 'US',
    region: 'California',
    city: 'Los Angeles',
    latitude: 34.05,
    longitude: -118.24,
    asn: 'AS15133',
    org: 'Cloudflare, Inc.',
    provider: 'ipinfo',
  }),
}

describe('geoip tool', () => {
  it('returns the first provider answer with every contract key', async () => {
    const geo = definition([answer])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
    expect(result.ip).toBe('93.184.216.34')
    expect(result.country).toBe('US')
    expect(result.map_url).toBe('https://maps.google.com/?q=34.05,-118.24')
    expect(result.is_cdn).toBe(true)
    expect(result.reverse_dns).toEqual(['example.com'])
    expect(result.fallback_note).toBeNull()
  })

  it('falls back in provider order and records a note', async () => {
    const failing = { name: 'ipinfo', lookup: vi.fn().mockRejectedValue(new Error('down')) }
    const second = { name: 'ipwhois', lookup: vi.fn().mockResolvedValue({ ...answer.lookup(), provider: 'ipwhois', org: 'Other' }) }
    const geo = definition([failing, second])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.provider).toBe('ipwhois')
    expect(result.fallback_note).toMatch(/ipinfo failed, ipwhois answered/)
  })

  it('throws upstream when every provider fails', async () => {
    const failing = { name: 'ipinfo', lookup: vi.fn().mockRejectedValue(new ToolError('upstream', 'Lookup service unavailable')) }
    const geo = definition([failing])
    await expect(geo.execute({ target: 'example.com' }, {})).rejects.toMatchObject({
      kind: 'upstream',
    })
  })

  it('serves a cache hit without calling any provider', async () => {
    const cached = { ip: '93.184.216.34', country: 'US', provider: 'ipinfo' }
    const lookup = vi.fn()
    const geo = definition([{ name: 'ipinfo', lookup }], {
      getCached: async () => cached,
    })
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.cached).toBe(true)
    expect(lookup).not.toHaveBeenCalled()
  })

  it('rejects a private target through the policy', async () => {
    const geo = definition([answer], {
      resolve: async () => {
        throw Object.assign(new Error('blocked'), { statusCode: 422 })
      },
    })
    await expect(geo.execute({ target: '10.0.0.1' }, {})).rejects.toThrow('blocked')
  })

  it('never exceeds the concurrency limit', async () => {
    const semaphore = createSemaphore({ limit: 5 })
    let active = 0
    let max = 0
    const slow = {
      name: 'ipinfo',
      async lookup() {
        active += 1
        max = Math.max(max, active)
        await new Promise((resolve) => setTimeout(resolve, 5))
        active -= 1
        return { ip: '93.184.216.34', provider: 'ipinfo' }
      },
    }
    const geo = definition([slow], {
      limits: {
        acquireGeoipRate: async () => {},
        withGeoipSlot: async (fn) => {
          const release = await semaphore.acquire()
          try {
            return await fn()
          } finally {
            release()
          }
        },
      },
    })
    await Promise.all(
      Array.from({ length: 20 }, () => geo.execute({ target: 'example.com' }, {}))
    )
    expect(max).toBeLessThanOrEqual(5)
  })

  it('detects CDN organizations', () => {
    expect(detectCdn('Cloudflare, Inc.')).toBe(true)
    expect(detectCdn('Akamai Technologies')).toBe(true)
    expect(detectCdn('Some Small ISP')).toBe(false)
  })
})

describe('geoip providers', () => {
  function client(body) {
    return {
      async request() {
        return { status: 200, body: Buffer.from(JSON.stringify(body)) }
      },
    }
  }

  it('maps ipinfo fields including loc and org ASN', async () => {
    const provider = createIpinfo({
      client: client({ ip: '1.2.3.4', country: 'US', city: 'X', loc: '1,2', org: 'AS123 Example' }),
    })
    const result = await provider.lookup('1.2.3.4', {})
    expect(result).toMatchObject({ country: 'US', latitude: 1, longitude: 2, asn: 'AS123' })
  })

  it('maps ipwhois fields and rejects success:false', async () => {
    const ok = createIpwhois({
      client: client({ success: true, ip: '1.2.3.4', country: 'DE', connection: { asn: 42, org: 'Example' } }),
    })
    await expect(ok.lookup('1.2.3.4', {})).resolves.toMatchObject({ country: 'DE', asn: 'AS42' })

    const bad = createIpwhois({ client: client({ success: false }) })
    await expect(bad.lookup('1.2.3.4', {})).rejects.toThrow()
  })

  it('maps ipapi fields and rejects error payloads', async () => {
    const ok = createIpapi({
      client: client({ country_name: 'FR', city: 'Paris', latitude: 48.8, longitude: 2.3 }),
    })
    await expect(ok.lookup('1.2.3.4', {})).resolves.toMatchObject({ country: 'FR', city: 'Paris' })

    const bad = createIpapi({ client: client({ error: true }) })
    await expect(bad.lookup('1.2.3.4', {})).rejects.toThrow()
  })
})
