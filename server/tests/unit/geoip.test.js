import { describe, it, expect, vi } from 'vitest'
import {
  RESULT_KEYS,
  createGeoipDefinition,
} from '../../src/tools/geoip/index.js'
import { createProvider as createIpinfo } from '../../src/tools/geoip/providers/ipinfo.js'
import { createProvider as createIpwhois } from '../../src/tools/geoip/providers/ipwhois.js'
import { createProvider as createIpapi } from '../../src/tools/geoip/providers/ipapi.js'
import {
  boolOrNull,
  continentName,
  countryName,
  flagEmoji,
} from '../../src/tools/geoip/providers/_normalize.js'
import { detectCdn, locationAccuracy } from '../../src/tools/geoip/enrich.js'
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

const baseAnswer = {
  ip: '93.184.216.34',
  country: 'United States',
  country_code: 'US',
  continent: 'North America',
  continent_code: 'NA',
  region: 'California',
  city: 'Los Angeles',
  postal: '90001',
  latitude: 34.05,
  longitude: -118.24,
  timezone: 'America/Los_Angeles',
  utc_offset: null,
  flag_emoji: '🇺🇸',
  calling_code: null,
  asn: 'AS15133',
  org: 'Cloudflare, Inc.',
  isp: 'Cloudflare',
  asn_domain: 'cloudflare.com',
  is_proxy: false,
  is_hosting: true,
  is_vpn: null,
  is_tor: null,
  provider: 'ipinfo',
}

const answer = {
  name: 'ipinfo',
  lookup: vi.fn().mockResolvedValue({ ...baseAnswer }),
}

describe('geoip tool', () => {
  it('returns the first provider answer with every contract key', async () => {
    const geo = definition([answer])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
    expect(result.addresses).toEqual(['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])
    expect(result.resolved_ips).toEqual(result.addresses)
    expect(result.ip).toBe('93.184.216.34')
    expect(result.country).toBe('United States')
    expect(result.country_code).toBe('US')
    expect(result.map_url).toBe('https://maps.google.com/?q=34.05,-118.24')
    expect(result.is_cdn).toBe(true)
    expect(result.cdn_provider).toBe('Cloudflare')
    expect(result.location_accuracy).toBe('city')
    expect(result.confidence).toBeNull()
    expect(result.scan_duration_seconds).toEqual(expect.any(Number))
    expect(result.reverse_dns).toEqual(['example.com'])
    expect(result.fallback_note).toBeNull()
    expect(result.ip_results).toHaveLength(2)
    expect(result.ip_results[0]).toMatchObject({
      ip: '93.184.216.34',
      family: 4,
      country: 'United States',
      country_code: 'US',
      cdn_provider: 'Cloudflare',
      is_cdn: true,
      provider: 'ipinfo',
      error: null,
    })
  })

  it('falls back in provider order and records a note', async () => {
    const failing = { name: 'ipinfo', lookup: vi.fn().mockRejectedValue(new Error('down')) }
    const second = {
      name: 'ipwhois',
      lookup: vi.fn().mockResolvedValue({ ...baseAnswer, provider: 'ipwhois', org: 'Other' }),
    }
    const geo = definition([failing, second])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.provider).toBe('ipwhois')
    expect(result.fallback_note).toMatch(/ipinfo failed, ipwhois answered/)
  })

  it('throws upstream when every provider fails', async () => {
    const failing = {
      name: 'ipinfo',
      lookup: vi.fn().mockRejectedValue(new ToolError('upstream', 'Lookup service unavailable')),
    }
    const geo = definition([failing])
    await expect(geo.execute({ target: 'example.com' }, {})).rejects.toMatchObject({
      kind: 'upstream',
    })
  })

  it('serves a cache hit without calling any provider', async () => {
    const cached = { ip: '93.184.216.34', country: 'United States', provider: 'ipinfo' }
    const lookup = vi.fn()
    const getCached = vi.fn().mockResolvedValue(cached)
    const geo = definition([{ name: 'ipinfo', lookup }], { getCached })
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(getCached).toHaveBeenCalledWith('geoip:v2', '93.184.216.34')
    expect(result.cached).toBe(true)
    expect(result.scan_duration_seconds).toEqual(expect.any(Number))
    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
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

  it('records one failed IP without failing the lookup', async () => {
    const lookup = vi.fn(async (ip) => {
      if (ip === '93.184.216.34') throw new Error('ip failed')
      return { ...baseAnswer, ip }
    })
    const geo = definition([{ name: 'ipinfo', lookup }])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.ip_results).toHaveLength(2)
    expect(result.ip_results[0]).toMatchObject({
      ip: '93.184.216.34',
      error: 'ip failed',
    })
    expect(result.ip_results[1].error).toBeNull()
    expect(result.ip).toBe('2606:2800:220:1:248:1893:25c8:1946')
  })

  it('caps per-IP lookups at GEOIP_MAX_IPS while keeping all resolved IPs', async () => {
    const many = async () => ({
      host: 'example.com',
      addresses: Array.from({ length: 6 }, (_, index) => ({
        address: `8.8.8.${index + 1}`,
        family: 4,
      })),
    })
    const lookup = vi.fn(async (ip) => ({ ...baseAnswer, ip }))
    const geo = definition([{ name: 'ipinfo', lookup }], {
      resolve: many,
      env: { ...env, GEOIP_MAX_IPS: 4 },
    })
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.ip_results).toHaveLength(4)
    expect(result.resolved_ips).toHaveLength(6)
    expect(lookup).toHaveBeenCalledTimes(4)
  })

  it('sets confidence from a consensus lookup when enabled', async () => {
    const first = { name: 'ipinfo', lookup: vi.fn().mockResolvedValue({ ...baseAnswer }) }
    const second = {
      name: 'ipwhois',
      lookup: vi.fn().mockResolvedValue({ ...baseAnswer, provider: 'ipwhois' }),
    }
    const geo = definition([first, second], { env: { ...env, GEOIP_CONSENSUS: true } })
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.confidence).toBe('high')
    expect(second.lookup).toHaveBeenCalledTimes(1)
  })

  it('sets low confidence when consensus countries differ', async () => {
    const first = { name: 'ipinfo', lookup: vi.fn().mockResolvedValue({ ...baseAnswer }) }
    const second = {
      name: 'ipwhois',
      lookup: vi
        .fn()
        .mockResolvedValue({ ...baseAnswer, country: 'Canada', provider: 'ipwhois' }),
    }
    const geo = definition([first, second], { env: { ...env, GEOIP_CONSENSUS: true } })
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.confidence).toBe('low')
  })

  it('does not query a second provider when consensus is off', async () => {
    const first = { name: 'ipinfo', lookup: vi.fn().mockResolvedValue({ ...baseAnswer }) }
    const second = { name: 'ipwhois', lookup: vi.fn().mockResolvedValue({ ...baseAnswer }) }
    const geo = definition([first, second])
    const result = await geo.execute({ target: 'example.com' }, {})
    expect(result.confidence).toBeNull()
    expect(second.lookup).not.toHaveBeenCalled()
  })

  it('never exceeds the concurrency limit', async () => {
    const semaphore = createSemaphore({ limit: 5 })
    let active = 0
    let max = 0
    const slow = {
      name: 'ipinfo',
      async lookup(ip) {
        active += 1
        max = Math.max(max, active)
        await new Promise((resolve) => setTimeout(resolve, 5))
        active -= 1
        return { ip, provider: 'ipinfo' }
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
})

describe('geoip enrichment', () => {
  it('maps CDN organizations to provider names', () => {
    expect(detectCdn('Cloudflare, Inc.')).toEqual({
      is_cdn: true,
      cdn_provider: 'Cloudflare',
    })
    expect(detectCdn('Akamai Technologies')).toEqual({
      is_cdn: true,
      cdn_provider: 'Akamai',
    })
    expect(detectCdn('Amazon CloudFront')).toEqual({
      is_cdn: true,
      cdn_provider: 'Amazon CloudFront',
    })
    expect(detectCdn('Some Small ISP')).toEqual({ is_cdn: false, cdn_provider: null })
  })

  it('does not flag generic clouds as CDNs', () => {
    expect(detectCdn('Google LLC').is_cdn).toBe(false)
    expect(detectCdn('Microsoft Corporation').is_cdn).toBe(false)
  })

  it('derives location accuracy from the best available field', () => {
    expect(locationAccuracy({ city: 'X', region: 'Y', country: 'Z' })).toBe('city')
    expect(locationAccuracy({ city: null, region: 'Y', country: 'Z' })).toBe('region')
    expect(locationAccuracy({ country: 'Z' })).toBe('country')
    expect(locationAccuracy({})).toBeNull()
  })
})

describe('geoip normalizers', () => {
  it('resolves country names and flags from ISO codes', () => {
    expect(countryName('US')).toBe('United States')
    expect(countryName('ZZ')).toBeNull()
    expect(flagEmoji('US')).toBe('🇺🇸')
    expect(flagEmoji('us')).toBe('🇺🇸')
    expect(flagEmoji('USA')).toBeNull()
  })

  it('resolves continent names', () => {
    expect(continentName('EU')).toBe('Europe')
    expect(continentName('NA')).toBe('North America')
    expect(continentName('XX')).toBeNull()
  })

  it('keeps unsupplied booleans null', () => {
    expect(boolOrNull(true)).toBe(true)
    expect(boolOrNull(false)).toBe(false)
    expect(boolOrNull(null)).toBeNull()
    expect(boolOrNull(undefined)).toBeNull()
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

  it('maps ipinfo fields including postal, timezone, privacy and ASN domain', async () => {
    const provider = createIpinfo({
      client: client({
        ip: '1.2.3.4',
        country: 'US',
        city: 'X',
        region: 'California',
        postal: '90001',
        loc: '1,2',
        org: 'AS123 Example',
        timezone: 'America/Los_Angeles',
        asn: { asn: 'AS123', domain: 'example.com' },
        privacy: { proxy: true, hosting: false, vpn: null, tor: false },
      }),
    })
    const result = await provider.lookup('1.2.3.4', {})
    expect(result).toMatchObject({
      country: 'United States',
      country_code: 'US',
      postal: '90001',
      latitude: 1,
      longitude: 2,
      timezone: 'America/Los_Angeles',
      utc_offset: null,
      flag_emoji: '🇺🇸',
      calling_code: null,
      asn: 'AS123',
      asn_domain: 'example.com',
      is_proxy: true,
      is_hosting: false,
      is_vpn: null,
      is_tor: false,
      isp: null,
      provider: 'ipinfo',
    })
  })

  it('returns null booleans for ipinfo when privacy is absent', async () => {
    const provider = createIpinfo({
      client: client({ ip: '1.2.3.4', country: 'US' }),
    })
    const result = await provider.lookup('1.2.3.4', {})
    expect(result.is_proxy).toBeNull()
    expect(result.is_hosting).toBeNull()
    expect(result.is_vpn).toBeNull()
    expect(result.is_tor).toBeNull()
  })

  it('maps ipwhois fields and rejects success:false', async () => {
    const ok = createIpwhois({
      client: client({
        success: true,
        ip: '1.2.3.4',
        country: 'Germany',
        country_code: 'DE',
        continent: 'Europe',
        continent_code: 'EU',
        region: 'Berlin',
        city: 'Berlin',
        postal: '10115',
        latitude: 52.52,
        longitude: 13.4,
        calling_code: '49',
        flag: { emoji: '🇩🇪' },
        connection: { asn: 42, org: 'Example', isp: 'Example ISP', domain: 'example.de' },
        timezone: { id: 'Europe/Berlin', utc: '+01:00' },
        security: { proxy: false, hosting: true, vpn: false, tor: false },
      }),
    })
    await expect(ok.lookup('1.2.3.4', {})).resolves.toMatchObject({
      country: 'Germany',
      country_code: 'DE',
      continent: 'Europe',
      continent_code: 'EU',
      postal: '10115',
      timezone: 'Europe/Berlin',
      utc_offset: '+01:00',
      flag_emoji: '🇩🇪',
      calling_code: '49',
      asn: 'AS42',
      org: 'Example',
      isp: 'Example ISP',
      asn_domain: 'example.de',
      is_proxy: false,
      is_hosting: true,
      is_vpn: false,
      is_tor: false,
      provider: 'ipwhois',
    })

    const bad = createIpwhois({ client: client({ success: false }) })
    await expect(bad.lookup('1.2.3.4', {})).rejects.toThrow()
  })

  it('derives the ipwhois flag and null booleans when fields are absent', async () => {
    const provider = createIpwhois({
      client: client({ success: true, ip: '1.2.3.4', country_code: 'FR' }),
    })
    const result = await provider.lookup('1.2.3.4', {})
    expect(result.flag_emoji).toBe('🇫🇷')
    expect(result.is_proxy).toBeNull()
    expect(result.timezone).toBeNull()
  })

  it('maps ipapi fields and rejects error payloads', async () => {
    const ok = createIpapi({
      client: client({
        country_name: 'France',
        country_code: 'FR',
        continent_code: 'EU',
        city: 'Paris',
        region: 'Ile-de-France',
        postal: '75001',
        latitude: 48.8,
        longitude: 2.3,
        timezone: 'Europe/Paris',
        utc_offset: '+0100',
        country_calling_code: '+33',
        asn: 'AS3215',
        org: 'Orange',
      }),
    })
    await expect(ok.lookup('1.2.3.4', {})).resolves.toMatchObject({
      country: 'France',
      country_code: 'FR',
      continent: 'Europe',
      continent_code: 'EU',
      postal: '75001',
      city: 'Paris',
      timezone: 'Europe/Paris',
      utc_offset: '+0100',
      flag_emoji: '🇫🇷',
      calling_code: '+33',
      asn: 'AS3215',
      org: 'Orange',
      isp: null,
      is_proxy: null,
      is_hosting: null,
      is_vpn: null,
      is_tor: null,
      provider: 'ipapi',
    })

    const bad = createIpapi({ client: client({ error: true }) })
    await expect(bad.lookup('1.2.3.4', {})).rejects.toThrow()
  })
})
