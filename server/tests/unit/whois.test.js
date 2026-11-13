import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import {
  RESULT_KEYS,
  createWhoisDefinition,
} from '../../src/tools/whois/index.js'
import { parseWhois, isNotFound } from '../../src/tools/whois/port43.js'
import { normalizeRdap } from '../../src/tools/whois/rdapNormalize.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`../fixtures/rdap/${name}.json`, import.meta.url), 'utf8'))

const env = { WHOIS_CACHE_TTL_SEC: 3600 }

function makeDefinition({ rdap, legacy, cache = null } = {}) {
  return createWhoisDefinition({
    rdap,
    legacy: legacy ?? vi.fn(),
    getCached: cache?.get ?? (async () => null),
    setCached: cache?.set ?? (async () => {}),
    env,
  })
}

describe('whois normalization', () => {
  it('maps an RDAP domain fixture', () => {
    const result = normalizeRdap('example.com', fixture('domain'))
    expect(result.registrar).toBe('Example Registrar')
    expect(result.creation_date).toBe('2000-01-01T00:00:00Z')
    expect(result.name_servers).toEqual(['ns1.example.com', 'ns2.example.com'])
    expect(result.dnssec).toBe(true)
    expect(result.rdap_available).toBe(true)
    expect(result.expiry_status).toBe('active')
  })

  it('detects privacy redaction', () => {
    const result = normalizeRdap('private.example', fixture('privacy'))
    expect(result.privacy_protected).toBe(true)
    expect(result.risk_indicators).toContain('privacy_protected')
  })

  it('flags an expired domain', () => {
    const result = normalizeRdap('expired.example', fixture('expired'))
    expect(result.expiry_status).toBe('expired')
    expect(result.days_until_expiry).toBeLessThan(0)
    expect(result.risk_indicators).toContain('suspicious_status')
  })
})

describe('port 43 parser', () => {
  it('parses two registry date formats and key/value variants', () => {
    const text = [
      'Domain Name: EXAMPLE.COM',
      'Registrar: Example Registrar, Inc.',
      'Creation Date: 2000-01-01T00:00:00Z',
      'Registry Expiry Date: 2099-01-01T00:00:00Z',
      'Updated Date: 01-jan-2025',
      'Name Server: NS1.EXAMPLE.COM',
      'Name Server: ns1.example.com',
      'Domain Status: clientTransferProhibited',
      'Registrar Abuse Contact Email: abuse@example.com',
    ].join('\n')
    const result = parseWhois(text)
    expect(result.registrar).toBe('Example Registrar, Inc.')
    expect(result.creation_date).toBe('2000-01-01')
    expect(result.expiration_date).toBe('2099-01-01')
    expect(result.updated_date).toBe('2025-01-01')
    expect(result.name_servers).toEqual(['ns1.example.com'])
    expect(result.status).toEqual(['clientTransferProhibited'])
    expect(result.emails).toEqual(['abuse@example.com'])
    expect(result.raw_text.length).toBeLessThanOrEqual(10 * 1024)
  })

  it('detects a not-found body', () => {
    expect(isNotFound('No match for "NOPE.EXAMPLE".')).toBe(true)
    expect(isNotFound('Domain Name: EXAMPLE.COM')).toBe(false)
  })
})

describe('whois tool', () => {
  it('reduces a subdomain to its registrable domain', () => {
    const definition = makeDefinition({ rdap: {} })
    expect(definition.normalize({ target: 'https://www.deep.example.co.uk/path' }).target).toBe(
      'example.co.uk'
    )
  })

  it('accepts a public IP and rejects a private one', () => {
    const definition = makeDefinition({ rdap: {} })
    expect(definition.normalize({ target: '8.8.8.8' })).toMatchObject({ isIp: true })
    expect(() => definition.normalize({ target: '10.0.0.1' })).toThrow()
  })

  it('returns a normal domain result with every contract key', async () => {
    const queryDomain = vi.fn().mockResolvedValue({ found: true, data: fixture('domain') })
    const definition = makeDefinition({ rdap: { queryDomain, queryIp: vi.fn() } })
    const input = definition.normalize({ target: 'example.com' })
    const result = await definition.execute(input)
    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
    expect(result.registrar).toBe('Example Registrar')
    expect(result.cached).toBe(false)
  })

  it('marks a 404 as available', async () => {
    const queryDomain = vi.fn().mockResolvedValue({ found: false })
    const definition = makeDefinition({
      rdap: { queryDomain, queryIp: vi.fn() },
      legacy: vi.fn().mockResolvedValue({ available: true }),
    })
    const result = await definition.execute(definition.normalize({ target: 'free.example' }))
    expect(result.available).toBe(true)
    expect(result.rdap_available).toBe(false)
  })

  it('serves a cache hit without calling upstream', async () => {
    const queryDomain = vi.fn()
    const cached = { ...normalizeRdap('example.com', fixture('domain')) }
    const definition = makeDefinition({
      rdap: { queryDomain, queryIp: vi.fn() },
      cache: { get: async () => cached, set: vi.fn() },
    })
    const result = await definition.execute(definition.normalize({ target: 'example.com' }))
    expect(result.cached).toBe(true)
    expect(queryDomain).not.toHaveBeenCalled()
  })

  it('falls back to port 43 when RDAP is down', async () => {
    const queryDomain = vi.fn().mockRejectedValue(new ToolError('upstream', 'Lookup service unavailable'))
    const legacy = vi.fn().mockResolvedValue({
      available: false,
      registrar: 'Legacy Registrar',
      name_servers: ['ns1.example.com'],
      status: [],
    })
    const definition = makeDefinition({ rdap: { queryDomain, queryIp: vi.fn() }, legacy })
    const result = await definition.execute(definition.normalize({ target: 'example.com' }))
    expect(result.registrar).toBe('Legacy Registrar')
    expect(result.rdap_available).toBe(false)
    expect(legacy).toHaveBeenCalledWith('example.com')
  })

  it('throws upstream when both RDAP and port 43 fail', async () => {
    const queryDomain = vi.fn().mockRejectedValue(new ToolError('upstream', 'Lookup service unavailable'))
    const legacy = vi.fn().mockRejectedValue(new ToolError('upstream', 'Lookup service unavailable'))
    const definition = makeDefinition({ rdap: { queryDomain, queryIp: vi.fn() }, legacy })
    await expect(
      definition.execute(definition.normalize({ target: 'example.com' }))
    ).rejects.toMatchObject({ kind: 'upstream' })
  })

  it('works with a cache that is down', async () => {
    const queryDomain = vi.fn().mockResolvedValue({ found: true, data: fixture('domain') })
    const definition = createWhoisDefinition({
      rdap: { queryDomain, queryIp: vi.fn() },
      legacy: vi.fn(),
      getCached: async () => null,
      setCached: async () => {
        throw new Error('redis down')
      },
      env,
    })
    const result = await definition.execute(definition.normalize({ target: 'example.com' }))
    expect(result.registrar).toBe('Example Registrar')
  })
})
