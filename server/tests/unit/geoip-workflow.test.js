import { describe, it, expect, vi } from 'vitest'
import { parseOriginTxt, parseAsnNameTxt } from '../../src/tools/geoip/sources/cymru.js'
import { parseTorExitList } from '../../src/tools/geoip/sources/tor.js'
import { hostingStatus, hostingProvider } from '../../src/tools/geoip/sources/hosting.js'
import { detectAnycast } from '../../src/tools/geoip/sources/anycast.js'
import { buildPrivacy, classifyUsageType } from '../../src/tools/geoip/sources/privacy.js'
import { dnsblCheck } from '../../src/tools/geoip/sources/reputation.js'
import { createAsnDefinition } from '../../src/tools/asn/index.js'
import { createCidrDefinition } from '../../src/tools/geoip/cidr.js'
import { createBulkDefinition } from '../../src/tools/geoip/bulk.js'

describe('GeoIP source parsing', () => {
  it('parses Team Cymru origin TXT records and selects the matching prefix', () => {
    const records = [
      ['15169 | 8.8.8.0/24 | US | arin | 1992-12-01'],
      ['13335 | 8.8.0.0/16 | US | arin | 1992-12-01'],
    ]
    expect(parseOriginTxt(records, '8.8.8.8')).toEqual({
      asn: 'AS15169',
      prefix: '8.8.8.0/24',
      country: 'US',
      rir: 'arin',
      allocated: '1992-12-01',
    })
  })

  it('parses Team Cymru ASN name TXT records', () => {
    const records = [['15169 | US | arin | 2000-03-30 | GOOGLE, US']]
    expect(parseAsnNameTxt(records)).toEqual({
      asn: 'AS15169',
      country: 'US',
      rir: 'arin',
      allocated: '2000-03-30',
      name: 'GOOGLE, US',
    })
  })

  it('parses Tor exit list bodies and ignores comments', () => {
    const body = Buffer.from('# comment\n1.1.1.1\n2.2.2.2\n\n3.3.3.3\n')
    expect(parseTorExitList(body)).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3'])
  })

  it('detects hosting ASNs from the curated list', () => {
    expect(hostingStatus('AS16509')).toBe(true)
    expect(hostingStatus('as16509')).toBe(true)
    expect(hostingStatus('AS999999')).toBe(false)
    expect(hostingStatus('AS3356')).toBe(false)
    expect(hostingStatus('AS4134')).toBe(false)
    expect(hostingStatus(null)).toBeNull()
    expect(hostingProvider('AS16509')).toBeTruthy()
  })

  it('detects curated anycast prefixes and ASNs', () => {
    expect(detectAnycast({ ip: '8.8.8.8' })).toMatchObject({ likely: true })
    expect(detectAnycast({ asn: 'AS13335' })).toMatchObject({ likely: true })
    expect(detectAnycast({ ip: '203.0.113.1', asn: 'AS64500' })).toEqual({ likely: null, basis: null })
  })

  it('classifies usage types and derives privacy with an explicit basis', () => {
    expect(classifyUsageType('Data Center/Web Hosting/Transit')).toBe('hosting')
    expect(classifyUsageType('Mobile ISP')).toBe('mobile')
    expect(classifyUsageType('unknown')).toBeNull()
    expect(buildPrivacy({ torStatus: true, hosting: false })).toMatchObject({
      ip_type: 'tor',
      ip_type_basis: 'tor-exit-list',
      privacy: { tor: true, hosting: false },
      privacy_sources: ['tor-exit-list', 'asn-list'],
    })
    expect(buildPrivacy({ hosting: true })).toMatchObject({
      ip_type: 'hosting',
      ip_type_basis: 'asn-list',
    })
  })
})

describe('DNSBL reputation', () => {
  it('separates listed, clean, and unknown zones', async () => {
    const resolver = {
      resolve4: vi.fn(async (host) => {
        if (host.endsWith('listed.example')) return ['127.0.0.2']
        if (host.endsWith('refused.example')) return ['127.255.255.254']
        throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' })
      }),
    }
    const result = await dnsblCheck('8.8.8.8', { zones: ['listed.example', 'refused.example', 'clean.example'], resolver })
    expect(result).toMatchObject({ checked: true, listed: ['listed.example'], clean: ['clean.example'], unknown: ['refused.example'] })
  })

  it('skips non-IPv4 and empty zone lists', async () => {
    expect(await dnsblCheck('2001:db8::1', { zones: ['x.example'] })).toMatchObject({ checked: false })
    expect(await dnsblCheck('8.8.8.8', { zones: [] })).toMatchObject({ checked: false })
  })
})

describe('ASN definition', () => {
  it('merges Team Cymru and RIPEstat results', async () => {
    const definition = createAsnDefinition({
      cymru: vi.fn(async () => ({ asn: 'AS15169', name: 'GOOGLE', country: 'US', rir: 'arin', allocated: '2000-03-30' })),
      ripestat: vi.fn(async () => ({ prefixes: ['8.8.8.0/24'], prefix_count: 1, truncated: false })),
    })
    const data = await definition.execute({ asn: 'AS15169' })
    expect(data).toMatchObject({ asn: 'AS15169', name: 'GOOGLE', prefix_count: 1 })
    expect(data.prefixes).toEqual(['8.8.8.0/24'])
  })

  it('normalizes ASN input and reports source warnings without fabricating data', async () => {
    const definition = createAsnDefinition({
      cymru: vi.fn(async () => { throw new Error('down') }),
      ripestat: vi.fn(async () => ({ prefixes: [], prefix_count: 0, truncated: false })),
    })
    const data = await definition.execute({ asn: '15169' })
    expect(data.name).toBeNull()
    expect(data.warnings).toEqual([{ source: 'team-cymru', message: 'down' }])
  })
})

describe('CIDR and bulk definitions', () => {
  it('expands public CIDR blocks and skips private addresses', () => {
    const definition = createCidrDefinition()
    const input = { target: '8.8.8.0/30' }
    const target = definition.validateInput(input)
    expect(target.display).toBe('8.8.8.0/30')
    expect(input.addresses).toEqual(['8.8.8.0', '8.8.8.1', '8.8.8.2', '8.8.8.3'])
    expect(() => definition.validateInput({ target: '192.168.1.0/30' })).toThrow(/no public addresses/)
    expect(() => definition.validateInput({ target: '8.8.8.0/16' })).toThrow(/between \/24 and \/32/)
  })

  it('aggregates CIDR results with per-address status', async () => {
    const definition = createCidrDefinition({
      geoip: {
        execute: vi.fn(async ({ target }) => {
          if (target.endsWith('.1')) throw new Error('lookup failed')
          return { ip: target, country_code: 'US', asn: 'AS15169', ip_type: 'hosting', privacy: { hosting: true }, warnings: [] }
        }),
      },
    })
    const input = { target: '8.8.8.0/30' }
    definition.validateInput(input)
    const data = await definition.execute(input)
    expect(data).toMatchObject({ total: 4, completed: 3, failed: 1 })
    expect(data.summary.countries).toEqual({ US: 3 })
    expect(data.results.find((row) => row.ip === '8.8.8.1')).toMatchObject({ status: 'error' })
  })

  it('dedupes bulk input, enforces tier limits, and charges one quota unit per target', async () => {
    const definition = createBulkDefinition({
      env: { GEOIP_BULK_MAX_FREE: 2, GEOIP_BULK_MAX_PAID: 5 },
      validate: vi.fn(async (value) => {
        if (value === 'bad') throw new Error('blocked')
        return {}
      }),
    })
    const input = { targets: ['8.8.8.8', '8.8.8.8', 'example.com', 'bad'] }
    const target = await definition.validateInput(input, { req: { user: { tier: 'FREE', role: 'USER' } } })
    expect(target.display).toBe('bulk (2)')
    expect(input.targets).toEqual(['8.8.8.8', 'example.com'])
    expect(input.rejected).toEqual([{ input: 'bad', reason: 'blocked' }])
    expect(definition.quotaUnits(input)).toBe(2)
    await expect(definition.validateInput({ targets: ['a', 'b', 'c'] }, { req: { user: { tier: 'FREE' } } }))
      .rejects.toThrow(/limited to 2/)
  })

  it('aggregates bulk results and keeps rejected rows', async () => {
    const definition = createBulkDefinition({
      geoip: { execute: vi.fn(async ({ target }) => ({ ip: target, country_code: 'US', asn: 'AS1', ip_type: 'hosting', privacy: {}, warnings: [] })) },
    })
    const input = { targets: ['8.8.8.8', '9.9.9.9'], rejected: [{ input: 'bad', reason: 'blocked' }] }
    const data = await definition.execute(input)
    expect(data).toMatchObject({ total: 2, completed: 2, failed: 0 })
    expect(data.rejected).toHaveLength(1)
    expect(data.results.map((row) => row.input)).toEqual(['8.8.8.8', '9.9.9.9'])
  })
})
