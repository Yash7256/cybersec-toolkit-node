import { describe, it, expect, vi } from 'vitest'
import dns from 'node:dns'
import {
  RESULT_KEYS,
  createDnsDefinition,
  reverseName,
} from '../../src/tools/dns/index.js'
import { normalizeHost } from '../../src/security/hostPolicy.js'
import { classifyIp } from '../../src/security/ipPolicy.js'
import { TYPE_NUMBERS } from '../../src/net/dohClient.js'

function answer(type, data, ttl = 300) {
  return { name: 'example.com.', type: TYPE_NUMBERS[type], TTL: ttl, data }
}

function fakeDoh(responses) {
  return {
    async queryAll(name, types) {
      return types.map((type) => {
        const entry = responses[type] ?? { Status: 0 }
        return { type, data: entry, resolver: 'Cloudflare DoH' }
      })
    },
  }
}

const noerror = {
  A: { Status: 0, AD: true, Answer: [answer('A', '93.184.216.34')] },
  AAAA: { Status: 0, Answer: [answer('AAAA', '2606:2800:220:1:248:1893:25c8:1946')] },
  MX: { Status: 0, Answer: [answer('MX', '10 mail.example.com.')] },
  NS: { Status: 0, Answer: [answer('NS', 'ns1.example.com.')] },
  TXT: { Status: 0, Answer: [answer('TXT', '"v=spf1" " -all"')] },
  CNAME: { Status: 0, Answer: [answer('CNAME', 'www.example.com.')] },
  SOA: {
    Status: 0,
    Answer: [
      answer('SOA', 'ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300'),
    ],
  },
  CAA: { Status: 0, Answer: [answer('CAA', '0 issue "letsencrypt.org"')] },
}

describe('dns tool', () => {
  it('maps every ALL record type like the legacy result', async () => {
    const definition = createDnsDefinition({ doh: fakeDoh(noerror) })
    const input = definition.normalize({ target: 'example.com', record_type: 'ALL' })
    const result = await definition.execute(input)

    expect(Object.keys(result).sort()).toEqual([...RESULT_KEYS].sort())
    expect(result.error).toBeNull()
    expect(result.dnssec_validated).toBe(true)
    expect(result.query_time_ms).toBeGreaterThanOrEqual(0)

    const byType = Object.fromEntries(result.records.map((record) => [record.type, record]))
    expect(byType.A).toMatchObject({ type: 'A', ttl: 300, value: '93.184.216.34' })
    expect(byType.MX).toMatchObject({ priority: 10, value: 'mail.example.com.' })
    expect(byType.TXT.value).toBe('v=spf1 -all')
    expect(byType.SOA).toMatchObject({
      value: 'ns1.example.com.',
      mname: 'ns1.example.com.',
      rname: 'hostmaster.example.com.',
      serial: 2024010101,
    })
    expect(byType.CAA.value).toBe('0 issue "letsencrypt.org"')
  })

  it('reports NXDOMAIN as Domain not found and stops', async () => {
    const definition = createDnsDefinition({
      doh: fakeDoh({ A: { Status: 3 }, AAAA: { Status: 3 } }),
    })
    const result = await definition.execute(
      definition.normalize({ target: 'missing.example', record_type: 'ALL' })
    )
    expect(result.records).toEqual([])
    expect(result.error).toBe('Domain not found')
  })

  it('reports NODATA as No records of this type', async () => {
    const definition = createDnsDefinition({ doh: fakeDoh({ A: { Status: 0 } }) })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com', record_type: 'A' })
    )
    expect(result.error).toBe('No records of this type')
  })

  it('reports a query timeout', async () => {
    const definition = createDnsDefinition({
      doh: {
        async queryAll() {
          return [{ type: 'A', error: { kind: 'target', message: 'Query timed out' } }]
        },
      },
    })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com', record_type: 'A' })
    )
    expect(result.error).toBe('Query timed out')
  })

  it('builds PTR names for IPv4 and IPv6', () => {
    expect(reverseName('192.0.2.10')).toBe('10.2.0.192.in-addr.arpa')
    expect(reverseName('2001:db8::1')).toBe(
      '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
    )
    expect(reverseName('not-an-ip')).toBeNull()
  })

  it('switches IP input to a PTR lookup', async () => {
    let queriedName
    const definition = createDnsDefinition({
      doh: {
        async queryAll(name, types) {
          queriedName = name
          return types.map((type) => ({
            type,
            data: { Status: 0, Answer: [answer('PTR', 'example.com.')] },
            resolver: 'Cloudflare DoH',
          }))
        },
      },
    })
    const input = definition.normalize({ target: '192.0.2.10', record_type: 'ALL' })
    expect(input.record_type).toBe('PTR')
    const result = await definition.execute(input)
    expect(queriedName).toBe('10.2.0.192.in-addr.arpa')
    expect(result.records[0].type).toBe('PTR')
  })

  it('rejects private IPs and localhost at the policy layer', () => {
    expect(classifyIp('10.0.0.1').allowed).toBe(false)
    expect(() => normalizeHost('localhost')).toThrow()
  })

  it('never calls the system resolver', async () => {
    const lookup = vi.spyOn(dns.promises, 'lookup')
    const resolve = vi.spyOn(dns.promises, 'resolve')
    const definition = createDnsDefinition({ doh: fakeDoh(noerror) })
    await definition.execute(
      definition.normalize({ target: 'example.com', record_type: 'ALL' })
    )
    expect(lookup).not.toHaveBeenCalled()
    expect(resolve).not.toHaveBeenCalled()
    lookup.mockRestore()
    resolve.mockRestore()
  })
})
