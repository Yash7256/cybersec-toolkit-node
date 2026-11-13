import { describe, it, expect, vi } from 'vitest'
import { RESULT_KEYS, createSubdomainDefinition, mapLimit } from '../../src/tools/subdomain/index.js'
import { schema, validBaseDomain } from '../../src/tools/subdomain/schema.js'
import { WORDLISTS } from '../../src/tools/subdomain/wordlists.js'
import { resolveSubdomainRecords } from '../../src/tools/subdomain/resolve.js'
import { detectWildcard, markWildcardEntries } from '../../src/tools/subdomain/wildcard.js'
import { classifySubdomainRisk, computeConfidence } from '../../src/tools/subdomain/risk.js'
import { probeSubdomain, extractTitle, detectTechnologies } from '../../src/tools/subdomain/probe.js'
import { TYPE_NUMBERS } from '../../src/net/dohClient.js'

const env = {
  SUBDOMAIN_DNS_CONCURRENCY: 5,
  SUBDOMAIN_HTTP_CONCURRENCY: 3,
  SUBDOMAIN_HTTP_TIMEOUT_MS: 1000,
  SUBDOMAIN_WILDCARD_CHECKS: 2,
  ALLOW_PRIVATE_TARGETS: false,
}

function answer(type, data) {
  return { type: TYPE_NUMBERS[type], data }
}

function fakeQuery(responses) {
  return async (name, types) => types.map((type) => {
    const entry = responses[type] ?? { Status: 0 }
    return { type, data: entry }
  })
}

describe('subdomain wordlists', () => {
  it('contains the expected entry counts and no duplicates', () => {
    expect(WORDLISTS.small).toHaveLength(50)
    expect(WORDLISTS.medium).toHaveLength(223)
    expect(WORDLISTS.large).toHaveLength(926)
    for (const words of Object.values(WORDLISTS)) {
      expect(new Set(words).size).toBe(words.length)
      expect(words.every((word) => /^[a-z0-9][a-z0-9-]*$/i.test(word))).toBe(true)
    }
  })
})

describe('subdomain schema', () => {
  it('normalizes a valid base domain', () => {
    expect(schema.parse({ domain: ' Example.COM. ' })).toEqual({
      domain: 'example.com', wordlist: 'small', strictness: 'medium',
    })
  })

  it('rejects IPs, single labels, spaces, ports and empty values', () => {
    for (const domain of ['8.8.8.8', 'localhost', 'exa mple.com', 'example.com:443', '', '-bad.example']) {
      expect(validBaseDomain(domain)).toBe(false)
      expect(() => schema.parse({ domain })).toThrow()
    }
  })

  it('enforces literals', () => {
    expect(() => schema.parse({ domain: 'example.com', wordlist: 'huge' })).toThrow()
    expect(() => schema.parse({ domain: 'example.com', strictness: 'max' })).toThrow()
  })
})

describe('subdomain risk and confidence', () => {
  it('matches keywords on label boundaries only', () => {
    expect(classifySubdomainRisk('dev.example.com')).toMatchObject({ level: 'HIGH' })
    expect(classifySubdomainRisk('devops.example.com').level).not.toBe('HIGH')
    expect(classifySubdomainRisk('mail.example.com')).toMatchObject({ level: 'MEDIUM' })
  })

  it('classifies HTTP evidence', () => {
    expect(classifySubdomainRisk('x.example.com', { alive: true, status: 401 })).toMatchObject({ level: 'HIGH' })
    expect(classifySubdomainRisk('x.example.com', { alive: true, status: 301 })).toMatchObject({ level: 'MEDIUM' })
    expect(classifySubdomainRisk('x.example.com', { alive: true, status: 200 })).toMatchObject({ level: 'LOW' })
  })

  it('caps wildcard confidence and verifies strong evidence', () => {
    const entry = {
      resolved: true,
      records: { A: ['1.2.3.4'], AAAA: [], MX: [], TXT: [], NS: [] },
      http: { alive: true, status: 200, response_time_ms: 100, title: 'Home' },
    }
    expect(computeConfidence(entry)).toEqual({ verified: true, confidence: 0.75 })
    expect(computeConfidence({ ...entry, wildcard: true })).toEqual({ verified: false, confidence: 0.2 })
    expect(computeConfidence({ resolved: false })).toEqual({ verified: false, confidence: 0 })
  })
})

describe('subdomain resolution', () => {
  it('maps every record type and unquotes TXT', async () => {
    const result = await resolveSubdomainRecords('www.example.com', {
      env,
      query: fakeQuery({
        A: { Status: 0, Answer: [answer('A', '93.184.216.34')] },
        AAAA: { Status: 0, Answer: [answer('AAAA', '2606:2800:220:1:248:1893:25c8:1946')] },
        CNAME: { Status: 0, Answer: [answer('CNAME', 'example.com.')] },
        MX: { Status: 0, Answer: [answer('MX', '10 mail.example.com.')] },
        TXT: { Status: 0, Answer: [answer('TXT', '"v=spf1 -all"')] },
        NS: { Status: 0, Answer: [answer('NS', 'ns1.example.com.')] },
      }),
    })
    expect(result).toMatchObject({
      subdomain: 'www.example.com', resolved: true, ip: '93.184.216.34', source: ['wordlist'],
    })
    expect(result.records).toEqual({
      A: ['93.184.216.34'],
      AAAA: ['2606:2800:220:1:248:1893:25c8:1946'],
      CNAME: ['example.com'],
      MX: ['mail.example.com.'],
      TXT: ['v=spf1 -all'],
      NS: ['ns1.example.com'],
    })
  })

  it('reports NXDOMAIN and no-records distinctly', async () => {
    const nx = await resolveSubdomainRecords('missing.example.com', {
      env, query: fakeQuery({ A: { Status: 3 }, AAAA: { Status: 3 } }),
    })
    expect(nx).toMatchObject({ resolved: false, error: 'NXDOMAIN' })
    const empty = await resolveSubdomainRecords('empty.example.com', { env, query: fakeQuery({}) })
    expect(empty).toMatchObject({ resolved: false, error: 'no records' })
  })

  it('retries transient failures', async () => {
    let calls = 0
    const query = async (name, types) => {
      calls += 1
      return types.map((type) => ({ type, error: new Error('Lookup service unavailable') }))
    }
    const result = await resolveSubdomainRecords('x.example.com', {
      env, query, retries: 1, wait: async () => {},
    })
    expect(calls).toBe(2)
    expect(result.error).toBe('timeout')
  })
})

describe('subdomain wildcard handling', () => {
  it('detects wildcard answers', async () => {
    const result = await detectWildcard('example.com', {
      env,
      query: async () => [{ type: 'A', data: { Status: 0, Answer: [answer('A', '1.2.3.4')] } }],
      prefix: (() => { let i = 0; return () => `r${i++}` })(),
    })
    expect(result).toEqual({ detected: true, ips: ['1.2.3.4'] })
  })

  it('marks medium/high matches and high also checks AAAA', () => {
    const results = [
      { resolved: true, records: { A: ['1.2.3.4'], AAAA: [] } },
      { resolved: true, records: { A: [], AAAA: ['::1'] } },
      { resolved: false, records: {} },
    ]
    markWildcardEntries(results, ['1.2.3.4'], 'medium')
    expect(results[0].wildcard).toBe(true)
    expect(results[1].wildcard).toBeUndefined()
    markWildcardEntries(results, ['::1'], 'high')
    expect(results[1].wildcard).toBe(true)
  })
})

describe('subdomain probe', () => {
  it('extracts bounded titles and technologies', () => {
    expect(extractTitle(Buffer.from('<title>  Hello &amp; <b>world</b> </title>'))).toBe('Hello & world')
    expect(extractTitle(Buffer.from('no title'))).toBeNull()
    expect(detectTechnologies({ server: 'nginx', 'x-powered-by': 'PHP/8.2', 'set-cookie': ['laravel_session=x'] }, 'wp-content'))
      .toEqual(['Nginx', 'PHP/8.2', 'Laravel', 'WordPress'])
  })

  it('falls back from HTTPS to HTTP', async () => {
    const request = vi.fn()
      .mockRejectedValueOnce(new Error('tls failed'))
      .mockResolvedValueOnce({
        status: 200,
        headers: { server: 'nginx' },
        finalUrl: 'http://www.example.com/',
        body: Buffer.from('<title>Welcome</title>'),
      })
    const result = await probeSubdomain('www.example.com', { env, http: { request } })
    expect(request.mock.calls[0][0]).toBe('https://www.example.com')
    expect(request.mock.calls[1][0]).toBe('http://www.example.com')
    expect(result).toMatchObject({ alive: true, status: 200, scheme: 'http', title: 'Welcome', server: 'nginx' })
  })
})

describe('subdomain orchestrator', () => {
  it('returns the legacy shape, filters wildcard entries and blocks private probes', async () => {
    const resolve = vi.fn(async (hostname) => {
      if (hostname.startsWith('www.')) {
        return { subdomain: hostname, resolved: true, records: { A: ['93.184.216.34'], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [] }, source: ['wordlist'], dns_ms: 1, ip: '93.184.216.34' }
      }
      if (hostname.startsWith('admin.')) {
        return { subdomain: hostname, resolved: true, records: { A: ['10.0.0.1'], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [] }, source: ['wordlist'], dns_ms: 1, ip: '10.0.0.1' }
      }
      if (hostname.startsWith('dev.')) {
        return { subdomain: hostname, resolved: true, records: { A: ['1.2.3.4'], AAAA: [], CNAME: [], MX: [], TXT: [], NS: [] }, source: ['wordlist'], dns_ms: 1, ip: '1.2.3.4' }
      }
      return { subdomain: hostname, resolved: false, records: {}, source: ['wordlist'], dns_ms: 1, error: 'NXDOMAIN' }
    })
    const probe = vi.fn(async () => ({ alive: true, status: 200, title: 'Home', technologies: [] }))
    const definition = createSubdomainDefinition({
      env,
      resolve,
      wildcard: async () => ({ detected: true, ips: ['1.2.3.4'] }),
      probe,
      now: (() => { let t = 0; return () => (t += 10) })(),
    })
    const result = await definition.execute(definition.normalize({ domain: 'example.com', wordlist: 'small' }), { env })

    expect(Object.keys(result).sort()).toEqual([...RESULT_KEYS].sort())
    expect(result.total_checked).toBe(50)
    expect(result.wildcard_detected).toBe(true)
    expect(result.wildcard_ips).toEqual(['1.2.3.4'])
    expect(result.found.some((entry) => entry.subdomain === 'dev.example.com')).toBe(false)
    expect(result.found.some((entry) => entry.subdomain === 'www.example.com')).toBe(true)
    const admin = result.found.find((entry) => entry.subdomain === 'admin.example.com')
    expect(admin.http).toMatchObject({ alive: false, skipped_reason: expect.stringContaining('non-public') })
    expect(probe).toHaveBeenCalledTimes(1)
    expect(result.total_found).toBe(2)
    expect(definition.summarize(result)).toMatchObject({ total_checked: 50, total_found: 2, high_risk: 1 })
  })

  it('limits concurrency', async () => {
    let active = 0
    let peak = 0
    await mapLimit([1, 2, 3, 4, 5], 2, async () => {
      active += 1
      peak = Math.max(peak, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      active -= 1
    })
    expect(peak).toBe(2)
  })
})
