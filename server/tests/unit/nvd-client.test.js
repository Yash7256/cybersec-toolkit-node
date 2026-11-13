import { describe, it, expect, vi } from 'vitest'
import { createNvdClient, parseNvdResponse } from '../../src/net/nvdClient.js'

const env = { NVD_API_KEY: undefined, NVD_MAX_RESULTS_PER_SERVICE: 10 }

function payload(vulnerabilities) {
  return { vulnerabilities }
}

const normal = payload([
  {
    cve: {
      id: 'CVE-2024-0001',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'es', value: 'Spanish' }, { lang: 'en', value: 'English summary' }],
      metrics: {
        cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N' } }],
      },
      published: '2024-01-01T00:00:00.000',
    },
  },
  {
    cve: {
      id: 'CVE-2023-0002',
      vulnStatus: 'Rejected',
      descriptions: [{ lang: 'en', value: 'rejected' }],
      metrics: {},
    },
  },
  {
    cve: {
      id: 'CVE-2022-0003',
      vulnStatus: 'Analyzed',
      descriptions: [{ lang: 'en', value: 'Legacy v2 only' }],
      metrics: { cvssMetricV2: [{ cvssData: { baseScore: 6.5, vectorString: 'AV:N/AC:L' }, baseSeverity: 'MEDIUM' }] },
    },
  },
])

function response(status, body) {
  return { status, body: Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)) }
}

function clientWith(responses, { sleepFn = async () => {}, limiter } = {}) {
  const queue = [...responses]
  const http = {
    request: vi.fn(async () => {
      const next = queue.shift()
      if (next instanceof Error) throw next
      return next
    }),
  }
  const acquired = []
  const client = createNvdClient({
    env,
    http,
    limiter: limiter ?? { acquire: async () => acquired.push(Date.now()) },
    breaker: { exec: (fn) => fn() },
    sleepFn,
  })
  return { client, http, acquired }
}

describe('nvd client', () => {
  it('parses v3.1 and falls back to v2, skipping rejected CVEs', () => {
    const parsed = parseNvdResponse(normal)
    expect(parsed).toHaveLength(2)
    expect(parsed[0]).toMatchObject({
      cve_id: 'CVE-2024-0001',
      description: 'English summary',
      severity: 'CRITICAL',
      cvss_score: 9.8,
      cvss_vector: 'CVSS:3.1/AV:N',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001',
    })
    expect(parsed[1]).toMatchObject({ cve_id: 'CVE-2022-0003', severity: 'MEDIUM', cvss_score: 6.5 })
  })

  it('handles empty results, missing metrics, and malformed JSON', async () => {
    expect(parseNvdResponse(payload([]))).toEqual([])
    expect(parseNvdResponse(payload([{ cve: { id: 'CVE-2024-9999' } }]))[0].severity).toBe('UNKNOWN')

    const { client } = clientWith([response(200, '{not json')])
    await expect(client.lookupByCpe('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')).rejects.toMatchObject({
      kind: 'upstream',
    })
  })

  it('retries 429/503 with backoff and then succeeds', async () => {
    const sleeps = []
    const { client, http, acquired } = clientWith(
      [response(429, {}), response(503, {}), response(200, normal)],
      { sleepFn: async (ms) => sleeps.push(ms) }
    )
    const cves = await client.lookupByCpe('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
    expect(cves).toHaveLength(2)
    expect(http.request).toHaveBeenCalledTimes(3)
    expect(acquired).toHaveLength(3)
    expect(sleeps).toHaveLength(2)
    expect(sleeps[1]).toBeGreaterThan(sleeps[0])
  })

  it('gives up on persistent 403 as an upstream error', async () => {
    const { client, http } = clientWith([response(403, {}), response(403, {}), response(403, {})])
    await expect(client.lookupByCpe('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')).rejects.toMatchObject({
      kind: 'upstream',
    })
    expect(http.request).toHaveBeenCalledTimes(3)
  })

  it('waits on the shared limiter instead of rejecting', async () => {
    let waited = 0
    const { client } = clientWith([response(200, normal)], {
      limiter: {
        acquire: async () => {
          waited += 1
          await new Promise((resolve) => setTimeout(resolve, 5))
        },
      },
    })
    await client.lookupByCpe('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
    expect(waited).toBe(1)
  })
})
