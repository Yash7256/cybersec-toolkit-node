import { describe, it, expect, afterAll } from 'vitest'
import { parseEnv } from '../../src/config/env.js'
import { disconnectRedis } from '../../src/redis/client.js'
import { asUser, makeTestApp } from '../helpers/auth.js'

const live = process.env.LIVE_TESTS === '1'
const env = parseEnv({ ...process.env, LOG_LEVEL: 'silent', FREE_DAILY_LIMIT: '100' })

describe.skipIf(!live)('live smoke test', () => {
  afterAll(() => disconnectRedis())

  it('runs all six tools against example.com', async () => {
    const app = makeTestApp({ env })
    const user = await asUser(app, { clerkId: 'live_smoke' })
    const timings = []

    async function call(name, body) {
      const started = Date.now()
      const res = await user.post(`/api/tools/${name}`).send(body)
      timings.push({ tool: name, status: res.status, ms: Date.now() - started })
      expect(res.status, `${name}: ${JSON.stringify(res.body)}`).toBe(200)
      expect(res.body.status).toBe('COMPLETED')
      return res.body.data
    }

    const dns = await call('dns', { target: 'example.com', record_type: 'A' })
    expect(Array.isArray(dns.records)).toBe(true)
    expect(dns.records.length).toBeGreaterThan(0)

    const ssl = await call('ssl', { host: 'example.com' })
    expect(typeof ssl.supports_tls12).toBe('boolean')

    const headers = await call('http_headers', { target: 'example.com' })
    expect([200, 301, 302, 307, 308]).toContain(headers.status_code)

    const whois = await call('whois', { target: 'example.com' })
    expect(whois.available === false || whois.registrar !== null).toBe(true)

    const geoip = await call('geoip', { target: 'example.com' })
    expect(geoip.country).not.toBeNull()

    const ping = await call('ping', { target: 'example.com', count: 2 })
    expect(['icmp', 'tcp']).toContain(ping.method)

    console.table(timings)
    for (const timing of timings) expect(timing.ms).toBeLessThan(15000)
  }, 90000)
})
