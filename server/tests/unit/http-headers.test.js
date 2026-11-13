import { describe, it, expect } from 'vitest'
import {
  RESULT_KEYS,
  createHttpHeadersDefinition,
} from '../../src/tools/httpHeaders/index.js'
import { normalizeTarget } from '../../src/tools/httpHeaders/request.js'

const ctx = { target: { addresses: [{ address: '93.184.216.34', family: 4 }] } }

const SECURE_HEADERS = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
}

function fakeClient(headers = {}, overrides = {}) {
  return {
    async request(url) {
      return {
        status: 200,
        headers,
        finalUrl: url,
        redirects: [],
        addresses: ctx.target.addresses,
        body: Buffer.alloc(0),
        ...overrides,
      }
    },
  }
}

async function run(headers, overrides) {
  const definition = createHttpHeadersDefinition({ client: fakeClient(headers, overrides) })
  const input = definition.normalize({ target: 'example.com', path: '/' })
  return definition.execute(input, ctx)
}

describe('http headers tool', () => {
  it('scores an all-secure site high with low risk', async () => {
    const result = await run(SECURE_HEADERS)
    expect(Object.keys(result)).toEqual(expect.arrayContaining(RESULT_KEYS))
    expect(result.status_code).toBe(200)
    expect(result.security_score).toBe(100)
    expect(result.risk_level).toBe('low')
    expect(result.hsts.strong).toBe(true)
    expect(result.csp.weak).toBe(false)
    expect(result.clickjacking.protected).toBe(true)
    expect(result.tls_verification_skipped).toBe(true)
  })

  it('scores a bare site low and lists missing headers', async () => {
    const result = await run({})
    expect(result.security_score).toBeLessThan(30)
    expect(result.risk_level).toBe('high')
    expect(result.security_headers.filter((header) => !header.present)).toHaveLength(6)
  })

  it('flags a weak CSP', async () => {
    const result = await run({
      ...SECURE_HEADERS,
      'content-security-policy': "default-src * 'unsafe-inline' 'unsafe-eval'",
    })
    expect(result.csp.weak).toBe(true)
    expect(result.csp.unsafeInline).toBe(true)
    expect(result.csp.unsafeEval).toBe(true)
    expect(result.csp.wildcard).toBe(true)
    expect(result.security_score).toBeLessThan(100)
  })

  it('flags insecure cookies', async () => {
    const result = await run({
      ...SECURE_HEADERS,
      'set-cookie': ['sid=abc; Path=/', 'theme=dark; Secure; HttpOnly'],
    })
    expect(result.cookies).toHaveLength(2)
    expect(result.cookies[0].issues).toEqual(['missing_secure', 'missing_httponly'])
    expect(result.cookies[1].issues).toEqual([])
  })

  it('records a multi-hop redirect chain', async () => {
    const redirects = [
      { from: 'https://example.com/', to: 'https://www.example.com/', status: 301 },
      { from: 'https://www.example.com/', to: 'https://www.example.com/home', status: 302 },
    ]
    const result = await run(SECURE_HEADERS, { redirects, finalUrl: 'https://www.example.com/home' })
    expect(result.redirects).toHaveLength(2)
    expect(result.url).toBe('https://www.example.com/home')
  })

  it('detects a Cloudflare CDN', async () => {
    const result = await run({ ...SECURE_HEADERS, server: 'cloudflare', 'cf-ray': 'abc' })
    expect(result.technologies).toContainEqual({ name: 'Cloudflare', category: 'cdn' })
  })

  it('flags server version disclosure', async () => {
    const result = await run({ ...SECURE_HEADERS, server: 'Apache/2.4.1' })
    expect(result.disclosure.server).toBe('Apache/2.4.1')
    expect(result.disclosure.issues.length).toBeGreaterThan(0)
    expect(result.security_score).toBeLessThan(100)
  })

  it('reads dangerous methods from the Allow header only', async () => {
    const result = await run({ ...SECURE_HEADERS, allow: 'GET, POST, TRACE, PUT' })
    expect(result.allowed_methods).toEqual(['GET', 'POST', 'TRACE', 'PUT'])
  })

  it('never includes the response body', async () => {
    const definition = createHttpHeadersDefinition({
      client: {
        async request(url) {
          return {
            status: 200,
            headers: SECURE_HEADERS,
            finalUrl: url,
            redirects: [],
            addresses: ctx.target.addresses,
            body: Buffer.from('SECRET BODY'),
          }
        },
      },
    })
    const result = await definition.execute(
      definition.normalize({ target: 'example.com', path: '/' }),
      ctx
    )
    expect(result.body).toBeUndefined()
    expect(JSON.stringify(result)).not.toContain('SECRET BODY')
  })

  it('normalizes hostnames before execution', () => {
    const definition = createHttpHeadersDefinition({ client: fakeClient({}) })
    const input = definition.normalize({ target: 'https://example.com/x', path: '/y' })
    expect(input.url).toBe('https://example.com/y')
    expect(input.target).toBe('example.com')
    expect(normalizeTarget({ target: 'example.com', path: '/' }).url).toBe('https://example.com/')
  })
})
