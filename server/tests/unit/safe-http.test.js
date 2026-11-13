import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import { createSafeHttp } from '../../src/net/safeHttp.js'
import { resolveTarget } from '../../src/security/resolve.js'

let server
let base

const stubLookup = async () => [{ address: '127.0.0.1', family: 4 }]

function permissiveResolver(counter) {
  return async (value, opts = {}) => {
    if (counter) counter.count += 1
    if (value === 'app.test') {
      return { host: value, addresses: [{ address: '127.0.0.1', family: 4 }] }
    }
    return resolveTarget(value, { ...opts, lookup: stubLookup })
  }
}

function client({ resolver = permissiveResolver(), policy } = {}) {
  return createSafeHttp({
    resolver,
    policy:
      policy ??
      (async (host) => ({
        host,
        addresses: [{ address: '127.0.0.1', family: 4 }],
      })),
  })
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://app.test')
    if (url.pathname === '/ok') {
      res.writeHead(200, { 'X-Test': 'yes', 'Set-Cookie': ['a=1', 'b=2'] })
      res.end('hello')
      return
    }
    if (url.pathname === '/large') {
      res.writeHead(200)
      res.end('x'.repeat(4096))
      return
    }
    if (url.pathname === '/slow') {
      // Never write headers.
      return
    }
    if (url.pathname === '/rel') {
      res.writeHead(302, { Location: '/final' })
      res.end()
      return
    }
    if (url.pathname === '/final') {
      res.writeHead(200)
      res.end('done')
      return
    }
    if (url.pathname === '/metadata') {
      res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data' })
      res.end()
      return
    }
    if (url.pathname === '/loopback') {
      res.writeHead(302, { Location: 'http://evil.test/' })
      res.end()
      return
    }
    const redirect = /^\/chain\/(\d+)$/.exec(url.pathname)
    if (redirect) {
      const n = Number(redirect[1])
      if (n === 0) {
        res.writeHead(200)
        res.end('end')
      } else {
        res.writeHead(302, { Location: `/chain/${n - 1}` })
        res.end()
      }
      return
    }
    res.writeHead(404)
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://app.test:${server.address().port}`
})

afterAll(() => new Promise((resolve) => server.close(resolve)))

describe('safeHttp', () => {
  it('returns headers-only responses without buffering the body', async () => {
    const result = await client().request(`${base}/ok`, { headersOnly: true })
    expect(result.status).toBe(200)
    expect(result.headers['x-test']).toBe('yes')
    expect(result.headers['set-cookie']).toEqual(['a=1', 'b=2'])
    expect(result.body.length).toBe(0)
  })

  it('enforces the body cap', async () => {
    await expect(
      client().request(`${base}/large`, { maxBytes: 16 })
    ).rejects.toMatchObject({ message: 'Response too large' })
  })

  it('times out a server that never sends headers', async () => {
    await expect(
      client().request(`${base}/slow`, { deadlineMs: 300 })
    ).rejects.toMatchObject({ message: 'Connection timed out' })
  })

  it('allows a five-hop redirect chain and rejects a sixth', async () => {
    const five = await client().request(`${base}/chain/5`)
    expect(five.status).toBe(200)
    expect(five.redirects).toHaveLength(5)

    await expect(client().request(`${base}/chain/6`)).rejects.toMatchObject({
      message: 'Too many redirects',
    })
  })

  it('rejects a redirect to the metadata address', async () => {
    await expect(client().request(`${base}/metadata`)).rejects.toMatchObject({
      message: 'Redirect target not allowed',
    })
  })

  it('rejects a redirect to a hostname that resolves to loopback', async () => {
    await expect(client().request(`${base}/loopback`)).rejects.toMatchObject({
      message: 'Redirect target not allowed',
    })
  })

  it('resolves relative redirects against the current URL', async () => {
    const result = await client().request(`${base}/rel`)
    expect(result.finalUrl).toBe(`${base}/final`)
    expect(result.redirects).toEqual([
      { from: `${base}/rel`, to: `${base}/final`, status: 302 },
    ])
  })

  it('resolves the host exactly once per request', async () => {
    const counter = { count: 0 }
    const safe = createSafeHttp({ resolver: permissiveResolver(counter) })
    await safe.request(`${base}/ok`)
    expect(counter.count).toBe(1)
  })

  it('trusted mode rejects hosts outside the allow-list', async () => {
    await expect(
      client().request(`${base}/ok`, { mode: 'trusted', allowHosts: ['allowed.test'] })
    ).rejects.toMatchObject({ message: 'Lookup service unavailable' })
  })

  it('trusted mode only allows https', async () => {
    await expect(
      client().request(`${base}/ok`, { mode: 'trusted', allowHosts: ['app.test'] })
    ).rejects.toMatchObject({ message: 'Lookup service unavailable' })
  })

  it('the strict default policy blocks a loopback target', async () => {
    const strict = createSafeHttp()
    await expect(
      strict.request(`http://127.0.0.1:${server.address().port}/ok`)
    ).rejects.toThrow()
  })
})
