import { describe, it, expect, vi } from 'vitest'
import { normalizeTarget, fetchHeaders, validatePath } from '../../src/tools/httpHeaders/request.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const ctx = { target: { addresses: [{ address: '93.184.216.34', family: 4 }] } }

function response(overrides = {}) {
  return {
    status: 200,
    headers: { 'content-type': 'text/html' },
    finalUrl: 'https://example.com/',
    redirects: [],
    addresses: ctx.target.addresses,
    body: Buffer.alloc(0),
    ...overrides,
  }
}

describe('http headers request layer', () => {
  it('normalizes a hostname to a default https URL', () => {
    const input = normalizeTarget({ target: 'example.com', path: '/' })
    expect(input).toMatchObject({
      target: 'example.com',
      url: 'https://example.com/',
      explicitScheme: false,
    })
  })

  it('keeps an explicit URL scheme and host', () => {
    const input = normalizeTarget({ target: 'http://example.com:8080/x', path: '/status' })
    expect(input.target).toBe('example.com')
    expect(input.url).toBe('http://example.com:8080/status')
    expect(input.explicitScheme).toBe(true)
  })

  it('rejects unsafe paths', () => {
    expect(() => validatePath('//evil.com')).toThrow(ToolError)
    expect(() => validatePath('/a%0d%0ab')).toThrow(ToolError)
    expect(() => validatePath('/a\r\nb')).toThrow(ToolError)
    expect(() => validatePath(`/${'a'.repeat(2048)}`)).toThrow(ToolError)
    expect(validatePath('/ok?q=1')).toBe('/ok?q=1')
  })

  it('falls back from https to http on a connect failure', async () => {
    const calls = []
    const client = {
      async request(url) {
        calls.push(url)
        if (url.startsWith('https://')) throw new ToolError('target', 'Connection refused')
        return response({ finalUrl: url })
      },
    }
    const input = normalizeTarget({ target: 'example.com', path: '/' })
    const result = await fetchHeaders({ input, ctx, client })
    expect(calls).toEqual(['https://example.com/', 'http://example.com/'])
    expect(result.finalUrl).toBe('http://example.com/')
  })

  it('does not fall back when the scheme was explicit', async () => {
    const client = {
      async request() {
        throw new ToolError('target', 'Connection refused')
      },
    }
    const input = normalizeTarget({ target: 'https://example.com', path: '/' })
    await expect(fetchHeaders({ input, ctx, client })).rejects.toThrow('Connection refused')
  })

  it('records the redirect chain', async () => {
    const redirects = [
      { from: 'https://example.com/', to: 'https://www.example.com/', status: 301 },
    ]
    const client = { async request() { return response({ redirects, finalUrl: 'https://www.example.com/' }) } }
    const input = normalizeTarget({ target: 'example.com', path: '/' })
    const result = await fetchHeaders({ input, ctx, client })
    expect(result.redirects).toEqual(redirects)
  })

  it('surfaces a blocked redirect as a friendly target error', async () => {
    const client = {
      async request() {
        throw new ToolError('target', 'Redirect target not allowed')
      },
    }
    const input = normalizeTarget({ target: 'example.com', path: '/' })
    await expect(fetchHeaders({ input, ctx, client })).rejects.toThrow(
      'Redirect target not allowed'
    )
  })

  it('sends headers-only GET requests with TLS verification disabled', async () => {
    const request = vi.fn().mockResolvedValue(response())
    const input = normalizeTarget({ target: 'example.com', path: '/' })
    await fetchHeaders({ input, ctx, client: { request } })
    expect(request).toHaveBeenCalledWith(
      'https://example.com/',
      expect.objectContaining({
        mode: 'user',
        headersOnly: true,
        method: 'GET',
        verifyTls: false,
        maxRedirects: 5,
        addresses: ctx.target.addresses,
      })
    )
  })
})
