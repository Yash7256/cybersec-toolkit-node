import { describe, it, expect, vi } from 'vitest'
import {
  validateTarget,
  validateTargets,
  validateRedirect,
  urlTargetSchema,
} from '../../src/security/targetPolicy.js'

const env = (allow = false) => ({ ALLOW_PRIVATE_TARGETS: allow })
const stub = () =>
  vi.fn(async (value) => ({
    host: value.toLowerCase(),
    addresses: [{ address: '93.184.216.34', family: 4 }],
  }))

async function expectCode(promise, code) {
  await expect(promise).rejects.toMatchObject({ name: 'AppError', statusCode: 422, code })
}

describe('validateTarget', () => {
  it('normalizes the target key for a public host', async () => {
    const resolver = stub()
    const result = await validateTarget('Example.COM', { env: env(false), resolver })
    expect(result).toMatchObject({
      target: 'Example.COM',
      targetKey: 'example.com',
      kind: 'host',
      addresses: [{ address: '93.184.216.34', family: 4 }],
    })
  })

  it('blocks a private IP when private targets are off', async () => {
    await expectCode(validateTarget('127.0.0.1', { env: env(false) }), 'TARGET_BLOCKED')
  })

  it('allows loopback/private targets only when the env flag is on', async () => {
    const result = await validateTarget('127.0.0.1', { env: env(true) })
    expect(result.targetKey).toBe('127.0.0.1')
    await expectCode(validateTarget('0.0.0.0', { env: env(true) }), 'TARGET_BLOCKED')
  })

  it('stores the original target string', async () => {
    const result = await validateTarget('  Example.COM  ', { env: env(false), resolver: stub() })
    expect(result.target).toBe('  Example.COM  ')
  })
})

describe('validateTargets', () => {
  it('rejects lists over 256 entries', async () => {
    await expectCode(
      validateTargets(Array.from({ length: 257 }, () => '8.8.8.8'), { env: env(false) }),
      'TARGET_INVALID'
    )
  })

  it('expands a /24 to 256 classified addresses', async () => {
    const [result] = await validateTargets(['192.168.1.0/24'], { env: env(true) })
    expect(result.kind).toBe('cidr')
    expect(result.targetKey).toBe('192.168.1.0/24')
    expect(result.addresses).toHaveLength(256)
    expect(result.addresses[0]).toEqual({ address: '192.168.1.0', family: 4 })
    expect(result.addresses[255]).toEqual({ address: '192.168.1.255', family: 4 })
  })

  it('rejects /23 before expanding and private CIDRs when private is off', async () => {
    await expectCode(validateTargets(['192.168.0.0/23'], { env: env(true) }), 'TARGET_INVALID')
    await expectCode(validateTargets(['192.168.1.0/24'], { env: env(false) }), 'TARGET_BLOCKED')
  })

  it('rejects IPv6 CIDRs', async () => {
    await expectCode(validateTargets(['2001:db8::/64'], { env: env(true) }), 'TARGET_INVALID')
  })

  it('dedupes by targetKey', async () => {
    const single = await validateTargets(['8.8.8.8', '8.8.8.8'], { env: env(false) })
    expect(single).toHaveLength(1)

    const hosts = await validateTargets(['Example.com', 'example.com'], {
      env: env(false),
      resolver: stub(),
    })
    expect(hosts).toHaveLength(1)
  })

  it('reports the failing index and no address detail', async () => {
    const err = await validateTargets(['8.8.8.8', '127.0.0.1'], { env: env(false) }).catch(
      (e) => e
    )
    expect(err.code).toBe('TARGET_BLOCKED')
    expect(err.index).toBe(1)
    expect(err.message).not.toContain('127.0.0.1')
  })
})

describe('no address leaks in policy errors', () => {
  const blocked = [
    '127.0.0.1',
    '10.0.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '::1',
    'fe80::1',
    '[::1]',
    'fd00::1',
    '100.64.0.1',
    '172.16.0.1',
  ]

  it.each(blocked)('does not leak %s', async (input) => {
    const err = await validateTarget(input, { env: env(false) }).catch((e) => e)
    const serialized = JSON.stringify(err)
    expect(err.message).not.toContain(input)
    expect(serialized).not.toContain(input)
    expect(err.message).not.toMatch(/private|internal|loopback/i)
    expect(serialized).not.toMatch(/private|internal|loopback/i)
  })

  it('does not leak a CIDR', async () => {
    const err = await validateTargets(['192.168.0.0/24'], { env: env(false) }).catch((e) => e)
    expect(JSON.stringify(err)).not.toContain('192.168.0.0/24')
  })
})

describe('urlTargetSchema', () => {
  it.each([
    'ftp://x.com',
    'http://user:pw@x.com',
    'http://x.com@evil.com',
    'http://[::1]/',
    'not a url',
  ])('rejects %s', (input) => {
    expect(urlTargetSchema.safeParse(input).success).toBe(false)
  })

  it('accepts http(s) URLs and returns host and port', () => {
    const result = urlTargetSchema.parse('https://example.com:8443/a?b=c')
    expect(result.host).toBe('example.com')
    expect(result.port).toBe(8443)
    expect(result.url).toBe('https://example.com:8443/a?b=c')
    expect(urlTargetSchema.parse('http://example.com/').port).toBe(80)
  })

  it('accepts public IPv6 URLs', () => {
    const result = urlTargetSchema.parse('https://[2606:4700:4700::1111]/')
    expect(result.port).toBe(443)
    expect(result.host).toContain('2606:4700:4700::1111')
  })
})

describe('validateRedirect', () => {
  it('blocks a redirect to cloud metadata', async () => {
    await expectCode(
      validateRedirect('http://169.254.169.254/latest/meta-data/', 'https://example.com'),
      'TARGET_BLOCKED'
    )
  })

  it('resolves relative redirects through the same policy', async () => {
    const result = await validateRedirect('/next', 'https://example.com/a', { resolver: stub() })
    expect(result.url).toBe('https://example.com/next')
    expect(result.targetKey).toBe('example.com')
  })

  it('rejects credentials and non-http schemes', async () => {
    await expectCode(
      validateRedirect('https://user:pw@example.com/', 'https://example.com'),
      'TARGET_INVALID'
    )
    await expectCode(validateRedirect('ftp://example.com/', 'https://example.com'), 'TARGET_INVALID')
  })
})
