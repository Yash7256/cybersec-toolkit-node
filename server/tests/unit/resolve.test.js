import { describe, it, expect, vi, afterEach } from 'vitest'
import { resolveTarget, pinnedLookup } from '../../src/security/resolve.js'
import AppError from '../../src/utils/AppError.js'

const lookupOf = (answers) => vi.fn(async () => answers)
const failing = (code) =>
  vi.fn(async () => {
    const err = new Error('lookup failed')
    err.code = code
    throw err
  })

async function expectCode(promise, code) {
  await expect(promise).rejects.toMatchObject({ name: 'AppError', statusCode: 422, code })
}

afterEach(() => {
  vi.useRealTimers()
})

describe('resolveTarget', () => {
  it('accepts a public hostname and normalizes answers', async () => {
    const lookup = lookupOf([{ address: '93.184.216.34', family: 4 }])
    const result = await resolveTarget('example.com', { kind: 'host', lookup })
    expect(result.host).toBe('example.com')
    expect(result.addresses).toEqual([{ address: '93.184.216.34', family: 4 }])
    expect(lookup).toHaveBeenCalledWith('example.com', { all: true, verbatim: true })
  })

  it('blocks a mixed public+private answer', async () => {
    const lookup = lookupOf([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 },
    ])
    const err = await resolveTarget('evil.example', { kind: 'host', lookup }).catch((e) => e)
    expect(err).toBeInstanceOf(AppError)
    expect(err.code).toBe('TARGET_BLOCKED')
    expect(err.reason).toBe('private')
    expect(err.message).not.toContain('10.0.0.5')
    expect(err.message.toLowerCase()).not.toContain('private')
  })

  it('blocks when every answer is private', async () => {
    await expectCode(
      resolveTarget('internal.example', {
        kind: 'host',
        lookup: lookupOf([{ address: '192.168.1.10', family: 4 }]),
      }),
      'TARGET_BLOCKED'
    )
  })

  it('blocks a CNAME chain that lands on a private address', async () => {
    await expectCode(
      resolveTarget('cdn.example', {
        kind: 'host',
        lookup: lookupOf([{ address: '10.0.0.5', family: 4 }]),
      }),
      'TARGET_BLOCKED'
    )
  })

  it('maps resolver errors to TARGET_UNRESOLVABLE', async () => {
    await expectCode(
      resolveTarget('missing.example', { kind: 'host', lookup: failing('ENOTFOUND') }),
      'TARGET_UNRESOLVABLE'
    )
    await expectCode(
      resolveTarget('missing.example', { kind: 'host', lookup: failing('EAI_AGAIN') }),
      'TARGET_UNRESOLVABLE'
    )
    await expectCode(
      resolveTarget('missing.example', { kind: 'host', lookup: failing('ENODATA') }),
      'TARGET_UNRESOLVABLE'
    )
  })

  it('times out and clears the timer', async () => {
    vi.useFakeTimers()
    const lookup = vi.fn(() => new Promise(() => {}))
    const promise = resolveTarget('slow.example', { kind: 'host', timeoutMs: 100, lookup })
    const assertion = expectCode(promise, 'TARGET_UNRESOLVABLE')
    await vi.advanceTimersByTimeAsync(100)
    await assertion
    expect(vi.getTimerCount()).toBe(0)
  })

  it('caps answers at 16 addresses', async () => {
    const answers = Array.from({ length: 40 }, (_value, index) => ({
      address: `93.184.216.${index + 1}`,
      family: 4,
    }))
    const result = await resolveTarget('many.example', { kind: 'host', lookup: lookupOf(answers) })
    expect(result.addresses).toHaveLength(16)
  })

  it('validates an IP directly and blocks private ones', async () => {
    const result = await resolveTarget('8.8.8.8', { kind: 'ip' })
    expect(result).toEqual({ host: '8.8.8.8', addresses: [{ address: '8.8.8.8', family: 4 }] })
    await expectCode(resolveTarget('127.0.0.1', { kind: 'ip' }), 'TARGET_BLOCKED')
  })

  it('never leaks an address in resolution errors', async () => {
    const err = await resolveTarget('missing.example', {
      kind: 'host',
      lookup: failing('ENOTFOUND'),
    }).catch((e) => e)
    expect(JSON.stringify(err)).not.toMatch(/\d+\.\d+\.\d+\.\d+/)
  })
})

describe('pinnedLookup', () => {
  const call = (lookup, hostname, options) =>
    new Promise((resolve, reject) => {
      lookup(hostname, options, (err, address, family) => {
        if (err) reject(err)
        else resolve(options?.all ? { addresses: address } : { address, family })
      })
    })

  it('returns only validated addresses in all mode', async () => {
    const lookup = pinnedLookup([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:4700:4700::1111', family: 6 },
    ])
    expect(await call(lookup, 'example.com', { all: true })).toEqual({
      addresses: [
        { address: '93.184.216.34', family: 4 },
        { address: '2606:4700:4700::1111', family: 6 },
      ],
    })
  })

  it('filters by family and supports the numeric options form', async () => {
    const lookup = pinnedLookup([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:4700:4700::1111', family: 6 },
    ])
    expect(await call(lookup, 'example.com', 6)).toEqual({
      address: '2606:4700:4700::1111',
      family: 6,
    })
  })

  it('never calls DNS and cannot be rebound', async () => {
    const resolver = vi
      .fn()
      .mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }])
      .mockResolvedValueOnce([{ address: '127.0.0.1', family: 4 }])

    const result = await resolveTarget('rebind.example', { kind: 'host', lookup: resolver })
    const lookup = pinnedLookup(result.addresses)
    expect(await call(lookup, 'rebind.example', { all: true })).toEqual({
      addresses: [{ address: '8.8.8.8', family: 4 }],
    })
    expect(resolver).toHaveBeenCalledTimes(1)
  })

  it('rejects a family with no validated address', async () => {
    const lookup = pinnedLookup([{ address: '93.184.216.34', family: 4 }])
    await expect(call(lookup, 'example.com', { family: 6 })).rejects.toMatchObject({
      code: 'ENOTFOUND',
    })
  })
})
