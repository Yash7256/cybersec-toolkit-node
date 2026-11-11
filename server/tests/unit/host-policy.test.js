import { describe, it, expect } from 'vitest'
import { normalizeHost } from '../../src/security/hostPolicy.js'
import AppError from '../../src/utils/AppError.js'

function expectCode(input, code) {
  try {
    normalizeHost(input)
  } catch (err) {
    expect(err).toBeInstanceOf(AppError)
    expect(err.statusCode).toBe(422)
    expect(err.code).toBe(code)
    return
  }
  throw new Error(`expected ${String(input)} to be rejected`)
}

describe('normalizeHost accepted values', () => {
  it('lowercases and strips one trailing dot', () => {
    expect(normalizeHost('Example.COM')).toEqual({ kind: 'host', value: 'example.com' })
    expect(normalizeHost('example.com.')).toEqual({ kind: 'host', value: 'example.com' })
    expect(normalizeHost('sub.example.co.uk')).toEqual({
      kind: 'host',
      value: 'sub.example.co.uk',
    })
  })

  it('keeps IDN and punycode hosts', () => {
    expect(normalizeHost('münchen.de')).toEqual({ kind: 'host', value: 'xn--mnchen-3ya.de' })
    expect(normalizeHost('xn--bcher-kva.example')).toEqual({
      kind: 'host',
      value: 'xn--bcher-kva.example',
    })
  })

  it('returns canonical IPs as kind ip', () => {
    expect(normalizeHost('8.8.8.8')).toEqual({ kind: 'ip', value: '8.8.8.8' })
    expect(normalizeHost('[2606:4700:4700::1111]')).toEqual({
      kind: 'ip',
      value: '2606:4700:4700::1111',
    })
  })

  it('tolerates surrounding spaces', () => {
    expect(normalizeHost('  example.com  ')).toEqual({ kind: 'host', value: 'example.com' })
  })
})

describe('normalizeHost ambiguous numeric forms', () => {
  const inputs = [
    '2130706433',
    '0x7f000001',
    '0x7f.0.0.1',
    '0177.0.0.1',
    '127.1',
    '1.2.3',
    '017700000001',
    '1.2.3.4.5',
    '256.1.1.1',
    '１２７.０.０.１',
  ]

  it.each(inputs)('rejects %s as ambiguous', (input) => {
    expectCode(input, 'TARGET_AMBIGUOUS')
  })
})

describe('normalizeHost invalid values', () => {
  const longLabel = `${'a'.repeat(64)}.com`
  const longHost = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`

  const inputs = [
    'user@evil.com',
    'http://example.com',
    'example.com/path',
    'example.com\\path',
    'example.com:80',
    'exa mple.com',
    'example.com\n',
    'exa\0mple.com',
    'a..b.com',
    '.example.com',
    '-bad.com',
    'bad-.com',
    'foo_bar.com',
    'example.com?x',
    'example.com#x',
    '[::1]:80',
    '[not-ip]',
    '[2606:4700:4700::1111]extra',
    '%65xample.com',
    longLabel,
    longHost,
    '',
    '   ',
    null,
    undefined,
    123,
  ]

  it.each(inputs)('rejects %s as invalid', (input) => {
    expectCode(input, 'TARGET_INVALID')
  })
})

describe('normalizeHost blocked names', () => {
  const inputs = [
    'localhost',
    'LOCALHOST.',
    'ⓛocalhost',
    'foo.localhost',
    'printer.local',
    'db.internal',
    'intranet',
    'foo',
    'x.home.arpa',
    'foo.lan',
    'foo.localdomain',
    'foo.corp',
    'foo.intranet',
  ]

  it.each(inputs)('rejects %s as blocked', (input) => {
    expectCode(input, 'TARGET_BLOCKED')
  })
})
