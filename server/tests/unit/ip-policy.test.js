import { describe, it, expect } from 'vitest'
import { classifyIp } from '../../src/security/ipPolicy.js'

const allowed = [
  '8.8.8.8',
  '1.1.1.1',
  '9.9.9.9',
  '4.4.4.4',
  '9.255.255.255',
  '11.0.0.0',
  '126.255.255.255',
  '128.0.0.0',
  '169.253.255.255',
  '169.255.0.0',
  '172.15.255.255',
  '172.32.0.0',
  '191.255.255.255',
  '192.0.1.0',
  '192.167.255.255',
  '192.169.0.0',
  '193.0.0.1',
  '100.63.255.255',
  '100.128.0.0',
  '198.20.0.0',
  '198.51.99.1',
  '198.51.101.1',
  '203.0.114.1',
  '223.255.255.255',
  '2606:4700:4700::1111',
  '2001:4860:4860::8888',
  '2001:4860:4860::8844',
  '2a00:1450:4001:81b::200e',
  '2a03:2880:f10c:83:face:b00c:0:25de',
  '2400:cb00::1',
  '2a00:1::1',
  '::ffff:8.8.8.8',
  '::ffff:0:8.8.8.8',
  '64:ff9b::808:808',
  '2002:808:808::',
]

const blocked = [
  ['10.0.0.0', 'private'],
  ['10.0.0.1', 'private'],
  ['10.255.255.255', 'private'],
  ['172.16.0.0', 'private'],
  ['172.16.0.1', 'private'],
  ['172.31.255.255', 'private'],
  ['100.64.0.0', 'cgnat'],
  ['100.64.0.1', 'cgnat'],
  ['100.100.100.200', 'cgnat'],
  ['100.127.255.255', 'cgnat'],
  ['192.168.0.1', 'private'],
  ['192.168.255.255', 'private'],
  ['169.254.0.1', 'link_local'],
  ['169.254.169.254', 'metadata'],
  ['169.254.170.2', 'link_local'],
  ['0.0.0.0', 'unspecified'],
  ['0.1.2.3', 'unspecified'],
  ['127.0.0.1', 'loopback'],
  ['127.255.255.255', 'loopback'],
  ['224.0.0.1', 'multicast'],
  ['239.255.255.255', 'multicast'],
  ['240.0.0.0', 'reserved'],
  ['240.0.0.1', 'reserved'],
  ['255.255.255.255', 'reserved'],
  ['198.18.0.1', 'reserved'],
  ['198.19.255.255', 'reserved'],
  ['192.0.0.1', 'reserved'],
  ['192.0.0.255', 'reserved'],
  ['192.0.2.1', 'documentation'],
  ['192.88.99.1', 'reserved'],
  ['198.51.100.1', 'documentation'],
  ['203.0.113.1', 'documentation'],
  ['::', 'unspecified'],
  ['::1', 'loopback'],
  ['fe80::1', 'link_local'],
  ['fe80::a9fe:a9fe', 'link_local'],
  ['febf::1', 'link_local'],
  ['fc00::1', 'private'],
  ['fd00::1', 'private'],
  ['fd12:3456::1', 'private'],
  ['fd00:ec2::254', 'metadata'],
  ['ff02::1', 'multicast'],
  ['ff05::1', 'multicast'],
  ['2001:db8::1', 'documentation'],
  ['2001:db8:ffff::1', 'documentation'],
  ['3fff::1', 'documentation'],
  ['2001::1', 'reserved'],
  ['2001:10::1', 'reserved'],
  ['64:ff9b:1::1', 'translation'],
  ['100::1', 'reserved'],
  ['fec0::1', 'reserved'],
  ['::ffff:127.0.0.1', 'loopback'],
  ['::ffff:7f00:1', 'loopback'],
  ['::ffff:169.254.169.254', 'metadata'],
  ['::ffff:10.0.0.1', 'private'],
  ['::ffff:192.168.1.1', 'private'],
  ['::ffff:100.64.0.1', 'cgnat'],
  ['::127.0.0.1', 'malformed'],
  ['64:ff9b::7f00:1', 'loopback'],
  ['64:ff9b::a00:1', 'private'],
  ['64:ff9b::a9fe:a9fe', 'metadata'],
  ['2002:7f00:1::', 'loopback'],
  ['2002:a9fe:a9fe::', 'metadata'],
  ['2002:c0a8:101::', 'private'],
  ['0:0:0:0:0:ffff:7f00:1', 'loopback'],
  ['::ffff:0:7f00:1', 'loopback'],
  ['::ffff:0:a00:1', 'private'],
]

const malformed = [
  '',
  ' ',
  ' 8.8.8.8',
  '8.8.8.8 ',
  '8.8.8.8\n',
  '\t8.8.8.8',
  'fe80::1%eth0',
  '::1%lo',
  '1.2.3',
  '256.1.1.1',
  '1.2.3.4.5',
  '1.2.3.4.5.6',
  '1.2.3.4/24',
  '[8.8.8.8]',
  'localhost',
  '0x7f.0.0.1',
  '2130706433',
  '1'.repeat(300),
  null,
  undefined,
  123,
  {},
  true,
]

describe('classifyIp allowed addresses', () => {
  it.each(allowed)('allows %s', (input) => {
    const result = classifyIp(input)
    expect(result.allowed).toBe(true)
    expect(result.reason).toBeNull()
    expect([4, 6]).toContain(result.family)
    expect(result.normalized).toBeTruthy()
  })
})

describe('classifyIp blocked addresses', () => {
  it.each(blocked)('blocks %s (%s)', (input, reason) => {
    const result = classifyIp(input)
    expect(result.allowed).toBe(false)
    expect(result.reason).toBe(reason)
    if (result.reason !== 'malformed') expect(result.normalized).toBeTruthy()
  })
})

describe('classifyIp malformed input', () => {
  it.each(malformed)('rejects %s', (input) => {
    const result = classifyIp(input)
    expect(result.allowed).toBe(false)
    expect(result.reason).toBe('malformed')
    expect(result.normalized).toBeNull()
    expect(result.family).toBeNull()
  })
})
