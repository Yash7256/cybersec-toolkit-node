import { describe, it, expect } from 'vitest'
import { performance } from 'node:perf_hooks'
import { parsePorts, portsSchema } from '../../src/security/ports.js'

const rejects = (input) => expect(() => parsePorts(input)).toThrow()

describe('parsePorts valid forms', () => {
  it('parses strings, ranges and arrays', () => {
    expect(parsePorts('22,80,443,8000-8100')).toEqual([
      22,
      80,
      443,
      ...Array.from({ length: 101 }, (_value, index) => 8000 + index),
    ])
    expect(parsePorts([22, '80', '8000-8002'])).toEqual([22, 80, 8000, 8001, 8002])
    expect(parsePorts(' 22 , 80 ')).toEqual([22, 80])
  })

  it('collapses duplicates and overlaps', () => {
    expect(parsePorts('22,22,20-25')).toEqual([20, 21, 22, 23, 24, 25])
    expect(parsePorts(['1-5', '3-7'])).toEqual([1, 2, 3, 4, 5, 6, 7])
  })

  it('accepts exact span and total limits', () => {
    expect(parsePorts('1-5000')).toHaveLength(5000)
    expect(parsePorts('1-5000,5001-10000')).toHaveLength(10000)
    expect(parsePorts('1-5000,5001-10000')[9999]).toBe(10000)
  })

  it('accepts 1000 entries and rejects 1001', () => {
    const thousand = Array.from({ length: 1000 }, (_value, index) => String(index + 1))
    expect(parsePorts(thousand)).toHaveLength(1000)
    rejects([...thousand, '1001'])
  })
})

describe('parsePorts rejections', () => {
  it.each([
    '0',
    '65536',
    '-1',
    '1.5',
    '1e3',
    '0x10',
    '+22',
    '08',
    '00',
    '022',
    '22,,80',
    '22,',
    '100-50',
    '1-65535',
    '1-5001',
    '1-5000,5001-10001',
    '1 - 2',
    '1-2-3',
    '',
    [],
    [22.5],
    [-1],
    [0],
    [65536],
    [true],
    [null],
  ])('rejects %s', (input) => {
    rejects(input)
  })

  it('rejects an oversized list without expanding it', () => {
    const started = performance.now()
    rejects('1-65535')
    expect(performance.now() - started).toBeLessThan(5)
  })
})

describe('portsSchema', () => {
  it('transforms valid input to a sorted unique list', () => {
    expect(portsSchema.parse('80,22,22')).toEqual([22, 80])
  })

  it('rejects invalid input', () => {
    expect(portsSchema.safeParse('1-65535').success).toBe(false)
    expect(portsSchema.safeParse(22).success).toBe(false)
    expect(portsSchema.safeParse([]).success).toBe(false)
  })
})
