import { describe, it, expect } from 'vitest'
import { limitFor, nextResetAt, utcDate } from '../../src/config/limits.js'

const env = { FREE_DAILY_LIMIT: 5, PAID_DAILY_LIMIT: 100 }

describe('limitFor', () => {
  it('gives FREE users the free daily limit', () => {
    expect(limitFor({ tier: 'FREE', role: 'USER' }, env)).toBe(5)
  })

  it('gives PAID users the paid daily limit', () => {
    expect(limitFor({ tier: 'PAID', role: 'USER' }, env)).toBe(100)
  })

  it('gives ADMIN unlimited', () => {
    expect(limitFor({ tier: 'FREE', role: 'ADMIN' }, env)).toBe(Infinity)
    expect(limitFor({ tier: 'PAID', role: 'ADMIN' }, env)).toBe(Infinity)
  })
})

describe('nextResetAt', () => {
  it('returns the next UTC midnight', () => {
    expect(nextResetAt(new Date('2026-11-11T23:59:59Z'))).toBe('2026-11-12T00:00:00.000Z')
  })

  it('handles month end', () => {
    expect(nextResetAt(new Date('2026-01-31T12:00:00Z'))).toBe('2026-02-01T00:00:00.000Z')
  })

  it('handles leap day', () => {
    expect(nextResetAt(new Date('2028-02-28T10:00:00Z'))).toBe('2028-02-29T00:00:00.000Z')
  })

  it('handles year end', () => {
    expect(nextResetAt(new Date('2026-12-31T23:00:00Z'))).toBe('2027-01-01T00:00:00.000Z')
  })

  it('uses the current time by default', () => {
    expect(new Date(nextResetAt()).toISOString()).toBe(nextResetAt())
  })
})

describe('utcDate', () => {
  it('returns YYYY-MM-DD in UTC', () => {
    expect(utcDate(new Date('2026-11-11T23:59:59Z'))).toBe('2026-11-11')
    expect(utcDate(new Date('2026-11-12T00:00:00Z'))).toBe('2026-11-12')
  })
})
