import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createBreaker } from '../../src/net/circuitBreaker.js'
import { ToolError } from '../../src/tools/_shared/errors.js'

const fail = () => Promise.reject(new ToolError('upstream', 'Lookup service unavailable'))

describe('circuit breaker', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  })
  afterEach(() => vi.useRealTimers())

  it('opens after the failure threshold inside the window', async () => {
    const breaker = createBreaker({ name: 'test', failureThreshold: 3, windowMs: 1000, openMs: 5000 })
    for (let index = 0; index < 3; index += 1) {
      await expect(breaker.exec(fail)).rejects.toThrow('Lookup service unavailable')
    }
    const fn = vi.fn().mockResolvedValue('ok')
    await expect(breaker.exec(fn)).rejects.toMatchObject({ kind: 'upstream' })
    expect(fn).not.toHaveBeenCalled()
  })

  it('does not open when failures fall outside the window', async () => {
    const breaker = createBreaker({ name: 'test', failureThreshold: 2, windowMs: 1000, openMs: 5000 })
    await expect(breaker.exec(fail)).rejects.toThrow()
    vi.advanceTimersByTime(1500)
    await expect(breaker.exec(fail)).rejects.toThrow()
    await expect(breaker.exec(() => Promise.resolve('ok'))).resolves.toBe('ok')
  })

  it('closes after a successful half-open probe', async () => {
    const breaker = createBreaker({ name: 'test', failureThreshold: 1, windowMs: 1000, openMs: 5000 })
    await expect(breaker.exec(fail)).rejects.toThrow()
    vi.advanceTimersByTime(5001)
    await expect(breaker.exec(() => Promise.resolve('ok'))).resolves.toBe('ok')
    await expect(breaker.exec(() => Promise.resolve('again'))).resolves.toBe('again')
  })

  it('re-opens when the half-open probe fails', async () => {
    const breaker = createBreaker({ name: 'test', failureThreshold: 1, windowMs: 1000, openMs: 5000 })
    await expect(breaker.exec(fail)).rejects.toThrow()
    vi.advanceTimersByTime(5001)
    await expect(breaker.exec(fail)).rejects.toThrow()
    const fn = vi.fn().mockResolvedValue('ok')
    await expect(breaker.exec(fn)).rejects.toMatchObject({ kind: 'upstream' })
    expect(fn).not.toHaveBeenCalled()
  })
})
