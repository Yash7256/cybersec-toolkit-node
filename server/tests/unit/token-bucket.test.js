import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { TokenBucket } from '../../src/security/tokenBucket.js'

describe('TokenBucket', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(0)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('allows a full burst immediately, then paces at the exact rate', async () => {
    const bucket = new TokenBucket({ ratePerSec: 10, burst: 2 })

    await bucket.take()
    await bucket.take()

    let thirdResolved = false
    bucket.take().then(() => {
      thirdResolved = true
    })

    await vi.advanceTimersByTimeAsync(99)
    expect(thirdResolved).toBe(false)

    await vi.advanceTimersByTimeAsync(1)
    expect(thirdResolved).toBe(true)
  })

  it('never exceeds burst capacity', async () => {
    const bucket = new TokenBucket({ ratePerSec: 1, burst: 3 })
    let resolved = 0

    for (let i = 0; i < 3; i += 1) {
      bucket.take().then(() => {
        resolved += 1
      })
    }
    bucket.take().then(() => {
      resolved += 1
    })

    await vi.advanceTimersByTimeAsync(0)
    expect(resolved).toBe(3)

    await vi.advanceTimersByTimeAsync(500)
    expect(resolved).toBe(3)

    await vi.advanceTimersByTimeAsync(500)
    expect(resolved).toBe(4)
  })

  it('rejects a request larger than burst', async () => {
    const bucket = new TokenBucket({ ratePerSec: 1, burst: 2 })
    await expect(bucket.take(3)).rejects.toThrow(/exceeds burst/)
  })

  it('rejects non-positive and non-numeric amounts', async () => {
    const bucket = new TokenBucket({ ratePerSec: 1, burst: 2 })
    await expect(bucket.take(0)).rejects.toThrow(/positive amount/)
    await expect(bucket.take(-1)).rejects.toThrow(/positive amount/)
    await expect(bucket.take('1')).rejects.toThrow(/positive amount/)
  })

  it('serves concurrent waiters FIFO', async () => {
    const bucket = new TokenBucket({ ratePerSec: 1, burst: 1 })
    const order = []

    await bucket.take()
    bucket.take().then(() => order.push('B'))
    bucket.take().then(() => order.push('C'))

    await vi.advanceTimersByTimeAsync(1000)
    expect(order).toEqual(['B'])

    await vi.advanceTimersByTimeAsync(1000)
    expect(order).toEqual(['B', 'C'])
  })
})
