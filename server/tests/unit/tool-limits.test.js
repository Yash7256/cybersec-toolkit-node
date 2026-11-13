import { describe, it, expect } from 'vitest'
import { createSemaphore } from '../../src/tools/_shared/limits.js'

describe('tool semaphore', () => {
  it('caps concurrent work at the limit', async () => {
    const semaphore = createSemaphore({ limit: 2 })
    let active = 0
    let max = 0
    const task = async () => {
      const release = await semaphore.acquire()
      active += 1
      max = Math.max(max, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      active -= 1
      release()
    }
    await Promise.all(Array.from({ length: 10 }, task))
    expect(max).toBe(2)
    expect(semaphore.active).toBe(0)
    expect(semaphore.waiting).toBe(0)
  })

  it('releases a waiting task when a slot frees', async () => {
    const semaphore = createSemaphore({ limit: 1 })
    const first = await semaphore.acquire()
    expect(semaphore.active).toBe(1)
    let acquired = false
    const waiting = semaphore.acquire().then((release) => {
      acquired = true
      return release
    })
    await Promise.resolve()
    expect(acquired).toBe(false)
    first()
    const second = await waiting
    expect(acquired).toBe(true)
    second()
    expect(semaphore.active).toBe(0)
  })

  it('rejects invalid limits', () => {
    expect(() => createSemaphore({ limit: 0 })).toThrow()
    expect(() => createSemaphore({ limit: 1.5 })).toThrow()
  })
})
