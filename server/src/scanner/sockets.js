import { env as defaultEnv } from '../config/env.js'
import { metrics } from '../observability/metrics.js'

function abortError(signal) {
  const error = new Error('The operation was aborted')
  error.name = 'AbortError'
  error.code = 'ABORT_ERR'
  if (signal?.reason !== undefined) error.cause = signal.reason
  return error
}

export function createSocketSemaphore({
  max = defaultEnv.SCAN_GLOBAL_MAX_SOCKETS,
  onGauge = (count) => metrics.setScanSocketsInUse(count),
} = {}) {
  if (!(max > 0)) throw new Error('socket semaphore requires max > 0')

  let active = 0
  const waiters = []

  function publish() {
    try {
      onGauge(active)
    } catch {}
  }

  function release() {
    if (active <= 0) return
    active -= 1
    const next = waiters.shift()
    if (next) {
      active += 1
      next.settle()
    }
    publish()
  }

  function acquire(signal) {
    if (signal?.aborted) return Promise.reject(abortError(signal))

    return new Promise((resolve, reject) => {
      let settled = false

      const onAbort = () => {
        if (settled) return
        const index = waiters.indexOf(waiter)
        if (index !== -1) waiters.splice(index, 1)
        settled = true
        signal.removeEventListener('abort', onAbort)
        reject(abortError(signal))
      }

      const waiter = {
        settle() {
          if (settled) return
          settled = true
          signal?.removeEventListener('abort', onAbort)
          resolve(release)
        },
      }

      if (active < max) {
        active += 1
        publish()
        waiter.settle()
        return
      }

      waiters.push(waiter)
      signal?.addEventListener('abort', onAbort, { once: true })
    })
  }

  return {
    acquire,
    release,
    get active() {
      return active
    },
    get max() {
      return max
    },
    get waiting() {
      return waiters.length
    },
  }
}

export const socketSemaphore = createSocketSemaphore()
