import net from 'node:net'
import tls from 'node:tls'

function defaultConnect({ address, family, port, tls: useTls, servername }) {
  if (useTls) {
    return tls.connect({
      host: address,
      port,
      family,
      servername: servername || undefined,
      rejectUnauthorized: false,
      enableTrace: false,
    })
  }
  return net.connect({ host: address, port, family })
}

function stateForError(err, timedOut) {
  if (timedOut) return 'filtered'
  const code = err?.code
  if (code === 'ECONNREFUSED') return 'closed'
  return 'filtered'
}

export function tryConnect({
  address,
  family,
  port,
  tls: useTls = false,
  servername,
  timeoutMs = 2000,
  signal,
  connectImpl = defaultConnect,
} = {}) {
  return new Promise((resolve) => {
    let settled = false
    let timedOut = false
    let socket = null
    const startedAt = Date.now()

    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      if (!socket) return
      socket.removeListener('connect', onConnect)
      socket.removeListener('secureConnect', onConnect)
      socket.removeListener('error', onError)
      socket.removeListener('timeout', onTimeout)
    }

    const settle = (state, err = null) => {
      if (settled) return
      settled = true
      cleanup()

      if (state === 'open' && socket && !socket.destroyed) {
        socket.setTimeout?.(0)
        // Keep one inert listener so a late error cannot crash the process
        // before the caller attaches its own probe listeners.
        socket.on('error', () => {})
        resolve({ state, socket, latencyMs: Date.now() - startedAt })
        return
      }

      if (socket && !socket.destroyed) socket.destroy()
      socket?.removeAllListeners?.()
      resolve({ state, latched: err?.code ?? null, latencyMs: Date.now() - startedAt })
    }

    const timer = setTimeout(() => {
      timedOut = true
      settle('filtered')
    }, timeoutMs)
    timer.unref?.()

    const onAbort = () => settle('filtered')

    const onConnect = () => settle('open')
    const onTimeout = () => {
      timedOut = true
      settle('filtered')
    }
    const onError = (err) => settle(stateForError(err, timedOut), err)

    if (signal?.aborted) {
      clearTimeout(timer)
      resolve({ state: 'filtered', latched: 'ABORT_ERR', latencyMs: 0 })
      return
    }
    signal?.addEventListener('abort', onAbort, { once: true })

    try {
      socket = connectImpl({ address, family, port, tls: useTls, servername })
    } catch (err) {
      settle(stateForError(err, false), err)
      return
    }

    socket.once(useTls ? 'secureConnect' : 'connect', onConnect)
    socket.once('error', onError)
    socket.once('timeout', onTimeout)
  })
}
