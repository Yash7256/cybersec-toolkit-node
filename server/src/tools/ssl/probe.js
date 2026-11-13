import tls from 'node:tls'
import { ToolError, mapNetworkError } from '../_shared/errors.js'

export function probe({
  address,
  port,
  servername,
  minVersion,
  maxVersion,
  timeoutMs = 5000,
  signal,
} = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    const socket = tls.connect(
      {
        host: address,
        port,
        servername: servername || undefined,
        rejectUnauthorized: false,
        minVersion,
        maxVersion,
        timeout: timeoutMs,
      },
      () => {
        if (settled) return
        settled = true
        try {
          resolve({
            protocol: socket.getProtocol(),
            cipher: socket.getCipher(),
            cert: socket.getPeerCertificate(true),
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ?? null,
          })
        } finally {
          socket.destroy()
        }
      }
    )

    const fail = (err) => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(err)
    }

    socket.once('error', (err) => {
      if (
        err?.code === 'EPROTO' ||
        err?.code === 'ECONNRESET' ||
        String(err?.code).startsWith('ERR_SSL')
      ) {
        fail(new ToolError('target', 'No TLS service on this port', err))
        return
      }
      fail(mapNetworkError(err))
    })
    socket.once('timeout', () => fail(new ToolError('target', 'Connection timed out')))
    if (signal) {
      signal.addEventListener(
        'abort',
        () => fail(new ToolError('target', 'Connection timed out')),
        { once: true }
      )
    }
  })
}
