import { tryConnect } from '../connect.js'
import { socketSemaphore as defaultSemaphore } from '../sockets.js'

export function readSome(socket, { maxBytes = 1024, timeoutMs = 2000, signal } = {}) {
  return new Promise((resolve) => {
    const chunks = []
    let size = 0
    let settled = false

    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', finish)
      socket.removeListener('data', onData)
      socket.removeListener('end', finish)
      socket.removeListener('close', finish)
      socket.removeListener('error', finish)
      resolve(Buffer.concat(chunks, size))
    }

    const onData = (chunk) => {
      const room = maxBytes - size
      if (room <= 0) return finish()
      const slice = chunk.length > room ? chunk.subarray(0, room) : chunk
      chunks.push(slice)
      size += slice.length
      if (size >= maxBytes) return finish()
      // Returns the first application-level response chunk, matching the old
      // asyncio reader.read() behavior for these small interactive probes.
      finish()
    }

    const timer = setTimeout(finish, timeoutMs)
    timer.unref?.()
    if (signal?.aborted) return finish()
    signal?.addEventListener('abort', finish, { once: true })

    socket.on('data', onData)
    socket.once('end', finish)
    socket.once('close', finish)
    socket.once('error', finish)
  })
}

export async function withProbeSocket(
  { address, family, port, timeoutMs, signal, tls = false, servername, deps = {} },
  fn
) {
  const semaphore = deps.sockets ?? defaultSemaphore
  const connect = deps.connect ?? tryConnect
  const release = await semaphore.acquire(signal)
  let socket = null
  try {
    const result = await connect({ address, family, port, tls, servername, timeoutMs, signal })
    if (result.state !== 'open' || !result.socket) return null
    socket = result.socket
    return await fn(socket)
  } catch {
    return null
  } finally {
    if (socket) {
      try {
        socket.destroy()
      } catch {}
    }
    release()
  }
}

export function writeText(socket, text) {
  try {
    socket.write(text)
    return true
  } catch {
    return false
  }
}
