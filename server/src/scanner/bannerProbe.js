import {
  MAX_BANNER_BYTES,
  SSH_PORTS,
  WELCOME_PORTS,
  isHttpProbePort,
  probeTimeoutFor,
} from './constants.js'
import { fromBytes, fromHttpResponse } from './banners.js'
import { detectTechnologies } from './techDetect.js'
import { parseHttpResponse, parseSshBanner } from './serviceVersion.js'
import { sanitizeBanner } from './sanitize.js'

const HOST_RE = /^[a-z0-9.-]{1,253}$/

export function safeHostHeader(hostname, address) {
  const value = String(hostname ?? '').toLowerCase()
  if (HOST_RE.test(value)) return value
  return String(address ?? '')
}

export function versionFromBanner(port, raw, http) {
  if (!raw || raw.length === 0) return null
  if (http) return parseHttpResponse(raw)
  if (SSH_PORTS.has(port)) return parseSshBanner(raw)
  return null
}

function readSocket(socket, { maxBytes, timeoutMs, untilHeaders = false, signal }) {
  return new Promise((resolve) => {
    const chunks = []
    let size = 0
    let settled = false

    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
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
      if (untilHeaders) {
        const text = Buffer.concat(chunks, size).toString('latin1')
        if (text.includes('\r\n\r\n') || text.includes('\n\n')) return finish()
        return
      }
      // Passive protocols send one welcome line; return the first chunk like
      // asyncio's reader.read() did.
      finish()
    }

    const onAbort = () => finish()
    const timer = setTimeout(finish, timeoutMs)
    timer.unref?.()

    if (signal?.aborted) return finish()
    signal?.addEventListener('abort', onAbort, { once: true })

    socket.on('data', onData)
    socket.once('end', finish)
    socket.once('close', finish)
    socket.once('error', finish)
  })
}

export async function probeBanner({
  socket,
  port,
  address,
  hostname,
  timeoutMs = 2000,
  maxBytes = MAX_BANNER_BYTES,
  signal,
} = {}) {
  if (!socket) {
    return {
      raw_banner: null,
      welcome_message: null,
      server_response: null,
      version: null,
      technologies: [],
    }
  }

  const http = isHttpProbePort(port)
  const passiveTimeout = WELCOME_PORTS.has(port)
    ? probeTimeoutFor(port, timeoutMs)
    : Math.min(probeTimeoutFor(port, timeoutMs), 1500)

  try {
    if (http) {
      const host = safeHostHeader(hostname, address)
      const request =
        `GET / HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: CyberSec-PortScanner/1.0\r\n` +
        `Connection: close\r\n\r\n`
      try {
        socket.write(request)
      } catch {}

      const raw = await readSocket(socket, {
        maxBytes,
        timeoutMs: passiveTimeout,
        untilHeaders: true,
        signal,
      })
      const banner = fromHttpResponse(raw, { maxBytes })
      const technologies = detectTechnologies(banner.raw_banner, {
        extraText: banner.server_response,
      })
      return { ...banner, version: versionFromBanner(port, raw, true), technologies }
    }

    const raw = await readSocket(socket, {
      maxBytes,
      timeoutMs: passiveTimeout,
      untilHeaders: false,
      signal,
    })
    const banner = fromBytes(raw, { maxBytes })
    const technologies = detectTechnologies(raw, { extraText: banner.server_response })
    return { ...banner, version: versionFromBanner(port, raw, false), technologies }
  } finally {
    try {
      socket.destroy()
    } catch {}
  }
}

export function rawBannerText(value) {
  return sanitizeBanner(value)
}
