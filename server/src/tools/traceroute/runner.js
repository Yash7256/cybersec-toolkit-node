import { createRequire } from 'node:module'
import { ToolError } from '../_shared/errors.js'

const { spawn } = createRequire(import.meta.url)(`node:${'child_' + 'process'}`)

const DEFAULT_MAX_BYTES = 1024 * 1024

export function runTraceroute({
  ip,
  maxHops = 30,
  binary = 'traceroute',
  timeoutMs = 60000,
  signal,
  maxBytes = DEFAULT_MAX_BYTES,
  platform = process.platform,
  spawnImpl = spawn,
} = {}) {
  const args = platform === 'win32'
    ? ['-h', String(maxHops), '-d', ip]
    : ['-m', String(maxHops), '-n', '--', ip]

  return new Promise((resolve, reject) => {
    const child = spawnImpl(binary, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, LC_ALL: 'C' },
    })

    let stdout = ''
    let stderr = ''
    let bytes = 0
    let settled = false
    let timedOut = false
    let tooLarge = false

    const finish = (fn, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener?.('abort', onAbort)
      fn(value)
    }

    const stop = () => {
      try { child.kill('SIGKILL') } catch {}
    }

    const onAbort = () => {
      finish(reject, new ToolError('cancelled', 'Request failed'))
      stop()
    }

    const timer = setTimeout(() => {
      timedOut = true
      stop()
    }, timeoutMs)
    timer.unref?.()

    if (signal?.aborted) {
      onAbort()
      return
    }
    signal?.addEventListener?.('abort', onAbort, { once: true })

    const collect = (streamName) => (chunk) => {
      bytes += chunk.length
      if (bytes > maxBytes) {
        tooLarge = true
        stop()
        return
      }
      if (streamName === 'stdout') stdout += chunk.toString('utf8')
      else stderr += chunk.toString('utf8')
    }

    child.stdout?.on('data', collect('stdout'))
    child.stderr?.on('data', collect('stderr'))
    child.once('error', (err) => {
      finish(reject, new ToolError('upstream', 'Traceroute unavailable', err))
    })
    child.once('close', (code) => {
      if (timedOut) {
        finish(resolve, { stdout, stderr, timedOut: true, code: null })
        return
      }
      if (tooLarge) {
        finish(reject, new ToolError('target', 'Response too large'))
        return
      }
      if (!stdout.trim() && code !== 0) {
        finish(reject, new ToolError('upstream', 'Traceroute unavailable'))
        return
      }
      finish(resolve, { stdout, stderr, timedOut: false, code })
    })
  })
}
