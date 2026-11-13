import { Agent, request as undiciRequest } from 'undici'
import { normalizeHost } from '../security/hostPolicy.js'
import { resolveTarget, pinnedLookup } from '../security/resolve.js'
import { validateRedirect } from '../security/targetPolicy.js'
import { ToolError, mapNetworkError } from '../tools/_shared/errors.js'
import { env as defaultEnv } from '../config/env.js'

const CONNECT_TIMEOUT_MS = 5000
const HEADERS_TIMEOUT_MS = 8000
const BODY_TIMEOUT_MS = 8000
const MAX_HEADER_SIZE = 32 * 1024

function headerMap(raw) {
  const out = {}
  for (const [key, value] of Object.entries(raw ?? {})) {
    out[key.toLowerCase()] = Array.isArray(value) ? value : String(value)
  }
  return out
}

function makeAgent(addresses, { servername, verifyTls }) {
  return new Agent({
    connect: {
      lookup: pinnedLookup(addresses),
      servername,
      rejectUnauthorized: verifyTls,
      timeout: CONNECT_TIMEOUT_MS,
    },
  })
}

function isAbort(err) {
  return err?.name === 'AbortError' || err?.code === 'ABORT_ERR'
}

export function createSafeHttp({ policy, resolver = resolveTarget, env = defaultEnv } = {}) {
  const validate =
    policy ??
    (async (host) => {
      const normalized = normalizeHost(host)
      return resolver(normalized.value, {
        kind: normalized.kind,
        timeoutMs: env.DNS_TIMEOUT_MS,
      })
    })

  async function request(input, options = {}) {
    let current = String(input)
    let pinned = options.addresses
    const redirects = []
    const maxRedirects = options.maxRedirects ?? 5
    const startedAt = Date.now()

    for (let hop = 0; ; hop += 1) {
      let parsed
      try {
        parsed = new URL(current)
      } catch {
        throw new ToolError('target', 'Target returned an invalid response')
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new ToolError('target', 'Redirect target not allowed')
      }

      const trusted = options.mode === 'trusted'
      if (trusted) {
        if (parsed.protocol !== 'https:') {
          throw new ToolError('upstream', 'Lookup service unavailable')
        }
        const allowed = (options.allowHosts ?? []).map((host) => host.toLowerCase())
        if (!allowed.includes(parsed.hostname.toLowerCase())) {
          throw new ToolError('upstream', 'Lookup service unavailable')
        }
      }

      let resolved
      if (pinned) {
        resolved = { host: parsed.hostname, addresses: pinned }
      } else {
        try {
          resolved = await validate(parsed.hostname)
        } catch (err) {
          if (err instanceof ToolError) throw err
          if (trusted) throw new ToolError('upstream', 'Lookup service unavailable', err)
          throw err
        }
      }

      const controller = new AbortController()
      const deadline = setTimeout(
        () => controller.abort(),
        options.deadlineMs ?? 8000
      )
      const agent = makeAgent(resolved.addresses, {
        servername: parsed.hostname,
        verifyTls: options.verifyTls ?? true,
      })

      try {
        const response = await undiciRequest(current, {
          dispatcher: agent,
          method: options.method ?? 'GET',
          headers: {
            'user-agent': options.userAgent ?? env.HTTP_USER_AGENT,
            ...(options.body !== undefined ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
            ...(options.headers ?? {}),
          },
          signal: controller.signal,
          maxRedirections: 0,
          ...(options.body !== undefined ? { body: options.body } : {}),
          headersTimeout: HEADERS_TIMEOUT_MS,
          bodyTimeout: BODY_TIMEOUT_MS,
          maxHeaderSize: MAX_HEADER_SIZE,
        })

        const headers = headerMap(response.headers)
        let bytes = 0
        let body = Buffer.alloc(0)

        if (options.headersOnly) {
          await response.body.dump()
        } else {
          const chunks = []
          for await (const chunk of response.body) {
            bytes += chunk.length
            if (bytes > (options.maxBytes ?? 1024 * 1024)) {
              controller.abort()
              throw new ToolError('target', 'Response too large')
            }
            chunks.push(chunk)
          }
          body = Buffer.concat(chunks)
        }

        const location = headers.location
        if (location && options.followRedirects === false && response.statusCode >= 300 && response.statusCode < 400) {
          return {
            status: response.statusCode,
            headers,
            finalUrl: current,
            redirects,
            addresses: resolved.addresses,
            bytes,
            body,
            elapsedMs: Date.now() - startedAt,
          }
        }
        if (location && response.statusCode >= 300 && response.statusCode < 400) {
          if (hop >= maxRedirects) throw new ToolError('target', 'Too many redirects')
          let next
          try {
            next = new URL(location, current).toString()
          } catch {
            throw new ToolError('target', 'Redirect target not allowed')
          }
          if (
            parsed.protocol === 'https:' &&
            new URL(next).protocol === 'http:' &&
            !options.allowDowngrade
          ) {
            throw new ToolError('target', 'Redirect target not allowed')
          }
          if (trusted) {
            const allowed = (options.allowHosts ?? []).map((host) => host.toLowerCase())
            const nextUrl = new URL(next)
            if (
              nextUrl.protocol !== 'https:' ||
              !allowed.includes(nextUrl.hostname.toLowerCase())
            ) {
              throw new ToolError('upstream', 'Lookup service unavailable')
            }
          } else {
            try {
              await validateRedirect(location, current, { env, resolver })
            } catch {
              throw new ToolError('target', 'Redirect target not allowed')
            }
          }
          redirects.push({ from: current, to: next, status: response.statusCode })
          current = next
          pinned = undefined
          continue
        }

        return {
          status: response.statusCode,
          headers,
          finalUrl: current,
          redirects,
          addresses: resolved.addresses,
          bytes,
          body,
          elapsedMs: Date.now() - startedAt,
        }
      } catch (err) {
        if (err instanceof ToolError) throw err
        if (isAbort(err)) throw new ToolError('target', 'Connection timed out')
        throw mapNetworkError(err)
      } finally {
        clearTimeout(deadline)
        await agent.close().catch(() => {})
      }
    }
  }

  return { request }
}

export const safeHttp = createSafeHttp()
