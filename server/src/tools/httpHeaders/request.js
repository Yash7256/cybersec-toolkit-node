import { safeHttp } from '../../net/safeHttp.js'
import { ToolError } from '../_shared/errors.js'

const CONTROL_CHARS = /[\u0000-\u0020\u007f]|%0[ad]/i
const RETRIABLE = new Set(['Connection refused', 'Connection timed out', 'Host not reachable'])

export function validatePath(path) {
  if (typeof path !== 'string' || path.length > 2048) {
    throw new ToolError('target', 'Target returned an invalid response')
  }
  if (!path.startsWith('/') || path.startsWith('//') || CONTROL_CHARS.test(path)) {
    throw new ToolError('target', 'Target returned an invalid response')
  }
  return path
}

export function normalizeTarget(input) {
  const path = validatePath(input.path ?? '/')
  const raw = input.target.trim()
  const explicitScheme = /^https?:\/\//i.test(raw)
  let parsed
  try {
    parsed = explicitScheme ? new URL(raw) : new URL(`https://${raw}`)
  } catch {
    throw new ToolError('target', 'Target returned an invalid response')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new ToolError('target', 'Target returned an invalid response')
  }
  const host = parsed.hostname
  const origin = `${parsed.protocol}//${parsed.host}`
  return {
    ...input,
    target: host,
    path,
    url: `${origin}${path}`,
    explicitScheme,
  }
}

export async function fetchHeaders({ input, ctx, client = safeHttp } = {}) {
  const attempts = input.explicitScheme
    ? [input.url]
    : [input.url, `http://${new URL(input.url).host}${input.path}`]

  let lastError
  for (const url of attempts) {
    try {
      return await client.request(url, {
        mode: 'user',
        addresses: ctx.target.addresses,
        headersOnly: true,
        method: 'GET',
        verifyTls: false,
        maxRedirects: 5,
        headers: { 'accept-encoding': 'gzip, br' },
      })
    } catch (err) {
      lastError = err
      const retriable =
        !input.explicitScheme && err instanceof ToolError && RETRIABLE.has(err.message)
      if (!retriable) throw err
    }
  }
  throw lastError
}
