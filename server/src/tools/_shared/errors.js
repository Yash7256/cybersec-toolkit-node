const FRIENDLY = new Set([
  'Domain not found', 'No records of this type', 'Query timed out',
  'Connection refused', 'Connection timed out', 'Connection reset',
  'TLS handshake failed', 'Host not reachable', 'No TLS service on this port',
  'Target returned an invalid response', 'Too many redirects',
  'Redirect target not allowed', 'Response too large', 'Lookup service unavailable',
  'Not registered', 'Traceroute unavailable', 'Request failed',
])

export class ToolError extends Error {
  constructor(kind = 'internal', message = 'Request failed', cause) {
    super(FRIENDLY.has(message) ? message : 'Request failed')
    this.name = 'ToolError'
    this.kind = kind
    this.cause = cause
  }
}

export function mapNetworkError(err) {
  const code = err?.code
  if (code === 'ECONNREFUSED') return new ToolError('target', 'Connection refused', err)
  if (code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return new ToolError('target', 'Connection timed out', err)
  if (code === 'ECONNRESET') return new ToolError('target', 'Connection reset', err)
  if (String(code).startsWith('ERR_SSL') || code === 'EPROTO') return new ToolError('target', 'TLS handshake failed', err)
  return new ToolError('internal', 'Request failed', err)
}
