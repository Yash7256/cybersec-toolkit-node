import { safeHttp as defaultSafeHttp } from '../../net/safeHttp.js'
import { env as defaultEnv } from '../../config/env.js'

export function withQuery(url, params) {
  const next = new URL(url)
  for (const [key, value] of Object.entries(params)) next.searchParams.set(key, value)
  return next.toString()
}

export function encodeForm(data) {
  const body = new URLSearchParams()
  for (const [key, value] of Object.entries(data)) body.set(key, value)
  return body.toString()
}

export function createWebClient({
  http = defaultSafeHttp,
  env = defaultEnv,
  signal,
  verifyTls = false,
} = {}) {
  async function request(url, {
    method = 'GET',
    headers = {},
    body,
    followRedirects = true,
    maxBytes = env.WEBAPP_MAX_RESPONSE_BYTES,
    deadlineMs = env.WEBAPP_REQUEST_TIMEOUT_MS,
  } = {}) {
    const response = await http['request'](url, {
      method,
      headers,
      body,
      followRedirects,
      maxRedirects: 5,
      maxBytes,
      deadlineMs,
      verifyTls,
      signal,
    })
    return {
      url,
      finalUrl: response.finalUrl,
      status: response.status,
      headers: response.headers ?? {},
      body: response.body,
      text: response.body?.toString('utf8') ?? '',
    }
  }

  return { request }
}
