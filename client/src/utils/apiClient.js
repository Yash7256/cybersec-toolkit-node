/**
 * Centralised API client for the CyberSec frontend.
 *
 * Every outgoing request automatically attaches the Clerk bearer token when
 * the user is signed in. Anonymous requests are sent without the header so
 * backend optional-auth routes continue to work unchanged.
 *
 * Usage inside a React component:
 *   const { getToken } = useAuth()
 *   const data = await apiPost('/api/tools/dns', { target: 'example.com' }, getToken)
 *
 * Requirements: 8.1–8.5
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

/**
 * Build headers, attaching Authorization: Bearer <token> when a token is available.
 *
 * @param {Function|null} getToken - Clerk's getToken function from useAuth(), or null.
 * @param {Object} extra - Any additional headers to merge.
 * @returns {Promise<Headers>}
 */
async function buildHeaders(getToken, extra = {}) {
  const headers = new Headers({ 'Content-Type': 'application/json', ...extra })

  if (typeof getToken === 'function') {
    try {
      const token = await getToken()
      if (token) {
        headers.set('Authorization', `Bearer ${token}`)
      }
    } catch {
      // getToken() may throw if Clerk is not initialised, offline (ClerkOfflineError
      // in Core 3), or called during SSR — treat as anonymous in all cases.
    }
  }

  return headers
}

/**
 * Dispatch a global event to signal the tier limit was reached.
 * UpgradeModal listens for this.
 */
function dispatchLimitReached() {
  window.dispatchEvent(new CustomEvent('tier:limit_reached'));
}

/**
 * Check if a response is a 429 daily-limit-reached and dispatch the event.
 */
function checkRateLimit(response) {
  if (response.status === 429) {
    response.clone().json().then((body) => {
      if (body?.detail?.code === 'daily_limit_reached') {
        dispatchLimitReached();
      }
    }).catch(() => {});
  }
}

/**
 * Handle a 401 response: attempt a single token refresh, then retry.
 * If the retry also 401s AND signOut was provided, sign the user out and
 * redirect to '/'.  When signOut is null (e.g. TierContext polling /api/user/me),
 * just return null so the caller can handle gracefully without a redirect loop.
 *
 * @param {Function} requestFn - Zero-arg async function that performs the original request.
 * @param {Function|null} getToken - Clerk's getToken function.
 * @param {Function|null} signOut - Clerk's signOut function (from useClerk or useAuth).
 * @returns {Promise<Response|null>}
 */
async function handleUnauthorized(requestFn, getToken, signOut) {
  if (typeof getToken !== 'function') return null

  // Force-refresh the Clerk token cache
  let freshToken = null
  try {
    freshToken = await getToken({ skipCache: true })
  } catch {
    // token refresh failed (ClerkOfflineError or similar)
  }

  if (!freshToken) {
    // Only redirect/sign-out if the caller explicitly provided signOut,
    // meaning it wants session-expiry behaviour (not a background poll).
    if (typeof signOut === 'function') {
      await signOut()
      window.location.href = '/'
    }
    return null
  }

  // Retry once with the fresh token
  const retryResponse = await requestFn(freshToken)
  if (retryResponse.status === 401) {
    if (typeof signOut === 'function') {
      await signOut()
      window.location.href = '/'
    }
    return null
  }

  return retryResponse
}

/**
 * POST to a backend API path with JSON body.
 *
 * @param {string} path - API path, e.g. '/api/tools/dns'
 * @param {Object} body - JSON-serialisable request body.
 * @param {Function|null} getToken - Clerk's getToken function from useAuth().
 * @param {Function|null} signOut - Clerk's signOut function (optional; needed for auto sign-out on 401).
 * @returns {Promise<Response>}
 */
export async function apiPost(path, body, getToken = null, signOut = null) {
  const idempotencyKey = typeof globalThis.crypto?.randomUUID === 'function'
    ? globalThis.crypto.randomUUID().replaceAll('-', '')
    : `${Date.now()}${Math.random().toString(36).slice(2)}`
  const makeRequest = async (token) => {
    const headers = await buildHeaders(token ? () => Promise.resolve(token) : getToken, {
      'Idempotency-Key': idempotencyKey.slice(0, 64),
    })
    return fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })
  }

  const response = await makeRequest(null)

  checkRateLimit(response)

  if (response.status === 401) {
    return handleUnauthorized(makeRequest, getToken, signOut) ?? response
  }

  return response
}

export async function apiPostAndPoll(path, body, getToken = null, { signal, onProgress } = {}) {
  const response = await apiPost(path, body, getToken)
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) return { response, payload, data: null }
  if (response.status !== 202 || !payload.runId) return { response, payload, data: payload.data ?? payload }

  for (;;) {
    if (signal?.aborted) throw new DOMException('The request was aborted.', 'AbortError')
    const runResponse = await apiGet(`/api/runs/${payload.runId}`, null, getToken)
    const run = await runResponse.json().catch(() => ({}))
    onProgress?.(run.progressPct ?? 0, run)
    if (!['QUEUED', 'RUNNING'].includes(run.status)) {
      if (run.status !== 'COMPLETED') return { response: runResponse, payload: run, data: null }
      return { response: runResponse, payload: run, data: run.data }
    }
    await new Promise((resolve, reject) => {
      const timer = window.setTimeout(resolve, run.pollAfterMs ?? 1500)
      signal?.addEventListener('abort', () => {
        window.clearTimeout(timer)
        reject(new DOMException('The request was aborted.', 'AbortError'))
      }, { once: true })
    })
  }
}

/**
 * GET a backend API path with optional query params.
 *
 * @param {string} path - API path, e.g. '/api/tools/geoip'
 * @param {Object|null} params - Query string parameters (key/value pairs).
 * @param {Function|null} getToken - Clerk's getToken function from useAuth().
 * @param {Function|null} signOut - Clerk's signOut function (optional).
 * @returns {Promise<Response>}
 */
export async function apiGet(path, params = null, getToken = null, signOut = null, { signal } = {}) {
  const url = new URL(`${BASE_URL}${path}`, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== null && v !== undefined) url.searchParams.set(k, String(v))
    })
  }

  const makeRequest = async (token) => {
    const headers = await buildHeaders(token ? () => Promise.resolve(token) : getToken)
    return fetch(url.toString(), { method: 'GET', headers, signal })
  }

  const response = await makeRequest(null)

  checkRateLimit(response)

  if (response.status === 401) {
    return handleUnauthorized(makeRequest, getToken, signOut) ?? response
  }

  return response
}

/**
 * Open a fetch-based SSE stream with a POST request, attaching the Clerk token
 * via the Authorization header.
 *
 * Using fetch() instead of EventSource allows us to send the JWT in a header
 * rather than a query parameter (which would expose it in server logs, browser
 * history, and HTTP Referer headers).
 *
 * Returns a ReadableStreamDefaultReader over the raw SSE byte stream.
 * Callers are responsible for parsing SSE frames (split on '\n\n', strip 'data: ').
 *
 * @param {string} path - SSE endpoint path.
 * @param {Object|null} body - JSON body for the POST request.
 * @param {Function|null} getToken - Clerk's getToken function from useAuth().
 * @param {AbortSignal|null} signal - Optional AbortSignal to cancel the stream.
 * @returns {Promise<ReadableStreamDefaultReader>}
 */
export async function apiStream(path, body = null, getToken = null, signal = null) {
  const headers = await buildHeaders(getToken, {})

  const response = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
    signal,
  })

  if (!response.ok) {
    throw new Error(`Stream request failed: HTTP ${response.status}`)
  }

  if (!response.body) {
    throw new Error('Streaming is not supported in this browser.')
  }

  return response.body.getReader()
}
