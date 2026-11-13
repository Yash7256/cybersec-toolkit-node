import { safeHttp as defaultSafeHttp } from '../../net/safeHttp.js'
import { env as defaultEnv } from '../../config/env.js'

const DEFAULT_MAX_BYTES = 128 * 1024

export const TECH_HEADER_PATTERNS = Object.freeze([
  ['cloudflare', 'Cloudflare'],
  ['openresty', 'OpenResty'],
  ['nginx', 'Nginx'],
  ['apache', 'Apache'],
  ['iis', 'IIS'],
  ['caddy', 'Caddy'],
  ['gunicorn', 'Gunicorn'],
])

export const TECH_COOKIE_PATTERNS = Object.freeze([
  ['phpsessid', 'PHP'],
  ['asp.net_sessionid', 'ASP.NET'],
  ['laravel_session', 'Laravel'],
  ['rails', 'Ruby on Rails'],
])

export const TECH_BODY_PATTERNS = Object.freeze([
  ['wp-content', 'WordPress'],
  ['wp-includes', 'WordPress'],
  ['csrfmiddlewaretoken', 'Django'],
  ['__next', 'Next.js'],
  ['reactroot', 'React'],
  ['data-reactroot', 'React'],
])

export function extractTitle(body) {
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? '')
  const match = text.match(/<title[^>]*>(?:<!\[CDATA\[)?\s*([\s\S]*?)\s*(?:\]\]>)?<\/title>/i)
  if (!match) return null
  let title = match[1]
    .replace(/<[^>]*>/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  title = title.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  return title ? title.slice(0, 200) : null
}

export function detectTechnologies(headers = {}, body = '', serverValue = '') {
  const technologies = []
  const seen = new Set()
  const push = (name) => {
    if (name && !seen.has(name)) {
      seen.add(name)
      technologies.push(name)
    }
  }

  const server = String(serverValue || headers.server || '').toLowerCase()
  for (const [pattern, name] of TECH_HEADER_PATTERNS) {
    if (server.includes(pattern)) push(name)
  }

  if (headers['x-powered-by']) push(String(headers['x-powered-by']).trim())
  if (headers['x-generator']) push(String(headers['x-generator']).trim())

  const cookies = Array.isArray(headers['set-cookie'])
    ? headers['set-cookie'].join(' ')
    : String(headers['set-cookie'] ?? '')
  const cookiesLower = cookies.toLowerCase()
  for (const [pattern, name] of TECH_COOKIE_PATTERNS) {
    if (cookiesLower.includes(pattern)) push(name)
  }

  const bodyLower = (Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? ''))
    .slice(0, 3000)
    .toLowerCase()
  for (const [pattern, name] of TECH_BODY_PATTERNS) {
    if (bodyLower.includes(pattern)) push(name)
  }

  return technologies
}

function headerServer(headers) {
  const value = headers?.server
  return Array.isArray(value) ? value.join(' ') : String(value ?? '')
}

export async function probeSubdomain(hostname, {
  env = defaultEnv,
  http = defaultSafeHttp,
  signal,
  maxBytes = DEFAULT_MAX_BYTES,
} = {}) {
  for (const scheme of ['https', 'http']) {
    if (signal?.aborted) throw new Error('aborted')
    const url = `${scheme}://${hostname}`
    const started = Date.now()
    try {
      const response = await http['request'](url, {
        method: 'GET',
        maxBytes,
        maxRedirects: 5,
        deadlineMs: env.SUBDOMAIN_HTTP_TIMEOUT_MS,
        verifyTls: false,
        signal,
      })
      const server = headerServer(response.headers)
      return {
        alive: true,
        status: response.status,
        server,
        redirect_to: response.finalUrl && response.finalUrl !== url ? response.finalUrl : null,
        response_time_ms: Date.now() - started,
        scheme,
        title: extractTitle(response.body) ?? undefined,
        technologies: detectTechnologies(response.headers, response.body, server),
      }
    } catch {
      continue
    }
  }
  return { alive: false }
}
