import { definition as sslDefinition } from '../ssl/index.js'
import {
  SECURITY_HEADERS, SENSITIVE_FILES, ADMIN_PATHS, EVIL_ORIGIN, EXTERNAL_SENTINEL,
  CRITICAL, HIGH, MEDIUM, LOW, INFO,
} from './constants.js'
import { vulnerability, baseDomain } from './result.js'

export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length)
  let index = 0
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (index < items.length) {
      const current = index
      index += 1
      results[current] = await fn(items[current], current)
    }
  })
  await Promise.all(workers)
  return results
}

function headerValues(headers, name) {
  const value = headers[name.toLowerCase()]
  if (Array.isArray(value)) return value.map(String)
  return value == null ? [] : [String(value)]
}

export async function checkHeaders(url, { client }) {
  const vulnerabilities = []
  try {
    const response = await client.request(url)
    const headers = response.headers
    for (const [header, [severity, description]] of Object.entries(SECURITY_HEADERS)) {
      if (!(header.toLowerCase() in headers)) {
        vulnerabilities.push(vulnerability({
          vulnType: 'MISSING_HEADER',
          severity,
          url,
          parameter: header,
          evidence: `'${header}' not set. ${description}.`,
          recommendation: `Add '${header}' to all HTTP responses.`,
          category: 'headers',
        }))
      }
    }

    const csp = String(headers['content-security-policy'] ?? '')
    if (csp) {
      if (csp.includes('unsafe-inline') && csp.includes('unsafe-eval')) {
        vulnerabilities.push(vulnerability({
          vulnType: 'WEAK_CSP',
          severity: MEDIUM,
          url,
          parameter: 'Content-Security-Policy',
          evidence: "CSP contains both 'unsafe-inline' and 'unsafe-eval' - effectively neutralises XSS protection.",
          recommendation: "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes instead.",
          category: 'headers',
        }))
      } else if (csp.includes('unsafe-inline')) {
        vulnerabilities.push(vulnerability({
          vulnType: 'WEAK_CSP',
          severity: LOW,
          url,
          parameter: 'Content-Security-Policy',
          evidence: "CSP contains 'unsafe-inline', weakening XSS protection.",
          recommendation: "Replace 'unsafe-inline' with nonce-based or hash-based CSP directives.",
          category: 'headers',
        }))
      }
    }

    const hsts = String(headers['strict-transport-security'] ?? '')
    if (hsts) {
      const match = /max-age=(\d+)/i.exec(hsts)
      const maxAge = match ? Number(match[1]) : 0
      if (maxAge < 31536000) {
        vulnerabilities.push(vulnerability({
          vulnType: 'WEAK_HSTS',
          severity: LOW,
          url,
          parameter: 'Strict-Transport-Security',
          evidence: `HSTS max-age is ${maxAge}s (< 1 year).`,
          recommendation: 'Set HSTS max-age to at least 31536000 (1 year); add includeSubDomains and preload.',
          category: 'headers',
        }))
      }
    }

    for (const leaky of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
      const value = headers[leaky]
      if (value) {
        vulnerabilities.push(vulnerability({
          vulnType: 'INFO_DISCLOSURE',
          severity: LOW,
          url,
          parameter: leaky,
          evidence: `${leaky}: ${Array.isArray(value) ? value.join(', ') : value}`,
          recommendation: `Remove or genericise the '${leaky}' header to reduce fingerprinting.`,
          category: 'headers',
        }))
      }
    }

    for (const rawCookie of headerValues(headers, 'set-cookie')) {
      if (!rawCookie) continue
      const lower = rawCookie.toLowerCase()
      const issues = []
      if (!lower.includes('httponly')) issues.push('missing HttpOnly')
      if (!lower.includes('secure')) issues.push('missing Secure')
      if (!lower.includes('samesite')) issues.push('missing SameSite')
      if (issues.length > 0) {
        vulnerabilities.push(vulnerability({
          vulnType: 'INSECURE_COOKIE',
          severity: MEDIUM,
          url,
          parameter: rawCookie.split('=', 1)[0].trim(),
          evidence: `Cookie flags missing: ${issues.join(', ')}.`,
          recommendation: 'Set HttpOnly, Secure, and SameSite=Strict/Lax on session cookies.',
          category: 'headers',
        }))
      }
    }

    if (url.startsWith('http://')) {
      vulnerabilities.push(vulnerability({
        vulnType: 'PLAINTEXT_HTTP',
        severity: HIGH,
        url,
        evidence: 'Site served over unencrypted HTTP.',
        recommendation: 'Redirect all HTTP traffic to HTTPS and deploy a valid TLS certificate.',
        category: 'headers',
      }))
    }

    const cache = String(headers['cache-control'] ?? '')
    if ((!cache || (!cache.includes('no-store') && !cache.includes('private')))
      && response.status === 200
      && ['/admin', '/account', '/profile', '/dashboard', '/login'].some((keyword) => url.toLowerCase().includes(keyword))) {
      vulnerabilities.push(vulnerability({
        vulnType: 'CACHEABLE_SENSITIVE_PAGE',
        severity: LOW,
        url,
        parameter: 'Cache-Control',
        evidence: `Cache-Control: ${cache || '(not set)'} - sensitive page may be cached.`,
        recommendation: "Add 'Cache-Control: no-store, private' to authenticated/sensitive responses.",
        category: 'headers',
      }))
    }
  } catch (err) {
    vulnerabilities.push(vulnerability({
      vulnType: 'REQUEST_FAILED',
      severity: INFO,
      url,
      evidence: String(err?.message ?? 'Request failed').slice(0, 200),
      recommendation: 'Verify the site is reachable.',
      category: 'headers',
    }))
  }
  return vulnerabilities
}

export async function checkHttpMethods(url, { client }) {
  const vulnerabilities = []
  let allow = ''
  try {
    const response = await client.request(url, { method: 'OPTIONS', followRedirects: false })
    allow = String(response.headers.allow ?? response.headers.Allow ?? '')
  } catch {
    return vulnerabilities
  }
  const methods = allow.split(',').map((method) => method.trim().toUpperCase()).filter(Boolean)

  if (methods.includes('TRACE')) {
    vulnerabilities.push(vulnerability({
      vulnType: 'HTTP_TRACE_ENABLED',
      severity: MEDIUM,
      url,
      parameter: 'Allow',
      evidence: `TRACE method enabled (Allow: ${allow}).`,
      recommendation: 'Disable TRACE method on the web server to prevent Cross-Site Tracing (XST).',
      category: 'access-control',
    }))
  }
  for (const dangerous of ['PUT', 'DELETE', 'PATCH']) {
    if (!methods.includes(dangerous)) continue
    vulnerabilities.push(vulnerability({
      vulnType: 'DANGEROUS_HTTP_METHOD',
      severity: MEDIUM,
      url,
      parameter: 'Allow',
      evidence: `Method ${dangerous} is permitted (Allow: ${allow}).`,
      recommendation: `Disable ${dangerous} unless required by a REST API; restrict to authenticated users.`,
      category: 'access-control',
    }))
  }

  try {
    const response = await client.request(url, { method: 'TRACE', followRedirects: false })
    if (response.status === 200 && response.text.toUpperCase().includes('TRACE')
      && !vulnerabilities.some((item) => item.vuln_type === 'HTTP_TRACE_ENABLED')) {
      vulnerabilities.push(vulnerability({
        vulnType: 'HTTP_TRACE_ENABLED',
        severity: MEDIUM,
        url,
        evidence: 'TRACE request returned HTTP 200 with request echo.',
        recommendation: 'Disable TRACE method on the web server.',
        category: 'access-control',
      }))
    }
  } catch {}
  return vulnerabilities
}

export async function checkCors(url, { client }) {
  const vulnerabilities = []
  for (const method of ['GET', 'OPTIONS']) {
    let response
    try {
      response = await client.request(url, {
        method,
        headers: { origin: EVIL_ORIGIN },
        followRedirects: method === 'OPTIONS' ? false : true,
      })
    } catch {
      continue
    }
    const allowOrigin = String(response.headers['access-control-allow-origin'] ?? '')
    const allowCredentials = String(response.headers['access-control-allow-credentials'] ?? '').toLowerCase()
    if (!allowOrigin) continue

    if (allowOrigin === '*' && allowCredentials === 'true') {
      vulnerabilities.push(vulnerability({
        vulnType: 'CORS_WILDCARD_WITH_CREDENTIALS',
        severity: CRITICAL,
        url,
        parameter: 'Access-Control-Allow-Origin',
        evidence: `Wildcard ACAO with Allow-Credentials: true (method=${method}).`,
        recommendation: 'Never combine ACAO: * with Allow-Credentials: true.',
        category: 'cors',
      }))
      break
    }
    if (allowOrigin === '*') {
      vulnerabilities.push(vulnerability({
        vulnType: 'CORS_WILDCARD',
        severity: MEDIUM,
        url,
        parameter: 'Access-Control-Allow-Origin',
        evidence: `ACAO: * (method=${method}).`,
        recommendation: 'Restrict ACAO to an explicit allowlist of trusted origins.',
        category: 'cors',
      }))
      break
    }
    if (allowOrigin === EVIL_ORIGIN) {
      vulnerabilities.push(vulnerability({
        vulnType: 'CORS_REFLECTED_ORIGIN',
        severity: allowCredentials === 'true' ? CRITICAL : HIGH,
        url,
        parameter: 'Access-Control-Allow-Origin',
        evidence: `Server reflects arbitrary origin '${EVIL_ORIGIN}'. Credentials: ${allowCredentials} (method=${method}).`,
        recommendation: 'Do not dynamically echo the Origin header; use an explicit allowlist.',
        category: 'cors',
      }))
      break
    }
  }
  return vulnerabilities
}

export async function checkExposedFiles(baseUrl, { client, env, signal }) {
  const highRisk = new Set(['.env', '.git/config', '.git/HEAD', 'wp-config.php', 'config.php', 'configuration.php'])

  const results = await mapLimit(SENSITIVE_FILES, env.WEBAPP_CHECK_CONCURRENCY, async (path) => {
    if (signal?.aborted) return null
    const url = `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
    try {
      const response = await client.request(url, { followRedirects: false })
      if (response.status === 200) {
        const preview = response.text.slice(0, 100).replace(/\n/g, ' ').trim()
        return vulnerability({
          vulnType: 'EXPOSED_FILE',
          severity: highRisk.has(path) ? HIGH : MEDIUM,
          url,
          parameter: path,
          evidence: preview ? `HTTP 200 - preview: '${preview}'` : 'HTTP 200',
          recommendation: `Deny public access to '${path}' via server config or firewall.`,
          category: 'access-control',
        })
      }
      if ([301, 302].includes(response.status)) {
        return vulnerability({
          vulnType: 'EXPOSED_FILE',
          severity: LOW,
          url,
          parameter: path,
          evidence: `HTTP ${response.status} redirect - resource may be accessible.`,
          recommendation: `Verify '${path}' is not reachable after redirect.`,
          category: 'access-control',
        })
      }
    } catch {}
    return null
  })
  return results.filter(Boolean)
}

export async function checkAdminPanels(baseUrl, { client, env, signal }) {
  const results = await mapLimit(ADMIN_PATHS, env.WEBAPP_CHECK_CONCURRENCY, async (path) => {
    if (signal?.aborted) return null
    const url = `${baseUrl.replace(/\/+$/, '')}${path}`
    try {
      const response = await client.request(url)
      if (response.status === 200) {
        const body = response.text.toLowerCase()
        const isLogin = ['password', 'username', 'login', 'sign in', 'email', 'user'].some((keyword) => body.includes(keyword))
        return vulnerability({
          vulnType: 'ADMIN_PANEL_EXPOSED',
          severity: isLogin ? HIGH : MEDIUM,
          url,
          parameter: path,
          evidence: `Admin/login panel accessible without authentication. ${isLogin ? 'Login form detected.' : 'Page returned 200.'}`,
          recommendation: 'Restrict access via IP allowlist, VPN, or multi-factor authentication.',
          category: 'access-control',
        })
      }
      if (response.status === 403) {
        return vulnerability({
          vulnType: 'ADMIN_PANEL_FORBIDDEN',
          severity: LOW,
          url,
          parameter: path,
          evidence: 'Admin path exists but returns 403 - may be bypassed.',
          recommendation: 'Verify access controls cannot be bypassed (path traversal, case-sensitivity, etc.).',
          category: 'access-control',
        })
      }
    } catch {}
    return null
  })
  return results.filter(Boolean)
}

export function checkDirectoryListing(pages) {
  const pattern = /<title>\s*index of|<h1>\s*index of|directory listing for \/|parent directory.*last modified/i
  const vulnerabilities = []
  for (const page of pages) {
    if (!pattern.test(page.body_snippet ?? '')) continue
    vulnerabilities.push(vulnerability({
      vulnType: 'DIRECTORY_LISTING',
      severity: HIGH,
      url: page.url,
      evidence: 'Server returns an auto-generated directory index.',
      recommendation: 'Disable directory listing in server config (Options -Indexes for Apache; autoindex off for nginx).',
      category: 'access-control',
    }))
  }
  return vulnerabilities
}

export async function checkOpenRedirect(baseUrl, { client }) {
  const params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'redir', 'destination', 'goto', 'continue']
  for (const param of params) {
    const url = `${baseUrl.replace(/\/+$/, '')}/?${param}=${encodeURIComponent(EXTERNAL_SENTINEL)}`
    try {
      const response = await client.request(url, { followRedirects: false })
      const location = String(response.headers.location ?? '')
      if ([301, 302, 303, 307, 308].includes(response.status) && location.includes('example.com')) {
        return [vulnerability({
          vulnType: 'OPEN_REDIRECT',
          severity: MEDIUM,
          url,
          parameter: param,
          evidence: `HTTP ${response.status} Location: ${location}`,
          recommendation: `Validate redirect targets against an explicit allowlist; reject '${param}' pointing off-domain.`,
          category: 'injection',
        })]
      }
    } catch {}
  }
  return []
}

export async function checkRobots(baseUrl, { client }) {
  const robotsUrl = `${baseUrl.replace(/\/+$/, '')}/robots.txt`
  try {
    const response = await client.request(robotsUrl)
    if (response.status !== 200) return []
    const disallowed = [...response.text.matchAll(/disallow:\s*(\/\S+)/gi)].map((match) => match[1])
    const sensitive = disallowed.filter((path) => (
      ['admin', 'config', 'backup', 'private', 'secret', 'internal', 'staging', 'test', 'debug', 'phpmyadmin']
        .some((keyword) => path.toLowerCase().includes(keyword))
    ))
    if (sensitive.length === 0) return []
    return [vulnerability({
      vulnType: 'ROBOTS_SENSITIVE_PATHS',
      severity: INFO,
      url: robotsUrl,
      evidence: `robots.txt disallows potentially sensitive paths: ${sensitive.slice(0, 5).join(', ')}`,
      recommendation: 'Do not rely on robots.txt to protect sensitive content; use proper authentication/authorisation.',
      category: 'access-control',
    })]
  } catch {
    return []
  }
}

export async function checkTls(baseUrl, { env, target, signal, sslAudit = sslDefinition.execute.bind(sslDefinition) }) {
  let parsed
  try {
    parsed = new URL(baseUrl)
  } catch {
    return []
  }
  if (parsed.protocol !== 'https:') return []
  const host = parsed.hostname
  const port = Number(parsed.port || 443)
  const vulnerabilities = []

  let result
  try {
    result = await sslAudit(
      { host, port },
      { target, signal, env }
    )
  } catch (err) {
    return [vulnerability({
      vulnType: 'TLS_AUDIT_FAILED',
      severity: INFO,
      url: baseUrl,
      evidence: String(err?.message ?? 'TLS audit failed').slice(0, 200),
      recommendation: 'Verify TLS is properly configured.',
      category: 'tls',
    })]
  }

  if (result.error) {
    return [vulnerability({
      vulnType: 'TLS_ERROR',
      severity: MEDIUM,
      url: baseUrl,
      evidence: result.error,
      recommendation: 'Review and fix TLS configuration.',
      category: 'tls',
    })]
  }

  if (result.is_expired) {
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_CERT_EXPIRED',
      severity: CRITICAL,
      url: baseUrl,
      evidence: `Certificate expired. Days remaining: ${result.days_remaining}`,
      recommendation: 'Renew the TLS certificate immediately.',
      category: 'tls',
    }))
  } else if (result.days_remaining > 0 && result.days_remaining < 30) {
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_CERT_EXPIRING_SOON',
      severity: MEDIUM,
      url: baseUrl,
      evidence: `Certificate expires in ${result.days_remaining} day(s).`,
      recommendation: 'Renew the TLS certificate before it expires.',
      category: 'tls',
    }))
  }

  if (result.is_self_signed) {
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_SELF_SIGNED',
      severity: HIGH,
      url: baseUrl,
      evidence: 'Certificate is self-signed and not trusted by browsers.',
      recommendation: "Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt).",
      category: 'tls',
    }))
  }
  if (result.supports_tls12 === false) {
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_NO_TLS12',
      severity: HIGH,
      url: baseUrl,
      evidence: 'Server does not support TLS 1.2.',
      recommendation: 'Enable TLS 1.2 and TLS 1.3; disable TLS 1.0/1.1 and SSL.',
      category: 'tls',
    }))
  }
  if (['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(result.tls_version)) {
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_WEAK_VERSION',
      severity: HIGH,
      url: baseUrl,
      evidence: `Server negotiated deprecated protocol: ${result.tls_version}`,
      recommendation: 'Disable TLS 1.0, TLS 1.1, SSLv3, and SSLv2; require TLS 1.2+.',
      category: 'tls',
    }))
  }
  if (result.cipher_suite) {
    const weak = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5', 'anon']
    if (weak.some((marker) => String(result.cipher_suite).toUpperCase().includes(marker.toUpperCase()))) {
      vulnerabilities.push(vulnerability({
        vulnType: 'TLS_WEAK_CIPHER',
        severity: HIGH,
        url: baseUrl,
        evidence: `Weak cipher suite negotiated: ${result.cipher_suite}`,
        recommendation: 'Disable weak ciphers (RC4, DES, 3DES, EXPORT, NULL, MD5); prefer ECDHE+AES-GCM.',
        category: 'tls',
      }))
    }
  }
  if (result.certificate && result.hostname_matches === false) {
    const cn = result.certificate.subject?.commonName ?? ''
    vulnerabilities.push(vulnerability({
      vulnType: 'TLS_CERT_HOSTNAME_MISMATCH',
      severity: HIGH,
      url: baseUrl,
      evidence: `Certificate CN/SAN '${cn}' does not match host '${host}'.`,
      recommendation: 'Ensure the certificate covers all hostnames the site responds to.',
      category: 'tls',
    }))
  }

  return vulnerabilities
}
