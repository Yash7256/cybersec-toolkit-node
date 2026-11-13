import { SECURITY_HEADERS } from '../rules/securityHeaders.js'

export function analyzeSecurityHeaders(headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]))
  return SECURITY_HEADERS.map(([name, severity, description, recommendation]) => ({ name, severity, present: Boolean(lower[name]), description, recommendation }))
}

export function analyzeHsts(value) {
  if (!value) return { present: false, strong: false, maxAge: 0, includeSubDomains: false, preload: false }
  const maxAge = Number(/max-age\s*=\s*(\d+)/i.exec(value)?.[1] ?? 0)
  return { present: true, strong: maxAge >= 31536000, maxAge, includeSubDomains: /includeSubDomains/i.test(value), preload: /preload/i.test(value) }
}

export function analyzeCsp(value) {
  if (!value) return { present: false, weak: true, unsafeInline: false, unsafeEval: false, wildcard: false, frameAncestors: false }
  return { present: true, weak: /unsafe-inline|unsafe-eval|\*/i.test(value), unsafeInline: /unsafe-inline/i.test(value), unsafeEval: /unsafe-eval/i.test(value), wildcard: /(?:^|\s)\*(?:\s|$)/.test(value), frameAncestors: /(?:^|;)\s*frame-ancestors\s/i.test(value) }
}

export function analyzeClickjacking(headers = {}, csp = '') {
  const xfo = String(headers['x-frame-options'] ?? headers['X-Frame-Options'] ?? '').toUpperCase()
  return { protected: xfo === 'DENY' || xfo === 'SAMEORIGIN' || /frame-ancestors\s+(?!\*)/.test(csp), xFrameOptions: xfo || null }
}
