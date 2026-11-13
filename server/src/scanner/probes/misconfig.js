export function misconfiguration(category, title, severity, evidence, recommendation) {
  return { category, title, severity, evidence, recommendation }
}

export function httpResponseText(port) {
  return [port.server_response, port.raw_banner, port.welcome_message].filter(Boolean).join('\n')
}

export function parseHttpHeaders(response) {
  if (!response) return {}
  const headers = {}
  const lines = String(response).replace(/\r\n/g, '\n').split('\n').slice(1)
  for (const line of lines) {
    if (!line.trim()) break
    if (!line.includes(':')) continue
    const index = line.indexOf(':')
    headers[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim()
  }
  return headers
}

export function detectHttpMisconfigurations(port) {
  const response = httpResponseText(port)
  if (!response) return []

  const findings = []
  const bodyHint = response.toLowerCase()
  if (
    /<title>\s*index of\s*\/?/i.test(bodyHint) ||
    /<h1>\s*index of\s*\/?/i.test(bodyHint) ||
    bodyHint.includes('directory listing for /') ||
    (bodyHint.includes('parent directory') && bodyHint.includes('last modified'))
  ) {
    findings.push(
      misconfiguration(
        'directory_listing',
        'Directory listing enabled',
        'high',
        'The HTTP response appears to expose an auto-generated directory index.',
        'Disable directory indexes and require authentication for file browsing paths.'
      )
    )
  }

  const headers = parseHttpHeaders(response)
  const required = port.port_number === 443 || port.port_number === 8443
    ? {
        'content-security-policy': 'Content-Security-Policy',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
        'strict-transport-security': 'Strict-Transport-Security',
      }
    : {
        'content-security-policy': 'Content-Security-Policy',
        'x-frame-options': 'X-Frame-Options',
        'x-content-type-options': 'X-Content-Type-Options',
      }
  const missing = Object.entries(required)
    .filter(([key]) => !(key in headers))
    .map(([, display]) => display)
  if (missing.length) {
    findings.push(
      misconfiguration(
        'missing_security_headers',
        'Missing security headers',
        'medium',
        `Missing: ${missing.slice(0, 4).join(', ')}.`,
        'Add the missing browser security headers at the web server or application gateway.'
      )
    )
  }

  return findings
}

export function misconfigurationSummary(openPorts) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  const categories = new Set()
  let total = 0
  for (const port of openPorts) {
    for (const finding of port.misconfigurations ?? []) {
      total += 1
      const severity = String(finding.severity || 'medium').toLowerCase()
      severityCounts[severity in severityCounts ? severity : 'medium'] += 1
      const category = String(finding.category || '').trim()
      if (category) categories.add(category)
    }
  }
  return {
    total,
    critical: severityCounts.critical,
    high: severityCounts.high,
    medium: severityCounts.medium,
    low: severityCounts.low,
    categories: [...categories].sort(),
  }
}
