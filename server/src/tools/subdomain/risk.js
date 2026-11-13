export const RISK_KEYWORDS = Object.freeze({
  HIGH: Object.freeze([
    'dev', 'admin', 'vpn', 'jira', 'api', 'v1', 'test',
    'staging', 'internal', 'ssh', 'db', 'database',
    'git', 'backup', 'jenkins', 'grafana', 'prometheus',
    'kibana', 'elastic', 'dashboard', 'console',
    'management', 'login', 'auth', 'sso', 'panel',
    'control', 'direct', 'corp',
  ]),
  MEDIUM: Object.freeze([
    'mail', 'ftp', 'smtp', 'pop', 'imap', 'relay',
    'beta', 'demo', 'stage', 'sandbox', 'qa', 'uat', 'preprod',
    'ws', 'socket', 'websocket', 'webmail', 'email',
    'mysql', 'postgres', 'redis', 'mongo',
    'blog', 'shop', 'portal', 'app', 'support', 'help',
    'docs', 'wiki', 'forum', 'cdn',
    'ns1', 'ns2',
  ]),
})

function keywordLevel(hostname, keywords) {
  const hostnameLower = hostname.toLowerCase()
  for (const level of ['HIGH', 'MEDIUM']) {
    for (const keyword of keywords[level] ?? []) {
      const pattern = new RegExp(`(?:^|[.-])${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[.-]|$)`, 'i')
      if (pattern.test(hostnameLower)) {
        return { level, reason: `Subdomain contains '${keyword}'` }
      }
    }
  }
  return null
}

export function classifySubdomainRisk(hostname, http = null, riskKeywords = RISK_KEYWORDS) {
  const keyword = keywordLevel(hostname, riskKeywords)
  if (keyword) return keyword

  if (http?.alive) {
    const status = Number(http.status ?? 0)
    const title = String(http.title ?? '').toLowerCase()

    if ([401, 403, 407].includes(status)) {
      return { level: 'HIGH', reason: `HTTP ${status} requires authentication` }
    }
    if ([500, 502, 503].includes(status)) {
      return { level: 'HIGH', reason: `HTTP ${status} server error` }
    }
    for (const kw of ['login', 'admin', 'dashboard', 'signin', 'console', 'control panel']) {
      if (title.includes(kw)) return { level: 'HIGH', reason: `Page title contains '${kw}'` }
    }
    if ([301, 302, 307, 308].includes(status)) {
      return { level: 'MEDIUM', reason: `HTTP ${status} redirects elsewhere` }
    }
    if (status === 404) return { level: 'MEDIUM', reason: 'HTTP 404 not found' }
    if (Array.isArray(http.technologies) && http.technologies.length > 0) {
      return { level: 'MEDIUM', reason: `Runs ${http.technologies.slice(0, 2).join(', ')}` }
    }
    if (status >= 200 && status < 300) {
      return { level: 'LOW', reason: 'Standard web service' }
    }
  }

  return { level: 'LOW', reason: 'No web service or standard subdomain' }
}

export function computeConfidence(entry, wildcardIps = []) {
  if (!entry?.resolved) return { verified: false, confidence: 0 }

  let score = 0
  const records = entry.records ?? {}
  const http = entry.http ?? {}

  const aRecords = Array.isArray(records.A) ? records.A : []
  const hasA = aRecords.length > 0
  const hasAaaa = Array.isArray(records.AAAA) && records.AAAA.length > 0
  const hasOther = ['MX', 'TXT', 'NS', 'CNAME'].some(
    (type) => Array.isArray(records[type]) && records[type].length > 0
  )

  if (hasA) {
    score += 0.35
    if (aRecords.length >= 2) score += 0.05
  }
  if (hasAaaa) score += 0.05
  if (hasOther) score += 0.1

  if (http.alive) {
    const status = Number(http.status ?? 0)
    if (status >= 200 && status < 300) score += 0.3
    else if ([301, 302, 307, 308].includes(status)) score += 0.25
    else if ([401, 403, 404].includes(status)) score += 0.2
    else score += 0.1

    if (Number.isFinite(http.response_time_ms) && http.response_time_ms > 50) score += 0.05
    if (http.title) score += 0.05
  }

  if (entry.wildcard) score = Math.min(score, 0.2)
  if (wildcardIps.length > 0 && hasA) {
    const wildcard = new Set(wildcardIps)
    if (aRecords.some((ip) => wildcard.has(ip))) score *= 0.3
  }

  score = Math.max(0, Math.min(1, score))
  return {
    verified: score >= 0.6 && !entry.wildcard,
    confidence: Math.round(score * 100) / 100,
  }
}
