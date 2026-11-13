import { CRITICAL, HIGH, MEDIUM, LOW, INFO, SEVERITY_RANK } from './constants.js'

export function vulnerability({
  vulnType,
  severity,
  url,
  parameter = null,
  evidence = null,
  recommendation,
  category = '',
}) {
  return {
    vuln_type: vulnType,
    severity,
    url,
    parameter,
    evidence,
    recommendation,
    category,
  }
}

export function baseDomain(url) {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

export function absoluteUrl(base, href) {
  try {
    return new URL(href, base).toString()
  } catch {
    return null
  }
}

export function sameSite(baseUrl, candidate) {
  const baseHost = baseDomain(baseUrl)
  let host
  try {
    host = new URL(candidate).hostname
  } catch {
    return false
  }
  return host === baseHost || host.endsWith(`.${baseHost}`)
}

export function buildResult({
  target,
  baseUrl,
  pages = [],
  vulnerabilities = [],
  scanDuration = 0,
  fingerprint = null,
  screenshot = null,
  aiSummary = null,
  error = null,
}) {
  const counts = { [CRITICAL]: 0, [HIGH]: 0, [MEDIUM]: 0, [LOW]: 0, [INFO]: 0 }
  for (const item of vulnerabilities) {
    const key = String(item.severity ?? '').toLowerCase()
    counts[key] = (counts[key] ?? 0) + 1
  }
  return {
    target,
    base_url: baseUrl,
    pages_crawled: pages.length,
    vulnerabilities,
    total_vulns: vulnerabilities.length,
    critical_count: counts[CRITICAL],
    high_count: counts[HIGH],
    medium_count: counts[MEDIUM],
    low_count: counts[LOW],
    info_count: counts[INFO],
    scan_duration: Math.round(scanDuration * 1000) / 1000,
    fingerprint,
    screenshot,
    ai_summary: aiSummary,
    error,
  }
}

export function dedupeAndSort(vulnerabilities) {
  const seen = new Set()
  const unique = []
  for (const item of vulnerabilities) {
    const key = `${item.vuln_type}|${item.url}|${item.parameter ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    unique.push(item)
  }
  unique.sort((left, right) => (
    (SEVERITY_RANK[String(left.severity).toLowerCase()] ?? 5)
    - (SEVERITY_RANK[String(right.severity).toLowerCase()] ?? 5)
  ))
  return unique
}

export function timeoutError(seconds) {
  return `Scan exceeded the maximum allowed duration and was stopped early; results may be incomplete.`
}
