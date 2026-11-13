import dns from 'node:dns/promises'
import { env as defaultEnv } from '../../config/env.js'
import { safeHttp as defaultSafeHttp } from '../../net/safeHttp.js'
import { createBreaker } from '../../net/circuitBreaker.js'
import { isPublicIp, parseIp } from '../ip.js'
import { createOutboundLimiter } from '../../security/outboundLimiter.js'

const ABUSE_HOST = 'api.abuseipdb.com'
const SPAMHAUS_REFUSAL_CODES = new Set(['127.255.255.252', '127.255.255.254', '127.255.255.255'])

export function emptyThreatIntel(ip, reputation, summary, error = null) {
  return {
    ip,
    reputation,
    summary,
    reported_times: 0,
    abuse_confidence_score: null,
    abuseipdb: {
      checked: false,
      available: false,
      reported_times: null,
      abuse_confidence_score: null,
    },
    spamhaus: { checked: false, listed: false, zones: [] },
    known_botnet: false,
    sources: [],
    error,
  }
}

export async function abuseIpdbCheck({ ip, env = defaultEnv, http = defaultSafeHttp, breaker }) {
  if (!env.ABUSEIPDB_API_KEY) {
    return {
      checked: false,
      available: false,
      reported_times: null,
      abuse_confidence_score: null,
      error: 'ABUSEIPDB_API_KEY is not configured',
    }
  }

  const url = `https://${ABUSE_HOST}/api/v2/check?${new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: '90',
  }).toString()}`

  try {
    const run = () =>
      http.request(url, {
        mode: 'trusted',
        allowHosts: [ABUSE_HOST],
        headers: { key: env.ABUSEIPDB_API_KEY, accept: 'application/json' },
        deadlineMs: 8000,
        maxBytes: 128 * 1024,
      })
    const response = breaker ? await breaker.exec(run) : await run()
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`upstream status ${response.status}`)
    }
    const data = JSON.parse(response.body.toString('utf8'))?.data ?? {}
    return {
      checked: true,
      available: true,
      reported_times: data.totalReports ?? 0,
      abuse_confidence_score: data.abuseConfidenceScore ?? null,
      country_code: data.countryCode ?? null,
      usage_type: data.usageType ?? null,
      isp: data.isp ?? null,
      domain: data.domain ?? null,
      last_reported_at: data.lastReportedAt ?? null,
      error: null,
    }
  } catch (err) {
    const message =
      err?.message === 'Lookup service unavailable' || /upstream status/.test(err?.message ?? '')
        ? 'Lookup service unavailable'
        : err?.message ?? 'Request failed'
    return {
      checked: true,
      available: false,
      reported_times: null,
      abuse_confidence_score: null,
      error: message,
    }
  }
}

export async function spamhausCheck({ ip, env = defaultEnv, resolve4 = dns.resolve4 } = {}) {
  if (!env.THREAT_INTEL_SPAMHAUS) {
    return { checked: false, listed: false, zones: [], error: null }
  }

  const parsed = parseIp(ip)
  if (!parsed || parsed.kind() !== 'ipv4' || !isPublicIp(ip)) {
    return { checked: false, listed: false, zones: [], error: null }
  }

  const reversed = ip.split('.').reverse().join('.')
  const query = `${reversed}.zen.spamhaus.org`

  try {
    const addresses = await resolve4(query)
    if ((addresses ?? []).some((address) => SPAMHAUS_REFUSAL_CODES.has(address))) {
      return {
        checked: false,
        listed: false,
        zones: [],
        unavailable: true,
        error: 'Spamhaus refused the query',
      }
    }
    return {
      checked: true,
      listed: true,
      zones: [{ zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN' }],
      error: null,
    }
  } catch (err) {
    if (err?.code === 'ENOTFOUND' || err?.code === 'ENODATA') {
      return { checked: true, listed: false, zones: [], error: null }
    }
    return {
      checked: false,
      listed: false,
      zones: [],
      unavailable: true,
      error: 'Lookup service unavailable',
    }
  }
}

export async function checkThreatIntelligence({
  ip,
  env = defaultEnv,
  http = defaultSafeHttp,
  redis = null,
  resolver = dns.resolve4,
  breaker = createBreaker({ name: 'intel' }),
  limiter = null,
} = {}) {
  if (!ip) {
    return emptyThreatIntel(null, 'Unknown', 'No resolved IP was available for reputation checks.')
  }

  if (!parseIp(ip)) {
    return emptyThreatIntel(ip, 'Unknown', 'Resolved address was not a valid IP.', 'Invalid IP address')
  }

  if (!isPublicIp(ip)) {
    return emptyThreatIntel(
      ip,
      'Private/Local',
      'Private, loopback, or reserved IPs are not checked against public abuse databases.'
    )
  }

  if (!env.ABUSEIPDB_API_KEY && !env.THREAT_INTEL_SPAMHAUS) {
    return emptyThreatIntel(
      ip,
      'Not checked',
      'Threat intelligence is not checked because no AbuseIPDB key is configured and Spamhaus is disabled.',
      'ABUSEIPDB_API_KEY is not configured'
    )
  }

  let client = redis
  if (!client) {
    try {
      const { getRedisClient } = await import('../../redis/client.js')
      client = getRedisClient()
    } catch {
      client = null
    }
  }

  const cacheKey = `cst:intel:${ip}`
  if (client) {
    try {
      const cached = await client.get(cacheKey)
      if (cached != null) return JSON.parse(cached)
    } catch {}
  }

  const rateLimiter =
    limiter ??
    (env.ABUSEIPDB_API_KEY
      ? createOutboundLimiter({ name: 'intel', points: 1, durationSec: 1, maxWaitMs: 8000 })
      : null)

  const [abuseipdb, spamhaus] = await Promise.all([
    (async () => {
      if (rateLimiter) {
        try {
          await rateLimiter.acquire()
        } catch {}
      }
      return abuseIpdbCheck({ ip, env, http, breaker })
    })(),
    spamhausCheck({ ip, env, resolve4: resolver }),
  ])

  const reportedTimes = abuseipdb.reported_times ?? 0
  const abuseScore = abuseipdb.abuse_confidence_score
  const knownBotnet = false

  const sources = []
  if (abuseipdb.checked) sources.push('AbuseIPDB')
  if (spamhaus.checked) sources.push('Spamhaus')
  if (knownBotnet) sources.push('Known botnet list')

  let reputation = 'Clean'
  if (knownBotnet || spamhaus.listed || (abuseScore != null && abuseScore >= 75)) {
    reputation = 'Malicious'
  } else if (reportedTimes > 0 || (abuseScore != null && abuseScore >= 25)) {
    reputation = 'Suspicious'
  } else if (!abuseipdb.available && !spamhaus.checked) {
    reputation = 'Unknown'
  }

  let summary
  if (reputation === 'Malicious') {
    summary = `IP Reputation: Malicious. Reported ${reportedTimes} time(s) for abuse.`
  } else if (reputation === 'Suspicious') {
    summary = `IP Reputation: Suspicious. Reported ${reportedTimes} time(s) for abuse.`
  } else if (reputation === 'Clean') {
    summary = 'IP Reputation: Clean. No abuse reports or blocklist hits were found in checked sources.'
  } else {
    summary = 'IP Reputation: Unknown. No threat intelligence source returned a usable result.'
  }

  const result = {
    ip,
    reputation,
    summary,
    reported_times: reportedTimes,
    abuse_confidence_score: abuseScore,
    abuseipdb,
    spamhaus,
    known_botnet: knownBotnet,
    sources,
    error: abuseipdb.error || spamhaus.error,
  }

  if (client) {
    try {
      await client.setex(cacheKey, env.THREAT_INTEL_CACHE_TTL_SEC, JSON.stringify(result))
    } catch {}
  }
  return result
}

export function emptyThreatIntelForScan(ip, reason) {
  return emptyThreatIntel(ip ?? null, 'Not checked', reason)
}
