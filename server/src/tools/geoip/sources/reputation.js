import dns from 'node:dns'
import { abuseIpdbCheck } from '../../../scanner/intel/threatIntel.js'
import { cacheGet, cacheSet } from '../../_shared/cache.js'
import { createBreaker } from '../../../net/circuitBreaker.js'

const CACHE_NAME = 'geoip:reputation'
const CACHE_TTL_SEC = 6 * 60 * 60
const SPAMHAUS_REFUSAL = /^127\.255\.255\.\d+$/
const MAX_ZONES = 8

const abuseBreaker = createBreaker({ name: 'geoip-abuseipdb' })

function resolverFor(timeoutMs) {
  const resolver = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 })
  resolver.setServers(['1.1.1.1', '8.8.8.8'])
  return resolver
}

function isIpv4(ip) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)
}

export async function dnsblCheck(ip, {
  zones = [],
  timeoutMs = 2000,
  resolver = resolverFor(timeoutMs),
} = {}) {
  if (!isIpv4(ip) || zones.length === 0) {
    return { checked: false, listed: [], clean: [], unknown: [], error: null }
  }
  const reversed = ip.split('.').reverse().join('.')
  const selected = zones.slice(0, MAX_ZONES)
  const outcomes = await Promise.all(selected.map(async (zone) => {
    try {
      const addresses = await resolver.resolve4(`${reversed}.${zone}`)
      if ((addresses ?? []).some((address) => SPAMHAUS_REFUSAL.test(address))) {
        return { zone, state: 'unknown' }
      }
      return { zone, state: (addresses ?? []).length > 0 ? 'listed' : 'clean' }
    } catch (err) {
      if (err?.code === 'ENOTFOUND' || err?.code === 'ENODATA') return { zone, state: 'clean' }
      return { zone, state: 'unknown' }
    }
  }))
  return {
    checked: true,
    listed: outcomes.filter((entry) => entry.state === 'listed').map((entry) => entry.zone),
    clean: outcomes.filter((entry) => entry.state === 'clean').map((entry) => entry.zone),
    unknown: outcomes.filter((entry) => entry.state === 'unknown').map((entry) => entry.zone),
    error: null,
  }
}

function mapAbuse(result) {
  if (!result) return null
  if (!result.checked) return null
  return {
    checked: true,
    available: Boolean(result.available),
    score: result.abuse_confidence_score ?? null,
    total_reports: result.reported_times ?? null,
    last_reported_at: result.last_reported_at ?? null,
    usage_type: result.usage_type ?? null,
    error: result.error ?? null,
  }
}

export async function reputationCheck(ip, {
  env,
  http,
  limiter = null,
  redis = null,
  zones = env?.GEOIP_DNSBL_ZONES ?? [],
  resolver = resolverFor(2000),
  getCached = cacheGet,
  setCached = cacheSet,
  now = Date.now(),
} = {}) {
  if (env && env.GEOIP_REPUTATION_ENABLED === false) return null

  const cached = await getCached(CACHE_NAME, ip)
  if (cached) return cached

  const [abuse, dnsbl] = await Promise.all([
    (async () => {
      if (!env?.ABUSEIPDB_API_KEY) return null
      try {
        if (limiter) await limiter.acquireGeoipRate()
        return mapAbuse(await abuseIpdbCheck({ ip, env, http, breaker: abuseBreaker }))
      } catch {
        return { checked: true, available: false, score: null, total_reports: null, last_reported_at: null, usage_type: null, error: 'Lookup service unavailable' }
      }
    })(),
    dnsblCheck(ip, { zones, resolver }).catch(() => ({
      checked: false, listed: [], clean: [], unknown: [], error: 'Lookup service unavailable',
    })),
  ])

  const result = {
    abuseipdb: abuse,
    dnsbl,
    checked_at: new Date(now).toISOString(),
  }
  if (abuse || dnsbl.checked) await setCached(CACHE_NAME, ip, result, CACHE_TTL_SEC)
  return result
}
