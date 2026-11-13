import net from 'node:net'
import { z } from 'zod'
import { provider as ipwhois } from './providers/ipwhois.js'
import { provider as ipinfo } from './providers/ipinfo.js'
import { provider as ipapi } from './providers/ipapi.js'
import { detectCdn, enrich as defaultEnrich, locationAccuracy } from './enrich.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'
import { createLimits } from '../_shared/limits.js'
import { createBreaker } from '../../net/circuitBreaker.js'
import { resolveTarget } from '../../security/resolve.js'
import { env as defaultEnv } from '../../config/env.js'

export const RESULT_KEYS = [
  'target',
  'ip',
  'addresses',
  'resolved_ips',
  'country',
  'country_code',
  'continent',
  'continent_code',
  'region',
  'city',
  'postal',
  'latitude',
  'longitude',
  'timezone',
  'utc_offset',
  'flag_emoji',
  'calling_code',
  'asn',
  'org',
  'isp',
  'asn_domain',
  'provider',
  'is_cdn',
  'cdn_provider',
  'is_proxy',
  'is_hosting',
  'is_vpn',
  'is_tor',
  'confidence',
  'location_accuracy',
  'map_url',
  'reverse_dns',
  'abuse_contact',
  'fallback_note',
  'scan_duration_seconds',
  'ip_results',
  'cached',
  'error',
]

export const schema = z.object({ target: z.string().trim().min(1).max(260) })

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function emptyIpResult(entry) {
  return {
    ip: entry?.address ?? null,
    family: entry?.family ?? null,
    country: null,
    country_code: null,
    flag_emoji: null,
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    asn: null,
    org: null,
    isp: null,
    cdn_provider: null,
    is_cdn: false,
    reverse_dns: [],
    provider: null,
    error: null,
  }
}

function emptyResult(input) {
  return {
    target: input.target,
    ip: null,
    addresses: [],
    resolved_ips: [],
    country: null,
    country_code: null,
    continent: null,
    continent_code: null,
    region: null,
    city: null,
    postal: null,
    latitude: null,
    longitude: null,
    timezone: null,
    utc_offset: null,
    flag_emoji: null,
    calling_code: null,
    asn: null,
    org: null,
    isp: null,
    asn_domain: null,
    provider: null,
    is_cdn: false,
    cdn_provider: null,
    is_proxy: null,
    is_hosting: null,
    is_vpn: null,
    is_tor: null,
    confidence: null,
    location_accuracy: null,
    map_url: null,
    reverse_dns: [],
    abuse_contact: null,
    fallback_note: null,
    scan_duration_seconds: null,
    ip_results: [],
    cached: false,
    error: null,
  }
}

function elapsedSeconds(startedAt) {
  return Math.round((performance.now() - startedAt) / 10) / 100
}

function sameCountry(a, b) {
  if (!a || !b) return null
  return String(a).trim().toLowerCase() === String(b).trim().toLowerCase()
}

export function createGeoipDefinition({
  providers = [ipinfo, ipwhois],
  resolve = resolveTarget,
  getCached = cacheGet,
  setCached = cacheSet,
  enrich = defaultEnrich,
  limits = null,
  breaker = createBreaker({ name: 'geoip' }),
  env = defaultEnv,
  wait = sleep,
} = {}) {
  const ordered = () => {
    const names = String(env.GEOIP_PROVIDER_ORDER ?? '')
      .split(',')
      .map((name) => name.trim())
      .filter(Boolean)
    const selected = names
      .map((name) => providers.find((provider) => provider.name === name))
      .filter(Boolean)
    return selected.length > 0 ? selected : providers
  }

  function maxIps() {
    const value = Number(env.GEOIP_MAX_IPS ?? 4)
    if (!Number.isFinite(value)) return 4
    return Math.min(Math.max(Math.trunc(value), 1), 10)
  }

  async function queryProvider(provider, ip, { limiter, breaker, env, ctx }) {
    await limiter.acquireGeoipRate()
    let lastError = null
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await limiter.withGeoipSlot(() =>
          breaker.exec(() =>
            provider.lookup(ip, {
              token: env.IPINFO_API_TOKEN,
              signal: ctx?.signal,
            })
          )
        )
      } catch (err) {
        lastError = err
        if (attempt === 0) await wait(300)
      }
    }
    throw lastError ?? Object.assign(new Error('Lookup service unavailable'), { kind: 'upstream' })
  }

  async function lookupAddress(entry, options) {
    const { candidates } = options
    let lastError = null
    for (let index = 0; index < candidates.length; index += 1) {
      const provider = candidates[index]
      try {
        const data = await queryProvider(provider, entry.address, options)
        const enrichment = await enrich(entry.address)
        return {
          entry,
          data,
          enrichment,
          provider,
          fallbackNote:
            index > 0 ? `${candidates[0].name} failed, ${provider.name} answered` : null,
        }
      } catch (err) {
        lastError = err
      }
    }
    return { entry, error: lastError ?? new Error('Lookup service unavailable') }
  }

  function toIpResult(outcome) {
    const base = emptyIpResult(outcome.entry)
    if (outcome.error) {
      return {
        ...base,
        error: outcome.error.message ?? 'Lookup failed',
      }
    }
    const data = outcome.data ?? {}
    const cdn = detectCdn(data.org)
    return {
      ...base,
      country: data.country ?? null,
      country_code: data.country_code ?? null,
      flag_emoji: data.flag_emoji ?? null,
      region: data.region ?? null,
      city: data.city ?? null,
      latitude: data.latitude ?? null,
      longitude: data.longitude ?? null,
      asn: data.asn ?? null,
      org: data.org ?? null,
      isp: data.isp ?? null,
      cdn_provider: cdn.cdn_provider,
      is_cdn: cdn.is_cdn,
      reverse_dns: outcome.enrichment?.reverse_dns ?? [],
      provider: data.provider ?? outcome.provider?.name ?? null,
    }
  }

  return {
    name: 'geoip',
    toolEnum: 'GEOIP',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 3600,
    normalize: (input) => input,
    async execute(input, ctx) {
      const startedAt = performance.now()
      const target = input.target.trim()
      const { addresses } = await resolve(target, {
        kind: net.isIP(target) ? 'ip' : 'hostname',
        timeoutMs: env.DNS_TIMEOUT_MS,
      })
      const orderedAddresses = [...addresses].sort(
        (a, b) => (a.family === 4 ? 0 : 1) - (b.family === 4 ? 0 : 1)
      )
      const resolvedIps = orderedAddresses.map((entry) => entry.address)
      const primary = orderedAddresses[0]

      const cached = await getCached('geoip:v2', primary.address)
      if (cached) {
        return {
          ...emptyResult(input),
          ...cached,
          target: input.target,
          cached: true,
          scan_duration_seconds: elapsedSeconds(startedAt),
        }
      }

      const limiter = limits ?? createLimits({ env })
      const candidates = ordered()
      const selected = orderedAddresses.slice(0, maxIps())
      const options = { limiter, breaker, env, ctx, candidates }
      const outcomes = await Promise.all(selected.map((entry) => lookupAddress(entry, options)))
      const ipResults = outcomes.map((outcome) => toIpResult(outcome))

      const primaryIndex = outcomes.findIndex((outcome) => !outcome.error)
      if (primaryIndex === -1) {
        const failure = outcomes[0]?.error
        throw failure ?? Object.assign(new Error('Lookup service unavailable'), { kind: 'upstream' })
      }
      const outcome = outcomes[primaryIndex]
      const data = outcome.data
      const ip = outcome.entry.address
      const cdn = detectCdn(data.org)

      let confidence = null
      if (env.GEOIP_CONSENSUS === true) {
        const secondary = candidates.find((provider) => provider.name !== outcome.provider.name)
        if (secondary) {
          try {
            const other = await queryProvider(secondary, ip, options)
            confidence = sameCountry(data.country, other.country)
              ? 'high'
              : sameCountry(data.country, other.country) === false
                ? 'low'
                : null
          } catch {
            confidence = null
          }
        }
      }

      const result = {
        ...emptyResult(input),
        ...data,
        ip,
        addresses: resolvedIps,
        resolved_ips: resolvedIps,
        continent: data.continent ?? null,
        continent_code: data.continent_code ?? null,
        postal: data.postal ?? null,
        timezone: data.timezone ?? null,
        utc_offset: data.utc_offset ?? null,
        flag_emoji: data.flag_emoji ?? null,
        calling_code: data.calling_code ?? null,
        isp: data.isp ?? null,
        asn_domain: data.asn_domain ?? null,
        is_proxy: data.is_proxy ?? null,
        is_hosting: data.is_hosting ?? null,
        is_vpn: data.is_vpn ?? null,
        is_tor: data.is_tor ?? null,
        confidence,
        location_accuracy: locationAccuracy(data),
        is_cdn: cdn.is_cdn,
        cdn_provider: cdn.cdn_provider,
        map_url:
          data.latitude != null && data.longitude != null
            ? `https://maps.google.com/?q=${data.latitude},${data.longitude}`
            : null,
        reverse_dns: outcome.enrichment?.reverse_dns ?? [],
        abuse_contact: outcome.enrichment?.abuse_contact ?? null,
        fallback_note: outcome.fallbackNote,
        scan_duration_seconds: elapsedSeconds(startedAt),
        ip_results: ipResults,
      }
      await setCached('geoip:v2', ip, result, env.GEOIP_CACHE_TTL_SEC)
      return result
    },
    emptyResult,
    summarize: (data) => ({
      country: data.country,
      city: data.city,
      asn: data.asn,
      provider: data.provider,
      isCdn: data.is_cdn,
    }),
  }
}

export const definition = createGeoipDefinition()
