import net from 'node:net'
import { z } from 'zod'
import { provider as ipwhois } from './providers/ipwhois.js'
import { provider as ipinfo } from './providers/ipinfo.js'
import { provider as ipapi } from './providers/ipapi.js'
import { detectCdn, enrich as defaultEnrich, locationAccuracy } from './enrich.js'
import { cymruAsn } from './sources/cymru.js'
import { torExitStatus } from './sources/tor.js'
import { hostingStatus } from './sources/hosting.js'
import { reputationCheck } from './sources/reputation.js'
import { buildPrivacy } from './sources/privacy.js'
import { detectAnycast } from './sources/anycast.js'
import { getRedisClient } from '../../redis/client.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'
import { createLimits } from '../_shared/limits.js'
import { createBreaker } from '../../net/circuitBreaker.js'
import { resolveTarget } from '../../security/resolve.js'
import { env as defaultEnv } from '../../config/env.js'
import { buildPlan } from './plan.js'
import { runBatch } from './batch.js'
import { lookupAsn } from '../asn/index.js'

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
  'ip_type',
  'ip_type_basis',
  'privacy',
  'privacy_sources',
  'asn_detail',
  'network',
  'reputation',
  'consensus',
  'accuracy_radius_km',
  'accuracy_basis',
  'freshness',
  'warnings',
  'anycast',
  'reverse_ip',
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
    ip_type: null,
    ip_type_basis: null,
    privacy: { vpn: null, proxy: null, tor: null, relay: null, hosting: null },
    privacy_sources: [],
    asn_detail: null,
    network: null,
    reputation: null,
    consensus: { providers: [], agreement: null, max_distance_km: null },
    accuracy_radius_km: null,
    accuracy_basis: null,
    freshness: { fetched_at: null, db_date: null },
    warnings: [],
    anycast: { likely: null, basis: null },
    reverse_ip: null,
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
  redis = null,
  sources = {},
  asnLookup = lookupAsn,
} = {}) {
  const sourceCymru = sources.cymru ?? cymruAsn
  const sourceTor = sources.tor ?? torExitStatus
  const sourceHosting = sources.hosting ?? hostingStatus
  const sourceReputation = sources.reputation ?? reputationCheck
  const sourceAnycast = sources.anycast ?? detectAnycast
  const redisClient = () => redis ?? getRedisClient()
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

  async function automaticNetworkEnrichment(result, plan) {
    if (plan?.items?.[0]?.kind !== 'host' || !result.asn) return result
    try {
      const asnResult = await asnLookup(result.asn)
      return {
        ...result,
        asn_lookup: asnResult,
        cidr_prefixes: asnResult.prefixes ?? [],
        warnings: [...(result.warnings ?? []), ...(asnResult.warnings ?? [])],
      }
    } catch {
      return {
        ...result,
        asn_lookup: null,
        cidr_prefixes: [],
        warnings: [...(result.warnings ?? []), { source: 'asn-prefixes', message: 'ASN prefix lookup unavailable' }],
      }
    }
  }

  function maxIps() {
    const value = Number(env.GEOIP_MAX_IPS ?? 4)
    if (!Number.isFinite(value)) return 4
    return Math.min(Math.max(Math.trunc(value), 1), 10)
  }

  function distanceKm(a, b) {
    if (a.latitude == null || a.longitude == null || b.latitude == null || b.longitude == null) return null
    const toRad = (value) => (value * Math.PI) / 180
    const dLat = toRad(b.latitude - a.latitude)
    const dLon = toRad(b.longitude - a.longitude)
    const lat1 = toRad(a.latitude)
    const lat2 = toRad(b.latitude)
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2
    return Math.round(2 * 6371 * Math.asin(Math.sqrt(h)))
  }

  function buildConsensus(providers) {
    const withLocation = providers.filter((provider) => provider.latitude != null && provider.longitude != null)
    let maxDistance = null
    for (let i = 0; i < withLocation.length; i += 1) {
      for (let j = i + 1; j < withLocation.length; j += 1) {
        const distance = distanceKm(withLocation[i], withLocation[j])
        if (distance != null && (maxDistance == null || distance > maxDistance)) maxDistance = distance
      }
    }
    const countries = providers.map((provider) => provider.country).filter(Boolean)
    let agreement = null
    if (providers.length >= 2 && countries.length >= 2) {
      const same = countries.every((country) => sameCountry(country, countries[0]) === true)
      if (!same) agreement = 'low'
      else if (maxDistance != null && maxDistance < 50) agreement = 'high'
      else agreement = 'medium'
    }
    return { providers, agreement, max_distance_km: maxDistance }
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

  async function timedQuery(provider, ip, options) {
    const startedAt = performance.now()
    const data = await queryProvider(provider, ip, options)
    return { data, latency_ms: Math.round(performance.now() - startedAt) }
  }

  async function lookupAddress(entry, options) {
    const { candidates } = options
    let lastError = null
    for (let index = 0; index < candidates.length; index += 1) {
      const provider = candidates[index]
      try {
        const answer = await timedQuery(provider, entry.address, options)
        const enrichment = await enrich(entry.address)
        return {
          entry,
          data: answer.data,
          latency_ms: answer.latency_ms,
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

  const singleDefinition = {
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

      const warnings = []
      const consensusProviders = [{
        provider: outcome.provider.name,
        country: data.country ?? null,
        city: data.city ?? null,
        latitude: data.latitude ?? null,
        longitude: data.longitude ?? null,
        latency_ms: outcome.latency_ms ?? null,
      }]

      if (env.GEOIP_CONSENSUS === true) {
        const secondary = candidates.find((provider) => provider.name !== outcome.provider.name)
        if (secondary) {
          try {
            const answer = await timedQuery(secondary, ip, options)
            consensusProviders.push({
              provider: secondary.name,
              country: answer.data.country ?? null,
              city: answer.data.city ?? null,
              latitude: answer.data.latitude ?? null,
              longitude: answer.data.longitude ?? null,
              latency_ms: answer.latency_ms ?? null,
            })
          } catch {
            warnings.push({ source: secondary.name, message: 'Consensus provider unavailable' })
          }
        }
      }

      const consensus = buildConsensus(consensusProviders)
      const confidence = consensus.agreement

      let asnDetail = null
      try {
        asnDetail = await sourceCymru(ip)
      } catch {
        warnings.push({ source: 'team-cymru', message: 'ASN lookup unavailable' })
      }

      let torStatus = null
      try {
        torStatus = await sourceTor(ip, { redis: redisClient() })
      } catch {
        torStatus = null
      }
      if (torStatus === null) {
        warnings.push({ source: 'tor-exit-list', message: 'Tor exit list unavailable' })
      }

      const asnForSources = asnDetail?.asn ?? data.asn ?? null
      const hosting = sourceHosting(asnForSources)

      let reputation = null
      try {
        reputation = await sourceReputation(ip, {
          env,
          limiter,
          redis: redisClient(),
        })
      } catch {
        warnings.push({ source: 'reputation', message: 'Reputation lookup unavailable' })
      }
      if (outcome.enrichment?.rdap_error) {
        warnings.push({ source: 'rdap', message: 'RDAP lookup unavailable' })
      }
      if (reputation) {
        if (!reputation.abuseipdb && !reputation.dnsbl?.checked) {
          warnings.push({ source: 'reputation', message: 'Reputation sources not configured or unavailable' })
        }
        reputation = { ...reputation, tor_exit: torStatus }
      } else if (torStatus !== null) {
        reputation = { abuseipdb: null, dnsbl: null, tor_exit: torStatus, checked_at: null }
      }

      const privacy = buildPrivacy({
        providerPrivacy: data.privacy ?? null,
        torStatus,
        hosting,
        usageType: reputation?.abuseipdb?.usage_type ?? null,
      })
      const providerAccuracy = data.accuracy_radius_km ?? data.accuracy_radius ?? null
      const accuracyRadius = providerAccuracy != null
        ? Number(providerAccuracy)
        : consensus.max_distance_km != null && consensusProviders.length > 1
          ? Math.round(consensus.max_distance_km)
          : null
      const accuracyBasis = providerAccuracy != null
        ? 'provider'
        : accuracyRadius != null
          ? 'provider-disagreement'
          : null

      if (env.GEOIP_REVERSE_IP) {
        warnings.push({ source: 'reverse-ip', message: 'Reverse IP provider not configured' })
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
        is_proxy: privacy.privacy.proxy ?? data.is_proxy ?? null,
        is_hosting: privacy.privacy.hosting ?? data.is_hosting ?? null,
        is_vpn: privacy.privacy.vpn ?? data.is_vpn ?? null,
        is_tor: privacy.privacy.tor ?? data.is_tor ?? null,
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
        network: outcome.enrichment?.network ?? null,
        asn_detail: asnDetail,
        privacy: privacy.privacy,
        privacy_sources: privacy.privacy_sources,
        ip_type: privacy.ip_type,
        ip_type_basis: privacy.ip_type_basis,
        reputation,
        consensus,
        accuracy_radius_km: accuracyRadius,
        accuracy_basis: accuracyBasis,
        freshness: {
          fetched_at: new Date().toISOString(),
          db_date: data.db_date ?? null,
        },
        warnings,
        anycast: sourceAnycast({ ip, asn: asnForSources }),
        reverse_ip: null,
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
  return {
    ...singleDefinition,
    schema: z.object({ target: z.string().trim().min(1).max(20000) }),
    dedupeTtlSec: 0,
    dedupeTtlFor: (input) => input.plan?.mode === 'single' ? 3600 : input.plan?.mode === 'asn' ? 86400 : 0,
    mode: 'auto',
    async validateInput(input, { req } = {}) {
      const tier = req?.user?.role === 'ADMIN' ? 'ADMIN' : req?.user?.tier === 'PAID' ? 'PAID' : 'FREE'
      input.plan = buildPlan(input.target, { tier, env })
      return { targetKey: input.plan.targetKey, addresses: [], display: input.plan.display }
    },
    quotaUnits: (input) => input.plan?.units ?? 1,
    asyncWhen: (input) => (input.plan?.units ?? 1) > 1,
    async execute(input, ctx) {
      // Preserve the executor contract used by internal callers (traceroute and
      // the legacy unit tests); HTTP submissions always arrive with a plan.
      if (!input.plan && [4, 6].includes(net.isIP(input.target?.trim?.()))) {
        return singleDefinition.execute(input, ctx)
      }
      const plan = input.plan ?? buildPlan(input.target, { tier: 'PAID', env })
      if (plan.mode === 'single') {
        const single = await singleDefinition.execute({ target: plan.items[0].canonical }, ctx)
        const enriched = await automaticNetworkEnrichment(single, plan)
        return { ...enriched, mode: 'single', target: input.target }
      }
      if (plan.mode === 'asn') return { ...(await lookupAsn(plan.items[0].canonical)), mode: 'asn', target: plan.items[0].canonical }
      const data = await runBatch(plan.items, {
        signal: ctx?.signal,
        reportProgress: ctx?.reportProgress,
        lookup: (target, options) => singleDefinition.execute({ target }, { ...ctx, ...options }),
        lookupAsn: (asn) => lookupAsn(asn),
      })
      return { mode: 'batch', target: input.target, ...data, rejected: plan.rejected, skipped: plan.skipped, expanded_from: plan.expanded_from }
    },
    summarize: (data) => ({ mode: data.mode, country: data.country, city: data.city, asn: data.asn, provider: data.provider, isCdn: data.is_cdn, total: data.total, completed: data.completed, failed: data.failed }),
  }
}

export const definition = createGeoipDefinition()
