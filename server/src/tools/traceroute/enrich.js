import dns from 'node:dns'
import { classifyIp } from '../../security/ipPolicy.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'
import { definition as geoipDefinition } from '../geoip/index.js'

const NON_PUBLIC_REASONS = new Set([
  'private', 'loopback', 'link_local', 'cgnat', 'metadata', 'reserved',
  'documentation', 'multicast', 'unspecified', 'translation', 'malformed',
])

export const CDN_PATTERNS = Object.freeze({
  Cloudflare: ['cloudflare', 'as13335'],
  Akamai: ['akamai', 'as20940', 'as16625'],
  Fastly: ['fastly', 'as54113'],
  'Amazon CloudFront': ['cloudfront', 'amazon', 'aws', 'as16509'],
  Google: ['google', 'as15169'],
  'Microsoft Azure': ['azure', 'microsoft', 'as8075'],
})

export const HIDDEN_REASON =
  'No ICMP response. This hop is likely filtered by a firewall or configured to suppress traceroute probes.'

export function isPrivateIp(ip) {
  if (!ip) return false
  const result = classifyIp(ip)
  return !result.allowed && NON_PUBLIC_REASONS.has(result.reason)
}

export function qualityForLatency(rttMs) {
  if (rttMs == null) return { quality: 'Filtered', color: 'gray' }
  if (rttMs <= 10) return { quality: 'Excellent', color: 'green' }
  if (rttMs <= 40) return { quality: 'Good', color: 'cyan' }
  if (rttMs <= 100) return { quality: 'Moderate', color: 'yellow' }
  return { quality: 'Poor', color: 'red' }
}

export function detectProvider(ip, hostname) {
  const haystack = `${ip ?? ''} ${hostname ?? ''}`.toLowerCase()

  for (const [provider, needles] of Object.entries(CDN_PATTERNS)) {
    if (needles.some((needle) => haystack.includes(needle))) {
      return { provider, asn: null, cdnProvider: provider, isCdn: true, hopType: 'CDN Edge' }
    }
  }
  if (['google', '1e100', 'googleusercontent'].some((token) => haystack.includes(token))) {
    return { provider: 'Google', asn: 'AS15169', cdnProvider: 'Google', isCdn: true, hopType: 'Cloud Network' }
  }
  if (['amazon', 'aws', 'compute'].some((token) => haystack.includes(token))) {
    return {
      provider: 'Amazon Web Services',
      asn: 'AS16509',
      cdnProvider: 'Amazon CloudFront',
      isCdn: true,
      hopType: 'Cloud Network',
    }
  }
  if (['cloudflare', 'cf'].some((token) => haystack.includes(token))) {
    return { provider: 'Cloudflare', asn: 'AS13335', cdnProvider: 'Cloudflare', isCdn: true, hopType: 'CDN Edge' }
  }
  if (isPrivateIp(ip)) {
    return {
      provider: 'Private network',
      asn: null,
      cdnProvider: null,
      isCdn: false,
      hopType: ip?.startsWith('192.168.') || ip?.startsWith('10.') ? 'Residential Router' : 'Private Transit',
    }
  }
  if (hostname) {
    const labels = hostname.split('.')
    return {
      provider: (labels.length >= 2 ? labels[labels.length - 2] : hostname).replace(/^\w/, (c) => c.toUpperCase()),
      asn: null,
      cdnProvider: null,
      isCdn: false,
      hopType: 'ISP Backbone',
    }
  }
  return {
    provider: null,
    asn: null,
    cdnProvider: null,
    isCdn: false,
    hopType: ip ? 'Public Router' : 'Filtered Hop',
  }
}

export function emptyHop(hopNumber) {
  const { quality, color } = qualityForLatency(null)
  return {
    hop: hopNumber,
    ip: null,
    hostname: null,
    rtt_ms: null,
    rtt_samples_ms: [],
    packet_loss_pct: 100,
    quality,
    quality_color: color,
    latency_added_ms: null,
    is_hidden: true,
    hidden_reason: HIDDEN_REASON,
    is_private: false,
    provider: null,
    asn: null,
    hop_type: 'Filtered Hop',
    city: null,
    region: null,
    country: null,
    country_code: null,
    lat: null,
    lon: null,
    cdn_provider: null,
    is_cdn: false,
    insight: 'No response from this router; later hops may still be reachable.',
  }
}

async function reverseDns(ip) {
  const cached = await cacheGet('traceroute-ptr', ip)
  if (typeof cached === 'string') return cached || null

  let hostname = null
  try {
    const names = await Promise.race([
      dns.promises.reverse(ip),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000)),
    ])
    hostname = Array.isArray(names) && names.length > 0 ? String(names[0]).replace(/\.$/, '') : null
  } catch {
    hostname = null
  }
  await cacheSet('traceroute-ptr', ip, hostname ?? '', 3600)
  return hostname
}

async function geoipLookup(ip, { env, signal } = {}) {
  const result = await geoipDefinition.execute(
    geoipDefinition.normalize({ target: ip }),
    { env, signal }
  )
  if (!result || result.error) return {}
  return {
    city: result.city ?? null,
    region: result.region ?? null,
    country: result.country ?? null,
    country_code: result.country_code ?? null,
    lat: result.latitude ?? null,
    lon: result.longitude ?? null,
    provider: result.org || result.provider || null,
    asn: result.asn ?? null,
    cdn_provider: result.cdn_provider ?? (result.is_cdn ? result.provider : null),
    is_cdn: Boolean(result.is_cdn),
  }
}

export function createEnricher({
  reverse = reverseDns,
  geoip = geoipLookup,
  env,
  signal,
} = {}) {
  async function enrichHop(hopNumber, ip, samples, previousRtt) {
    const hostname = await reverse(ip)
    const rttMs = samples.length > 0
      ? Math.round((samples.reduce((sum, value) => sum + value, 0) / samples.length) * 1000) / 1000
      : null
    const packetLossPct = Math.round(((3 - Math.min(samples.length, 3)) / 3) * 1000) / 10
    const { quality, color } = qualityForLatency(rttMs)
    const latencyAdded = rttMs != null && previousRtt != null
      ? Math.round((rttMs - previousRtt) * 1000) / 1000
      : null
    const provider = detectProvider(ip, hostname)

    let insight = null
    if (latencyAdded != null && latencyAdded >= 40) {
      insight = `Hop ${hopNumber} added ${latencyAdded.toFixed(1)}ms, which looks like a routing or congestion spike.`
    } else if (packetLossPct) {
      insight = `Hop ${hopNumber} dropped ${packetLossPct.toFixed(0)}% of traceroute probes.`
    } else if (provider.isCdn) {
      insight = `Traffic appears to enter ${provider.cdnProvider} edge infrastructure here.`
    }

    return {
      hop: hopNumber,
      ip,
      hostname,
      rtt_ms: rttMs,
      rtt_samples_ms: samples.map((sample) => Math.round(sample * 1000) / 1000),
      packet_loss_pct: packetLossPct,
      quality,
      quality_color: color,
      latency_added_ms: latencyAdded,
      is_hidden: false,
      hidden_reason: null,
      is_private: isPrivateIp(ip),
      provider: provider.provider,
      asn: provider.asn,
      hop_type: provider.hopType,
      city: null,
      region: null,
      country: null,
      country_code: null,
      lat: null,
      lon: null,
      cdn_provider: provider.cdnProvider,
      is_cdn: provider.isCdn,
      insight,
    }
  }

  async function applyGeoip(hops) {
    const publicHops = hops
      .filter((hop) => hop.ip && !hop.is_private && !hop.is_hidden)
      .slice(0, 16)
    if (publicHops.length === 0) return hops

    const results = await Promise.allSettled(
      publicHops.map(async (hop) => ({ hop, geo: await geoip(hop.ip, { env, signal }) }))
    )
    for (const item of results) {
      if (item.status !== 'fulfilled') continue
      const { hop, geo } = item.value
      if (!geo || Object.keys(geo).length === 0) continue
      hop.city = geo.city ?? hop.city
      hop.region = geo.region ?? hop.region
      hop.country = geo.country ?? hop.country
      hop.country_code = geo.country_code ?? hop.country_code
      hop.lat = geo.lat ?? hop.lat
      hop.lon = geo.lon ?? hop.lon
      hop.provider = geo.provider || hop.provider
      hop.asn = geo.asn || hop.asn
      hop.cdn_provider = geo.cdn_provider || hop.cdn_provider
      hop.is_cdn = Boolean(geo.is_cdn || hop.is_cdn)
      if (hop.is_cdn) hop.hop_type = 'CDN Edge'
      else if (geo.provider && hop.hop_type === 'Public Router') hop.hop_type = 'ISP Backbone'
      if (hop.is_cdn && !hop.insight) {
        hop.insight = `Traffic appears to enter ${hop.cdn_provider} edge infrastructure here.`
      }
    }
    return hops
  }

  return { enrichHop, applyGeoip }
}
