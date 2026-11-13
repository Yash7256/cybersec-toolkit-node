import net from 'node:net'
import { z } from 'zod'
import { provider as ipwhois } from './providers/ipwhois.js'
import { provider as ipinfo } from './providers/ipinfo.js'
import { provider as ipapi } from './providers/ipapi.js'
import { detectCdn, enrich as defaultEnrich } from './enrich.js'
import { cacheGet, cacheSet } from '../_shared/cache.js'
import { createLimits } from '../_shared/limits.js'
import { createBreaker } from '../../net/circuitBreaker.js'
import { resolveTarget } from '../../security/resolve.js'
import { env as defaultEnv } from '../../config/env.js'

export const RESULT_KEYS = [
  'target',
  'ip',
  'addresses',
  'country',
  'region',
  'city',
  'latitude',
  'longitude',
  'asn',
  'org',
  'provider',
  'is_cdn',
  'map_url',
  'reverse_dns',
  'abuse_contact',
  'fallback_note',
  'cached',
  'error',
]

export const schema = z.object({ target: z.string().trim().min(1).max(260) })

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function emptyResult(input) {
  return {
    target: input.target,
    ip: null,
    addresses: [],
    country: null,
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    asn: null,
    org: null,
    provider: null,
    is_cdn: false,
    map_url: null,
    reverse_dns: [],
    abuse_contact: null,
    fallback_note: null,
    cached: false,
    error: null,
  }
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

  return {
    name: 'geoip',
    toolEnum: 'GEOIP',
    schema,
    touchesTarget: false,
    dedupeTtlSec: 3600,
    normalize: (input) => input,
    async execute(input, ctx) {
      const target = input.target.trim()
      const { addresses } = await resolve(target, {
        kind: net.isIP(target) ? 'ip' : 'hostname',
        timeoutMs: env.DNS_TIMEOUT_MS,
      })
      const primary = addresses.find((entry) => entry.family === 4) ?? addresses[0]
      const ip = primary.address

      const cached = await getCached('geoip', ip)
      if (cached) return { ...cached, cached: true }

      const limiter = limits ?? createLimits({ env })
      const candidates = ordered()
      let lastError = null

      for (let index = 0; index < candidates.length; index += 1) {
        const provider = candidates[index]
        await limiter.acquireGeoipRate()
        let data = null
        for (let attempt = 0; attempt < 2 && !data; attempt += 1) {
          try {
            data = await limiter.withGeoipSlot(() =>
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
        if (!data) continue

        const enrichment = await enrich(ip)
        const result = {
          ...emptyResult(input),
          ...data,
          ip,
          addresses: addresses.map((entry) => entry.address),
          is_cdn: detectCdn(data.org),
          map_url:
            data.latitude != null && data.longitude != null
              ? `https://maps.google.com/?q=${data.latitude},${data.longitude}`
              : null,
          reverse_dns: enrichment.reverse_dns ?? [],
          abuse_contact: enrichment.abuse_contact ?? null,
          fallback_note: index > 0 ? `${candidates[0].name} failed, ${provider.name} answered` : null,
        }
        await setCached('geoip', ip, result, env.GEOIP_CACHE_TTL_SEC)
        return result
      }

      throw lastError ?? Object.assign(new Error('Lookup service unavailable'), { kind: 'upstream' })
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
